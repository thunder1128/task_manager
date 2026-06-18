#!/usr/bin/env python3
"""タスク管理WEBアプリ バックエンド。

Python標準ライブラリのみで動作する軽量HTTPサーバー。
データは同じディレクトリの tasks.db (SQLite) に永続化する。
追加インストール不要。実行:  python3 server.py

ログイン認証 + プロジェクト単位のアクセス制御つき:
  - ユーザーは管理者が発行する(セルフ登録なし)。
  - 各ユーザーはプロジェクトを作成でき、作成者がオーナーになる。
  - オーナーはプロジェクトにメンバーを追加/削除できる。
  - かんばん列・イテレーション・タスクはプロジェクトに属し、
    そのプロジェクトのメンバーだけが閲覧・編集できる。

API:
  認証
  POST   /api/auth/login            ログイン {username, password}
  POST   /api/auth/logout           ログアウト
  GET    /api/auth/me               現在のユーザー情報(未ログインは401)
  ユーザー管理(管理者のみ)
  GET    /api/users                 ユーザー一覧
  POST   /api/users                 ユーザー作成 {username, password, is_admin?}
  PUT    /api/users/<id>            ユーザー更新 {password?, is_admin?}
  DELETE /api/users/<id>            ユーザー削除
  プロジェクト
  GET    /api/projects              自分が参加するプロジェクト一覧
  POST   /api/projects              プロジェクト作成 {name}
  PUT    /api/projects/<id>         プロジェクト更新(オーナーのみ) {name}
  DELETE /api/projects/<id>         プロジェクト削除(オーナーのみ)
  GET    /api/projects/<id>/members メンバー一覧(メンバーのみ)
  POST   /api/projects/<id>/members メンバー追加(オーナーのみ) {username, role?}
  DELETE /api/projects/<id>/members/<user_id>  メンバー削除(オーナーのみ)
  プロジェクト内データ(?project_id= またはbodyの project_id で指定。メンバーのみ)
  GET    /api/tasks?project_id=     タスク一覧
  POST   /api/tasks                 タスク作成
  POST   /api/tasks/reorder         並び順を保存
  PUT    /api/tasks/<id>            タスク更新
  DELETE /api/tasks/<id>            タスク削除
  GET    /api/columns?project_id=   かんばん列一覧
  POST   /api/columns               列作成
  POST   /api/columns/reorder       列の並び順を保存
  PUT    /api/columns/<id>          列更新
  DELETE /api/columns/<id>          列削除(配下タスクは別の列へ退避)
  GET    /api/iterations?project_id= イテレーション一覧
  POST   /api/iterations            イテレーション作成
  PUT    /api/iterations/<id>       イテレーション更新
  DELETE /api/iterations/<id>       イテレーション削除(配下タスクはバックログへ戻す)
それ以外のパスは静的ファイル(index.html等)を返す。
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import ssl
import threading
import urllib.request
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# DBの保存先。環境変数 TASKS_DB_PATH で差し替え可(AWS等で永続ボリュームを指定する用途)
DB_PATH = os.environ.get("TASKS_DB_PATH", os.path.join(BASE_DIR, "tasks.db"))
# 待受アドレス/ポートは環境変数で上書きできる。
#   HOST=0.0.0.0 … 全ネットワークインターフェースで待受(=ローカルホスト以外からもアクセス可)
#   HOST=127.0.0.1 … 同一マシンからのみ(従来の挙動)
# 既定は 0.0.0.0。認証はあるが、HTTPで運用する場合はリバースプロキシでのHTTPS化を推奨。
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))

# 初回起動時に作成する管理者アカウント(環境変数で指定可)
BOOTSTRAP_ADMIN_USER = os.environ.get("ADMIN_USERNAME", "admin")
BOOTSTRAP_ADMIN_PASS = os.environ.get("ADMIN_PASSWORD", "admin")

SESSION_COOKIE = "session"
SESSION_TTL = timedelta(days=7)
PBKDF2_ITERATIONS = 200_000

VALID_PRIORITY = {"low", "mid", "high"}
# イテレーションの状態
VALID_ITER_STATUS = {"planned", "active", "done"}
# 初期かんばん列 (名前, 完了扱いか)。プロジェクト作成時にシードする
DEFAULT_COLUMNS = [("未着手", 0), ("進行中", 0), ("完了", 1)]
# 初期のタスク種別。プロジェクト作成時にシードする(管理画面で追加/削除できる)
DEFAULT_TASK_TYPES = ["機能", "バグ", "改善"]
# 旧status文字列 → 初期列インデックスの対応(マイグレーション用)
LEGACY_STATUS_INDEX = {"todo": 0, "doing": 1, "done": 2}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ---- パスワードハッシュ(pbkdf2_hmac, 標準ライブラリのみ) ----
def hash_password(password):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERATIONS,
        base64.b64encode(salt).decode(),
        base64.b64encode(dk).decode(),
    )


def verify_password(password, stored):
    try:
        algo, iters, salt_b64, hash_b64 = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iters))
        return hmac.compare_digest(dk, expected)
    except (ValueError, TypeError):
        return False


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            is_admin      INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT    NOT NULL,
            updated_at    TEXT    NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token      TEXT    PRIMARY KEY,
            user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at TEXT    NOT NULL,
            expires_at TEXT    NOT NULL
        );
        CREATE TABLE IF NOT EXISTS projects (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL,
            owner_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at TEXT    NOT NULL,
            updated_at TEXT    NOT NULL
        );
        CREATE TABLE IF NOT EXISTS project_members (
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            user_id    INTEGER NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
            role       TEXT    NOT NULL DEFAULT 'member',
            created_at TEXT    NOT NULL,
            PRIMARY KEY (project_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS tasks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            title       TEXT    NOT NULL,
            description TEXT    NOT NULL DEFAULT '',
            status      TEXT    NOT NULL DEFAULT 'todo',
            priority    TEXT    NOT NULL DEFAULT 'mid',
            due_date    TEXT,
            category    TEXT    NOT NULL DEFAULT '',
            tags        TEXT    NOT NULL DEFAULT '',
            column_id   INTEGER,
            iteration_id INTEGER,
            type_id     INTEGER,
            position    INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT    NOT NULL,
            updated_at  TEXT    NOT NULL
        );
        CREATE TABLE IF NOT EXISTS task_types (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            name        TEXT    NOT NULL,
            position    INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT    NOT NULL,
            updated_at  TEXT    NOT NULL
        );
        CREATE TABLE IF NOT EXISTS columns (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            name        TEXT    NOT NULL,
            is_done     INTEGER NOT NULL DEFAULT 0,
            position    INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT    NOT NULL,
            updated_at  TEXT    NOT NULL
        );
        CREATE TABLE IF NOT EXISTS iterations (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            name        TEXT    NOT NULL,
            goal        TEXT    NOT NULL DEFAULT '',
            start_date  TEXT,
            end_date    TEXT,
            status      TEXT    NOT NULL DEFAULT 'planned',
            position    INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT    NOT NULL,
            updated_at  TEXT    NOT NULL
        );
        """
    )

    # 既存DBへのマイグレーション: projects に Slack Webhook URL 列を追加
    pcols = [r[1] for r in conn.execute("PRAGMA table_info(projects)").fetchall()]
    if "slack_webhook_url" not in pcols:
        conn.execute("ALTER TABLE projects ADD COLUMN slack_webhook_url TEXT NOT NULL DEFAULT ''")

    # 既存DBへのマイグレーション: tasks に種別(type_id)列を追加
    tcols = [r[1] for r in conn.execute("PRAGMA table_info(tasks)").fetchall()]
    if "type_id" not in tcols:
        conn.execute("ALTER TABLE tasks ADD COLUMN type_id INTEGER")

    # 管理者アカウントのブートストラップ(ユーザーが1人もいない初回のみ)
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        ts = now_iso()
        conn.execute(
            "INSERT INTO users (username, password_hash, is_admin, created_at, updated_at)"
            " VALUES (?,?,1,?,?)",
            (BOOTSTRAP_ADMIN_USER, hash_password(BOOTSTRAP_ADMIN_PASS), ts, ts),
        )
        print(f"★ 管理者アカウントを作成しました: ユーザー名 '{BOOTSTRAP_ADMIN_USER}'")
        if BOOTSTRAP_ADMIN_PASS == "admin":
            print("  ⚠ 初期パスワードは 'admin' です。ログイン後すぐに変更してください")
            print("  (環境変数 ADMIN_USERNAME / ADMIN_PASSWORD で初期値を指定できます)")

    conn.commit()
    conn.close()


def prune_sessions(conn):
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now_iso(),))


# ---- Slack 連携(Incoming Webhook) ----
def is_valid_slack_webhook(url):
    """Slack の Incoming Webhook URL かを検証(SSRF防止のためホストを固定)。"""
    if not url:
        return False
    try:
        u = urlparse(url)
    except ValueError:
        return False
    return u.scheme == "https" and u.hostname == "hooks.slack.com"


def _ssl_context():
    """HTTPS用のSSLコンテキスト。標準のCAが空の環境(macOSのpython.org版等)では
    certifi → /etc/ssl/cert.pem の順でフォールバックする(検証は常に有効)。"""
    ctx = ssl.create_default_context()
    if ctx.get_ca_certs():
        return ctx
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        pass
    if os.path.isfile("/etc/ssl/cert.pem"):
        try:
            return ssl.create_default_context(cafile="/etc/ssl/cert.pem")
        except Exception:
            pass
    return ctx


def post_to_slack(url, text):
    """Slack へメッセージを送信する(失敗してもアプリ本体に影響させない)。"""
    if not is_valid_slack_webhook(url):
        return
    payload = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5, context=_ssl_context()) as resp:
            resp.read()
    except Exception as e:  # ネットワーク不通・無効URL等は握りつぶしてログだけ
        print(f"  [slack] 送信失敗: {e}")


def notify_slack_async(url, text):
    """タスク作成のレスポンスを遅延させないよう別スレッドで送信する。"""
    if not is_valid_slack_webhook(url):
        return
    threading.Thread(target=post_to_slack, args=(url, text), daemon=True).start()


# ---- 直列化 ----
def task_to_dict(row):
    d = dict(row)
    d["tags"] = [t for t in (d.get("tags") or "").split(",") if t]
    return d


def column_to_dict(row):
    d = dict(row)
    d["is_done"] = bool(d.get("is_done"))
    return d


def user_to_dict(row):
    return {
        "id": row["id"],
        "username": row["username"],
        "is_admin": bool(row["is_admin"]),
        "created_at": row["created_at"],
    }


# ---- 入力サニタイズ ----
def sanitize_priority(value, default="mid"):
    return value if value in VALID_PRIORITY else default


def sanitize_iter_status(value, default="planned"):
    return value if value in VALID_ITER_STATUS else default


def sanitize_iteration_id(value, conn, project_id):
    """イテレーションIDを正規化。未割り当て/不正/他プロジェクトのものは None。"""
    if value in (None, "", "null"):
        return None
    try:
        v = int(value)
    except (TypeError, ValueError):
        return None
    row = conn.execute(
        "SELECT id FROM iterations WHERE id = ? AND project_id = ?", (v, project_id)
    ).fetchone()
    return v if row else None


def project_column_ids(conn, project_id):
    return [
        r[0]
        for r in conn.execute(
            "SELECT id FROM columns WHERE project_id = ? ORDER BY position ASC, id ASC",
            (project_id,),
        ).fetchall()
    ]


def sanitize_column_id(value, conn, project_id, default=None):
    """プロジェクト内の既存列IDに正規化する。不正なら default、それも無ければ先頭列。"""
    ids = project_column_ids(conn, project_id)
    try:
        v = int(value)
    except (TypeError, ValueError):
        v = None
    if v in ids:
        return v
    if default in ids:
        return default
    return ids[0] if ids else None


def sanitize_type_id(value, conn, project_id):
    """種別IDを正規化。未指定/不正/他プロジェクトのものは None。"""
    if value in (None, "", "null"):
        return None
    try:
        v = int(value)
    except (TypeError, ValueError):
        return None
    row = conn.execute(
        "SELECT id FROM task_types WHERE id = ? AND project_id = ?", (v, project_id)
    ).fetchone()
    return v if row else None


class Handler(BaseHTTPRequestHandler):
    server_version = "TaskManager/2.0"

    # ---- レスポンス補助 ----
    def _send_json(self, data, status=200, extra_headers=None):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def _query(self):
        return parse_qs(urlparse(self.path).query)

    def _path(self):
        return urlparse(self.path).path

    def log_message(self, fmt, *args):
        print(f"  {self.command} {self.path} -> {args[1] if len(args) > 1 else ''}")

    # ---- 認証 ----
    def _get_cookie(self, name):
        raw = self.headers.get("Cookie", "")
        if not raw:
            return None
        try:
            jar = SimpleCookie(raw)
        except Exception:
            return None
        m = jar.get(name)
        return m.value if m else None

    def current_user(self):
        """セッションCookieから現在のユーザーを返す。無効なら None。"""
        token = self._get_cookie(SESSION_COOKIE)
        if not token:
            return None
        conn = get_db()
        try:
            prune_sessions(conn)
            conn.commit()
            row = conn.execute(
                """SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
                   WHERE s.token = ? AND s.expires_at >= ?""",
                (token, now_iso()),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def login(self):
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        conn = get_db()
        try:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
            if row is None or not verify_password(password, row["password_hash"]):
                return self._send_json({"error": "ユーザー名またはパスワードが違います"}, 401)
            token = secrets.token_urlsafe(32)
            ts = now_iso()
            expires = (datetime.now(timezone.utc) + SESSION_TTL).isoformat()
            conn.execute(
                "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)",
                (token, row["id"], ts, expires),
            )
            conn.commit()
        finally:
            conn.close()
        cookie = (
            f"{SESSION_COOKIE}={token}; HttpOnly; Path=/; SameSite=Lax; "
            f"Max-Age={int(SESSION_TTL.total_seconds())}"
        )
        self._send_json(user_to_dict(row), 200, extra_headers=[("Set-Cookie", cookie)])

    def logout(self):
        token = self._get_cookie(SESSION_COOKIE)
        if token:
            conn = get_db()
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
            conn.close()
        cookie = f"{SESSION_COOKIE}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0"
        self._send_json({"ok": True}, 200, extra_headers=[("Set-Cookie", cookie)])

    def auth_me(self):
        user = self.current_user()
        if user is None:
            return self._send_json({"error": "unauthorized"}, 401)
        self._send_json(user_to_dict(user))

    # ---- プロジェクト権限ヘルパー ----
    @staticmethod
    def _membership(conn, project_id, user):
        return conn.execute(
            "SELECT role FROM project_members WHERE project_id = ? AND user_id = ?",
            (project_id, user["id"]),
        ).fetchone()

    def _require_member(self, conn, project_id, user):
        return self._membership(conn, project_id, user) is not None

    def _require_owner(self, conn, project_id, user):
        m = self._membership(conn, project_id, user)
        return m is not None and m["role"] == "owner"

    # ================= ルーティング =================
    def do_GET(self):
        path = self._path()
        if path == "/api/auth/me":
            return self.auth_me()
        if not path.startswith("/api/"):
            return self.serve_static()

        user = self.current_user()
        if user is None:
            return self._send_json({"error": "unauthorized"}, 401)

        if path == "/api/projects":
            return self.list_projects(user)
        m = re.match(r"^/api/projects/(\d+)/members$", path)
        if m:
            return self.list_members(user, int(m.group(1)))
        if path == "/api/users":
            return self.list_users(user)
        if path == "/api/tasks":
            return self.list_tasks(user)
        if path == "/api/columns":
            return self.list_columns(user)
        if path == "/api/iterations":
            return self.list_iterations(user)
        if path == "/api/task_types":
            return self.list_task_types(user)
        return self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        path = self._path()
        if path == "/api/auth/login":
            return self.login()
        if path == "/api/auth/logout":
            return self.logout()

        user = self.current_user()
        if user is None:
            return self._send_json({"error": "unauthorized"}, 401)

        if path == "/api/projects":
            return self.create_project(user)
        m = re.match(r"^/api/projects/(\d+)/members$", path)
        if m:
            return self.add_member(user, int(m.group(1)))
        if path == "/api/users":
            return self.create_user(user)
        if path == "/api/tasks/reorder":
            return self.reorder_tasks(user)
        if path == "/api/tasks":
            return self.create_task(user)
        if path == "/api/columns/reorder":
            return self.reorder_columns(user)
        if path == "/api/columns":
            return self.create_column(user)
        if path == "/api/iterations":
            return self.create_iteration(user)
        if path == "/api/task_types":
            return self.create_task_type(user)
        return self._send_json({"error": "not found"}, 404)

    def do_PUT(self):
        path = self._path()
        user = self.current_user()
        if user is None:
            return self._send_json({"error": "unauthorized"}, 401)
        m = re.match(r"^/api/users/(\d+)$", path)
        if m:
            return self.update_user(user, int(m.group(1)))
        m = re.match(r"^/api/projects/(\d+)$", path)
        if m:
            return self.update_project(user, int(m.group(1)))
        m = re.match(r"^/api/tasks/(\d+)$", path)
        if m:
            return self.update_task(user, int(m.group(1)))
        m = re.match(r"^/api/columns/(\d+)$", path)
        if m:
            return self.update_column(user, int(m.group(1)))
        m = re.match(r"^/api/iterations/(\d+)$", path)
        if m:
            return self.update_iteration(user, int(m.group(1)))
        m = re.match(r"^/api/task_types/(\d+)$", path)
        if m:
            return self.update_task_type(user, int(m.group(1)))
        return self._send_json({"error": "not found"}, 404)

    def do_DELETE(self):
        path = self._path()
        user = self.current_user()
        if user is None:
            return self._send_json({"error": "unauthorized"}, 401)
        m = re.match(r"^/api/users/(\d+)$", path)
        if m:
            return self.delete_user(user, int(m.group(1)))
        m = re.match(r"^/api/projects/(\d+)/members/(\d+)$", path)
        if m:
            return self.remove_member(user, int(m.group(1)), int(m.group(2)))
        m = re.match(r"^/api/projects/(\d+)$", path)
        if m:
            return self.delete_project(user, int(m.group(1)))
        m = re.match(r"^/api/tasks/(\d+)$", path)
        if m:
            return self.delete_task(user, int(m.group(1)))
        m = re.match(r"^/api/columns/(\d+)$", path)
        if m:
            return self.delete_column(user, int(m.group(1)))
        m = re.match(r"^/api/iterations/(\d+)$", path)
        if m:
            return self.delete_iteration(user, int(m.group(1)))
        m = re.match(r"^/api/task_types/(\d+)$", path)
        if m:
            return self.delete_task_type(user, int(m.group(1)))
        return self._send_json({"error": "not found"}, 404)

    # ================= ユーザー管理(管理者のみ) =================
    def list_users(self, user):
        if not user["is_admin"]:
            return self._send_json({"error": "管理者権限が必要です"}, 403)
        conn = get_db()
        rows = conn.execute("SELECT * FROM users ORDER BY id ASC").fetchall()
        conn.close()
        self._send_json([user_to_dict(r) for r in rows])

    def create_user(self, user):
        if not user["is_admin"]:
            return self._send_json({"error": "管理者権限が必要です"}, 403)
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        if not username:
            return self._send_json({"error": "ユーザー名は必須です"}, 400)
        if len(password) < 4:
            return self._send_json({"error": "パスワードは4文字以上にしてください"}, 400)
        ts = now_iso()
        conn = get_db()
        try:
            cur = conn.execute(
                "INSERT INTO users (username, password_hash, is_admin, created_at, updated_at)"
                " VALUES (?,?,?,?,?)",
                (username, hash_password(password), 1 if data.get("is_admin") else 0, ts, ts),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
        except sqlite3.IntegrityError:
            conn.close()
            return self._send_json({"error": "そのユーザー名は既に使われています"}, 409)
        conn.close()
        self._send_json(user_to_dict(row), 201)

    def update_user(self, user, target_id):
        if not user["is_admin"]:
            return self._send_json({"error": "管理者権限が必要です"}, 403)
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)
        conn = get_db()
        existing = conn.execute("SELECT * FROM users WHERE id = ?", (target_id,)).fetchone()
        if existing is None:
            conn.close()
            return self._send_json({"error": "not found"}, 404)
        fields = {}
        if "password" in data:
            pw = data.get("password") or ""
            if len(pw) < 4:
                conn.close()
                return self._send_json({"error": "パスワードは4文字以上にしてください"}, 400)
            fields["password_hash"] = hash_password(pw)
        if "is_admin" in data:
            # 自分自身の管理者権限を誤って外して締め出すのを防ぐ
            if existing["id"] == user["id"] and not data.get("is_admin"):
                conn.close()
                return self._send_json({"error": "自分自身の管理者権限は外せません"}, 400)
            fields["is_admin"] = 1 if data.get("is_admin") else 0
        if not fields:
            conn.close()
            return self._send_json({"error": "更新項目がありません"}, 400)
        fields["updated_at"] = now_iso()
        sets = ", ".join(f"{k} = ?" for k in fields)
        conn.execute(f"UPDATE users SET {sets} WHERE id = ?", list(fields.values()) + [target_id])
        # パスワード変更時は当該ユーザーのセッションを失効
        if "password_hash" in fields:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (target_id,))
        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE id = ?", (target_id,)).fetchone()
        conn.close()
        self._send_json(user_to_dict(row))

    def delete_user(self, user, target_id):
        if not user["is_admin"]:
            return self._send_json({"error": "管理者権限が必要です"}, 403)
        if target_id == user["id"]:
            return self._send_json({"error": "自分自身は削除できません"}, 400)
        conn = get_db()
        existing = conn.execute("SELECT id FROM users WHERE id = ?", (target_id,)).fetchone()
        if existing is None:
            conn.close()
            return self._send_json({"error": "not found"}, 404)
        # オーナーとして抱えるプロジェクトがあると孤児になるため拒否
        owned = conn.execute(
            "SELECT COUNT(*) FROM projects WHERE owner_id = ?", (target_id,)
        ).fetchone()[0]
        if owned:
            conn.close()
            return self._send_json(
                {"error": "このユーザーが所有するプロジェクトがあります。先に委譲/削除してください"}, 400
            )
        conn.execute("DELETE FROM users WHERE id = ?", (target_id,))
        conn.commit()
        conn.close()
        self._send_json({"ok": True})

    # ================= プロジェクト =================
    def _project_to_dict(self, conn, row, user):
        m = self._membership(conn, row["id"], user)
        owner = conn.execute(
            "SELECT username FROM users WHERE id = ?", (row["owner_id"],)
        ).fetchone()
        member_count = conn.execute(
            "SELECT COUNT(*) FROM project_members WHERE project_id = ?", (row["id"],)
        ).fetchone()[0]
        role = m["role"] if m else None
        webhook = row["slack_webhook_url"] if "slack_webhook_url" in row.keys() else ""
        result = {
            "id": row["id"],
            "name": row["name"],
            "owner_id": row["owner_id"],
            "owner_name": owner["username"] if owner else None,
            "my_role": role,
            "member_count": member_count,
            "slack_configured": bool(webhook),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
        # Webhook URL は秘密情報なのでオーナーにのみ返す
        if role == "owner":
            result["slack_webhook_url"] = webhook or ""
        return result

    def list_projects(self, user):
        conn = get_db()
        rows = conn.execute(
            """SELECT p.* FROM projects p
               JOIN project_members pm ON pm.project_id = p.id
               WHERE pm.user_id = ?
               ORDER BY p.created_at ASC, p.id ASC""",
            (user["id"],),
        ).fetchall()
        result = [self._project_to_dict(conn, r, user) for r in rows]
        conn.close()
        self._send_json(result)

    def create_project(self, user):
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)
        name = (data.get("name") or "").strip()
        if not name:
            return self._send_json({"error": "プロジェクト名は必須です"}, 400)
        ts = now_iso()
        conn = get_db()
        cur = conn.execute(
            "INSERT INTO projects (name, owner_id, created_at, updated_at) VALUES (?,?,?,?)",
            (name, user["id"], ts, ts),
        )
        pid = cur.lastrowid
        conn.execute(
            "INSERT INTO project_members (project_id, user_id, role, created_at) VALUES (?,?,'owner',?)",
            (pid, user["id"], ts),
        )
        # 既定のかんばん列をシード
        for i, (cname, is_done) in enumerate(DEFAULT_COLUMNS):
            conn.execute(
                "INSERT INTO columns (project_id, name, is_done, position, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?)",
                (pid, cname, is_done, i, ts, ts),
            )
        # 既定のタスク種別をシード
        for i, tname in enumerate(DEFAULT_TASK_TYPES):
            conn.execute(
                "INSERT INTO task_types (project_id, name, position, created_at, updated_at)"
                " VALUES (?,?,?,?,?)",
                (pid, tname, i, ts, ts),
            )
        conn.commit()
        row = conn.execute("SELECT * FROM projects WHERE id = ?", (pid,)).fetchone()
        result = self._project_to_dict(conn, row, user)
        conn.close()
        self._send_json(result, 201)

    def update_project(self, user, pid):
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)
        conn = get_db()
        existing = conn.execute("SELECT * FROM projects WHERE id = ?", (pid,)).fetchone()
        if existing is None:
            conn.close()
            return self._send_json({"error": "not found"}, 404)
        if not self._require_owner(conn, pid, user):
            conn.close()
            return self._send_json({"error": "オーナーのみ変更できます"}, 403)

        fields = {}
        if "name" in data:
            name = (data.get("name") or "").strip()
            if not name:
                conn.close()
                return self._send_json({"error": "プロジェクト名は必須です"}, 400)
            fields["name"] = name
        if "slack_webhook_url" in data:
            webhook = (data.get("slack_webhook_url") or "").strip()
            if webhook and not is_valid_slack_webhook(webhook):
                conn.close()
                return self._send_json(
                    {"error": "Slack Webhook URL は https://hooks.slack.com/ で始まる必要があります"}, 400
                )
            fields["slack_webhook_url"] = webhook
        if not fields:
            conn.close()
            return self._send_json({"error": "更新項目がありません"}, 400)

        fields["updated_at"] = now_iso()
        sets = ", ".join(f"{k} = ?" for k in fields)
        conn.execute(
            f"UPDATE projects SET {sets} WHERE id = ?", list(fields.values()) + [pid]
        )
        conn.commit()
        row = conn.execute("SELECT * FROM projects WHERE id = ?", (pid,)).fetchone()
        result = self._project_to_dict(conn, row, user)
        conn.close()
        self._send_json(result)

    def delete_project(self, user, pid):
        conn = get_db()
        existing = conn.execute("SELECT * FROM projects WHERE id = ?", (pid,)).fetchone()
        if existing is None:
            conn.close()
            return self._send_json({"error": "not found"}, 404)
        if not self._require_owner(conn, pid, user):
            conn.close()
            return self._send_json({"error": "オーナーのみ削除できます"}, 403)
        # 子テーブルは FK の ON DELETE CASCADE で消える
        conn.execute("DELETE FROM projects WHERE id = ?", (pid,))
        conn.commit()
        conn.close()
        self._send_json({"ok": True})

    # ---- メンバー管理 ----
    def list_members(self, user, pid):
        conn = get_db()
        if not self._require_member(conn, pid, user):
            conn.close()
            return self._send_json({"error": "このプロジェクトへのアクセス権がありません"}, 403)
        rows = conn.execute(
            """SELECT pm.user_id, pm.role, pm.created_at, u.username, u.is_admin
               FROM project_members pm JOIN users u ON u.id = pm.user_id
               WHERE pm.project_id = ?
               ORDER BY (pm.role = 'owner') DESC, u.username ASC""",
            (pid,),
        ).fetchall()
        conn.close()
        self._send_json(
            [
                {
                    "user_id": r["user_id"],
                    "username": r["username"],
                    "role": r["role"],
                    "created_at": r["created_at"],
                }
                for r in rows
            ]
        )

    def add_member(self, user, pid):
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)
        conn = get_db()
        if conn.execute("SELECT id FROM projects WHERE id = ?", (pid,)).fetchone() is None:
            conn.close()
            return self._send_json({"error": "not found"}, 404)
        if not self._require_owner(conn, pid, user):
            conn.close()
            return self._send_json({"error": "メンバーを追加できるのはオーナーのみです"}, 403)
        username = (data.get("username") or "").strip()
        target = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if target is None:
            conn.close()
            return self._send_json({"error": "そのユーザーは存在しません"}, 404)
        role = "owner" if data.get("role") == "owner" else "member"
        try:
            conn.execute(
                "INSERT INTO project_members (project_id, user_id, role, created_at) VALUES (?,?,?,?)",
                (pid, target["id"], role, now_iso()),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return self._send_json({"error": "そのユーザーは既にメンバーです"}, 409)
        conn.close()
        self._send_json(
            {"user_id": target["id"], "username": target["username"], "role": role}, 201
        )

    def remove_member(self, user, pid, target_user_id):
        conn = get_db()
        project = conn.execute("SELECT * FROM projects WHERE id = ?", (pid,)).fetchone()
        if project is None:
            conn.close()
            return self._send_json({"error": "not found"}, 404)
        if not self._require_owner(conn, pid, user):
            conn.close()
            return self._send_json({"error": "メンバーを削除できるのはオーナーのみです"}, 403)
        if target_user_id == project["owner_id"]:
            conn.close()
            return self._send_json({"error": "オーナーは削除できません"}, 400)
        cur = conn.execute(
            "DELETE FROM project_members WHERE project_id = ? AND user_id = ?",
            (pid, target_user_id),
        )
        conn.commit()
        removed = cur.rowcount
        conn.close()
        if removed == 0:
            return self._send_json({"error": "そのメンバーは見つかりません"}, 404)
        self._send_json({"ok": True})

    # ---- プロジェクトの解決(データ系API共通) ----
    def _resolve_project(self, conn, user, project_id):
        """project_id を検証し、メンバーなら int を返す。
        問題があれば (None, (エラーdict, status)) を返す。"""
        try:
            pid = int(project_id)
        except (TypeError, ValueError):
            return None, ({"error": "project_id is required"}, 400)
        if conn.execute("SELECT id FROM projects WHERE id = ?", (pid,)).fetchone() is None:
            return None, ({"error": "プロジェクトが見つかりません"}, 404)
        if not self._require_member(conn, pid, user):
            return None, ({"error": "このプロジェクトへのアクセス権がありません"}, 403)
        return pid, None

    def _project_of_row(self, conn, table, row_id):
        row = conn.execute(
            f"SELECT project_id FROM {table} WHERE id = ?", (row_id,)
        ).fetchone()
        return row["project_id"] if row else None

    # ================= タスクAPI =================
    def list_tasks(self, user):
        project_id = self._query().get("project_id", [None])[0]
        conn = get_db()
        pid, err = self._resolve_project(conn, user, project_id)
        if err:
            conn.close()
            return self._send_json(err[0], err[1])
        rows = conn.execute(
            "SELECT * FROM tasks WHERE project_id = ? ORDER BY position ASC, id ASC", (pid,)
        ).fetchall()
        conn.close()
        self._send_json([task_to_dict(r) for r in rows])

    def create_task(self, user):
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)
        title = (data.get("title") or "").strip()
        if not title:
            return self._send_json({"error": "title is required"}, 400)
        conn = get_db()
        pid, err = self._resolve_project(conn, user, data.get("project_id"))
        if err:
            conn.close()
            return self._send_json(err[0], err[1])

        column_id = sanitize_column_id(data.get("column_id"), conn, pid)
        if column_id is None:
            conn.close()
            return self._send_json({"error": "no columns exist"}, 400)
        ts = now_iso()
        tags = ",".join(t.strip() for t in (data.get("tags") or []) if str(t).strip())
        maxpos = conn.execute(
            "SELECT COALESCE(MAX(position), 0) FROM tasks WHERE project_id = ? AND column_id = ?",
            (pid, column_id),
        ).fetchone()[0]
        cur = conn.execute(
            """INSERT INTO tasks
               (project_id, title, description, priority, due_date, category, tags,
                column_id, iteration_id, type_id, position, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                pid,
                title,
                (data.get("description") or "").strip(),
                sanitize_priority(data.get("priority")),
                (data.get("due_date") or None),
                (data.get("category") or "").strip(),
                tags,
                column_id,
                sanitize_iteration_id(data.get("iteration_id"), conn, pid),
                sanitize_type_id(data.get("type_id"), conn, pid),
                maxpos + 1,
                ts,
                ts,
            ),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (cur.lastrowid,)).fetchone()

        # Slack 通知(プロジェクトに Webhook が設定されていれば送信)
        project = conn.execute("SELECT name, slack_webhook_url FROM projects WHERE id = ?", (pid,)).fetchone()
        col = conn.execute("SELECT name FROM columns WHERE id = ?", (column_id,)).fetchone()
        conn.close()

        if project and project["slack_webhook_url"]:
            prio_label = {"high": "高", "mid": "中", "low": "低"}.get(row["priority"], row["priority"])
            lines = [
                "🆕 新しいタスクが追加されました",
                f"*{row['title']}*",
                f"プロジェクト: {project['name']} / 優先度: {prio_label}"
                + (f" / 列: {col['name']}" if col else ""),
                f"登録者: {user['username']}",
            ]
            if row["due_date"]:
                lines.append(f"期限: {row['due_date']}")
            notify_slack_async(project["slack_webhook_url"], "\n".join(lines))

        self._send_json(task_to_dict(row), 201)

    def update_task(self, user, task_id):
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)
        conn = get_db()
        existing = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if existing is None:
            conn.close()
            return self._send_json({"error": "not found"}, 404)
        pid = existing["project_id"]
        if not self._require_member(conn, pid, user):
            conn.close()
            return self._send_json({"error": "このタスクへのアクセス権がありません"}, 403)

        cur = dict(existing)
        fields = {}
        if "title" in data:
            t = (data.get("title") or "").strip()
            if not t:
                conn.close()
                return self._send_json({"error": "title cannot be empty"}, 400)
            fields["title"] = t
        if "description" in data:
            fields["description"] = (data.get("description") or "").strip()
        if "column_id" in data:
            fields["column_id"] = sanitize_column_id(
                data.get("column_id"), conn, pid, cur["column_id"]
            )
        if "priority" in data:
            fields["priority"] = sanitize_priority(data.get("priority"), cur["priority"])
        if "due_date" in data:
            fields["due_date"] = data.get("due_date") or None
        if "category" in data:
            fields["category"] = (data.get("category") or "").strip()
        if "tags" in data:
            fields["tags"] = ",".join(
                t.strip() for t in (data.get("tags") or []) if str(t).strip()
            )
        if "iteration_id" in data:
            fields["iteration_id"] = sanitize_iteration_id(data.get("iteration_id"), conn, pid)
        if "type_id" in data:
            fields["type_id"] = sanitize_type_id(data.get("type_id"), conn, pid)
        if "position" in data:
            try:
                fields["position"] = int(data.get("position"))
            except (TypeError, ValueError):
                pass

        fields["updated_at"] = now_iso()
        sets = ", ".join(f"{k} = ?" for k in fields)
        params = list(fields.values()) + [task_id]
        conn.execute(f"UPDATE tasks SET {sets} WHERE id = ?", params)
        conn.commit()
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        conn.close()
        self._send_json(task_to_dict(row))

    def reorder_tasks(self, user):
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)
        ids = data.get("ids")
        if not isinstance(ids, list):
            return self._send_json({"error": "ids must be a list"}, 400)
        conn = get_db()
        pid, err = self._resolve_project(conn, user, data.get("project_id"))
        if err:
            conn.close()
            return self._send_json(err[0], err[1])

        ts = now_iso()
        for i, tid in enumerate(ids):
            try:
                tid = int(tid)
            except (TypeError, ValueError):
                continue
            conn.execute(
                "UPDATE tasks SET position = ?, updated_at = ? WHERE id = ? AND project_id = ?",
                (i, ts, tid, pid),
            )

        moved = data.get("moved_id")
        if moved is not None:
            try:
                moved = int(moved)
            except (TypeError, ValueError):
                moved = None
        if moved is not None:
            if "iteration_id" in data:
                conn.execute(
                    "UPDATE tasks SET iteration_id = ?, updated_at = ? WHERE id = ? AND project_id = ?",
                    (sanitize_iteration_id(data.get("iteration_id"), conn, pid), ts, moved, pid),
                )
            if "column_id" in data:
                conn.execute(
                    "UPDATE tasks SET column_id = ?, updated_at = ? WHERE id = ? AND project_id = ?",
                    (sanitize_column_id(data.get("column_id"), conn, pid), ts, moved, pid),
                )

        conn.commit()
        rows = conn.execute(
            "SELECT * FROM tasks WHERE project_id = ? ORDER BY position ASC, id ASC", (pid,)
        ).fetchall()
        conn.close()
        self._send_json([task_to_dict(r) for r in rows])

    def delete_task(self, user, task_id):
        conn = get_db()
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            conn.close()
            return self._send_json({"error": "not found"}, 404)
        if not self._require_member(conn, row["project_id"], user):
            conn.close()
            return self._send_json({"error": "このタスクへのアクセス権がありません"}, 403)
        conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
        conn.commit()
        conn.close()
        self._send_json({"ok": True})

    # ================= 列(かんばん)API =================
    def list_columns(self, user):
        project_id = self._query().get("project_id", [None])[0]
        conn = get_db()
        pid, err = self._resolve_project(conn, user, project_id)
        if err:
            conn.close()
            return self._send_json(err[0], err[1])
        rows = conn.execute(
            "SELECT * FROM columns WHERE project_id = ? ORDER BY position ASC, id ASC", (pid,)
        ).fetchall()
        conn.close()
        self._send_json([column_to_dict(r) for r in rows])

    def create_column(self, user):
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)
        name = (data.get("name") or "").strip()
        if not name:
            return self._send_json({"error": "name is required"}, 400)
        conn = get_db()
        pid, err = self._resolve_project(conn, user, data.get("project_id"))
        if err:
            conn.close()
            return self._send_json(err[0], err[1])
        ts = now_iso()
        maxpos = conn.execute(
            "SELECT COALESCE(MAX(position), -1) FROM columns WHERE project_id = ?", (pid,)
        ).fetchone()[0]
        cur = conn.execute(
            "INSERT INTO columns (project_id, name, is_done, position, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?)",
            (pid, name, 1 if data.get("is_done") else 0, maxpos + 1, ts, ts),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM columns WHERE id = ?", (cur.lastrowid,)).fetchone()
        conn.close()
        self._send_json(column_to_dict(row), 201)

    def update_column(self, user, col_id):
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)
        conn = get_db()
        existing = conn.execute("SELECT * FROM columns WHERE id = ?", (col_id,)).fetchone()
        if existing is None:
            conn.close()
            return self._send_json({"error": "not found"}, 404)
        if not self._require_member(conn, existing["project_id"], user):
            conn.close()
            return self._send_json({"error": "アクセス権がありません"}, 403)
        fields = {}
        if "name" in data:
            n = (data.get("name") or "").strip()
            if not n:
                conn.close()
                return self._send_json({"error": "name cannot be empty"}, 400)
            fields["name"] = n
        if "is_done" in data:
            fields["is_done"] = 1 if data.get("is_done") else 0
        if "position" in data:
            try:
                fields["position"] = int(data.get("position"))
            except (TypeError, ValueError):
                pass
        fields["updated_at"] = now_iso()
        sets = ", ".join(f"{k} = ?" for k in fields)
        conn.execute(f"UPDATE columns SET {sets} WHERE id = ?", list(fields.values()) + [col_id])
        conn.commit()
        row = conn.execute("SELECT * FROM columns WHERE id = ?", (col_id,)).fetchone()
        conn.close()
        self._send_json(column_to_dict(row))

    def reorder_columns(self, user):
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)
        ids = data.get("ids")
        if not isinstance(ids, list):
            return self._send_json({"error": "ids must be a list"}, 400)
        conn = get_db()
        pid, err = self._resolve_project(conn, user, data.get("project_id"))
        if err:
            conn.close()
            return self._send_json(err[0], err[1])
        ts = now_iso()
        for i, cid in enumerate(ids):
            try:
                cid = int(cid)
            except (TypeError, ValueError):
                continue
            conn.execute(
                "UPDATE columns SET position = ?, updated_at = ? WHERE id = ? AND project_id = ?",
                (i, ts, cid, pid),
            )
        conn.commit()
        rows = conn.execute(
            "SELECT * FROM columns WHERE project_id = ? ORDER BY position ASC, id ASC", (pid,)
        ).fetchall()
        conn.close()
        self._send_json([column_to_dict(r) for r in rows])

    def delete_column(self, user, col_id):
        conn = get_db()
        existing = conn.execute("SELECT * FROM columns WHERE id = ?", (col_id,)).fetchone()
        if existing is None:
            conn.close()
            return self._send_json({"error": "not found"}, 404)
        pid = existing["project_id"]
        if not self._require_member(conn, pid, user):
            conn.close()
            return self._send_json({"error": "アクセス権がありません"}, 403)
        ids = project_column_ids(conn, pid)
        if len(ids) <= 1:
            conn.close()
            return self._send_json({"error": "最後の列は削除できません"}, 400)
        remaining = [i for i in ids if i != col_id]
        idx = ids.index(col_id)
        target = ids[idx - 1] if idx > 0 else remaining[0]
        conn.execute(
            "UPDATE tasks SET column_id = ? WHERE column_id = ? AND project_id = ?",
            (target, col_id, pid),
        )
        conn.execute("DELETE FROM columns WHERE id = ?", (col_id,))
        conn.commit()
        conn.close()
        self._send_json({"ok": True, "moved_to": target})

    # ================= イテレーションAPI =================
    def list_iterations(self, user):
        project_id = self._query().get("project_id", [None])[0]
        conn = get_db()
        pid, err = self._resolve_project(conn, user, project_id)
        if err:
            conn.close()
            return self._send_json(err[0], err[1])
        rows = conn.execute(
            "SELECT * FROM iterations WHERE project_id = ? ORDER BY position ASC, id ASC", (pid,)
        ).fetchall()
        conn.close()
        self._send_json([dict(r) for r in rows])

    def create_iteration(self, user):
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)
        name = (data.get("name") or "").strip()
        if not name:
            return self._send_json({"error": "name is required"}, 400)
        conn = get_db()
        pid, err = self._resolve_project(conn, user, data.get("project_id"))
        if err:
            conn.close()
            return self._send_json(err[0], err[1])
        ts = now_iso()
        maxpos = conn.execute(
            "SELECT COALESCE(MAX(position), 0) FROM iterations WHERE project_id = ?", (pid,)
        ).fetchone()[0]
        cur = conn.execute(
            """INSERT INTO iterations
               (project_id, name, goal, start_date, end_date, status, position, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                pid,
                name,
                (data.get("goal") or "").strip(),
                (data.get("start_date") or None),
                (data.get("end_date") or None),
                sanitize_iter_status(data.get("status")),
                maxpos + 1,
                ts,
                ts,
            ),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM iterations WHERE id = ?", (cur.lastrowid,)).fetchone()
        conn.close()
        self._send_json(dict(row), 201)

    def update_iteration(self, user, iter_id):
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)
        conn = get_db()
        existing = conn.execute("SELECT * FROM iterations WHERE id = ?", (iter_id,)).fetchone()
        if existing is None:
            conn.close()
            return self._send_json({"error": "not found"}, 404)
        if not self._require_member(conn, existing["project_id"], user):
            conn.close()
            return self._send_json({"error": "アクセス権がありません"}, 403)
        cur = dict(existing)
        fields = {}
        if "name" in data:
            n = (data.get("name") or "").strip()
            if not n:
                conn.close()
                return self._send_json({"error": "name cannot be empty"}, 400)
            fields["name"] = n
        if "goal" in data:
            fields["goal"] = (data.get("goal") or "").strip()
        if "start_date" in data:
            fields["start_date"] = data.get("start_date") or None
        if "end_date" in data:
            fields["end_date"] = data.get("end_date") or None
        if "status" in data:
            fields["status"] = sanitize_iter_status(data.get("status"), cur["status"])
        if "position" in data:
            try:
                fields["position"] = int(data.get("position"))
            except (TypeError, ValueError):
                pass
        fields["updated_at"] = now_iso()
        sets = ", ".join(f"{k} = ?" for k in fields)
        conn.execute(
            f"UPDATE iterations SET {sets} WHERE id = ?", list(fields.values()) + [iter_id]
        )
        conn.commit()
        row = conn.execute("SELECT * FROM iterations WHERE id = ?", (iter_id,)).fetchone()
        conn.close()
        self._send_json(dict(row))

    def delete_iteration(self, user, iter_id):
        conn = get_db()
        existing = conn.execute("SELECT * FROM iterations WHERE id = ?", (iter_id,)).fetchone()
        if existing is None:
            conn.close()
            return self._send_json({"error": "not found"}, 404)
        pid = existing["project_id"]
        if not self._require_member(conn, pid, user):
            conn.close()
            return self._send_json({"error": "アクセス権がありません"}, 403)
        conn.execute(
            "UPDATE tasks SET iteration_id = NULL WHERE iteration_id = ? AND project_id = ?",
            (iter_id, pid),
        )
        conn.execute("DELETE FROM iterations WHERE id = ?", (iter_id,))
        conn.commit()
        conn.close()
        self._send_json({"ok": True})

    # ================= 種別(タスクタイプ)API =================
    def list_task_types(self, user):
        project_id = self._query().get("project_id", [None])[0]
        conn = get_db()
        pid, err = self._resolve_project(conn, user, project_id)
        if err:
            conn.close()
            return self._send_json(err[0], err[1])
        rows = conn.execute(
            "SELECT * FROM task_types WHERE project_id = ? ORDER BY position ASC, id ASC", (pid,)
        ).fetchall()
        conn.close()
        self._send_json([dict(r) for r in rows])

    def create_task_type(self, user):
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)
        name = (data.get("name") or "").strip()
        if not name:
            return self._send_json({"error": "name is required"}, 400)
        conn = get_db()
        pid, err = self._resolve_project(conn, user, data.get("project_id"))
        if err:
            conn.close()
            return self._send_json(err[0], err[1])
        ts = now_iso()
        maxpos = conn.execute(
            "SELECT COALESCE(MAX(position), -1) FROM task_types WHERE project_id = ?", (pid,)
        ).fetchone()[0]
        cur = conn.execute(
            "INSERT INTO task_types (project_id, name, position, created_at, updated_at)"
            " VALUES (?,?,?,?,?)",
            (pid, name, maxpos + 1, ts, ts),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM task_types WHERE id = ?", (cur.lastrowid,)).fetchone()
        conn.close()
        self._send_json(dict(row), 201)

    def update_task_type(self, user, type_id):
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)
        conn = get_db()
        existing = conn.execute("SELECT * FROM task_types WHERE id = ?", (type_id,)).fetchone()
        if existing is None:
            conn.close()
            return self._send_json({"error": "not found"}, 404)
        if not self._require_member(conn, existing["project_id"], user):
            conn.close()
            return self._send_json({"error": "アクセス権がありません"}, 403)
        fields = {}
        if "name" in data:
            n = (data.get("name") or "").strip()
            if not n:
                conn.close()
                return self._send_json({"error": "name cannot be empty"}, 400)
            fields["name"] = n
        if "position" in data:
            try:
                fields["position"] = int(data.get("position"))
            except (TypeError, ValueError):
                pass
        if not fields:
            conn.close()
            return self._send_json({"error": "更新項目がありません"}, 400)
        fields["updated_at"] = now_iso()
        sets = ", ".join(f"{k} = ?" for k in fields)
        conn.execute(
            f"UPDATE task_types SET {sets} WHERE id = ?", list(fields.values()) + [type_id]
        )
        conn.commit()
        row = conn.execute("SELECT * FROM task_types WHERE id = ?", (type_id,)).fetchone()
        conn.close()
        self._send_json(dict(row))

    def delete_task_type(self, user, type_id):
        conn = get_db()
        existing = conn.execute("SELECT * FROM task_types WHERE id = ?", (type_id,)).fetchone()
        if existing is None:
            conn.close()
            return self._send_json({"error": "not found"}, 404)
        pid = existing["project_id"]
        if not self._require_member(conn, pid, user):
            conn.close()
            return self._send_json({"error": "アクセス権がありません"}, 403)
        # 種別を削除しても配下タスクは消さず、種別なし(NULL)に戻す
        conn.execute(
            "UPDATE tasks SET type_id = NULL WHERE type_id = ? AND project_id = ?",
            (type_id, pid),
        )
        conn.execute("DELETE FROM task_types WHERE id = ?", (type_id,))
        conn.commit()
        conn.close()
        self._send_json({"ok": True})

    # ================= 静的ファイル配信 =================
    def serve_static(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            path = "/index.html"
        safe = os.path.normpath(path).lstrip("/")
        full = os.path.join(BASE_DIR, safe)
        if not full.startswith(BASE_DIR) or not os.path.isfile(full):
            return self._send_json({"error": "not found"}, 404)

        ctype = "text/html; charset=utf-8"
        if full.endswith(".js"):
            ctype = "application/javascript; charset=utf-8"
        elif full.endswith(".css"):
            ctype = "text/css; charset=utf-8"
        elif full.endswith(".json"):
            ctype = "application/json; charset=utf-8"

        with open(full, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    display_host = "localhost" if HOST in ("0.0.0.0", "") else HOST
    print(f"タスク管理アプリ起動: http://{display_host}:{PORT}  (待受 {HOST}:{PORT})")
    print(f"DB: {DB_PATH}")
    if HOST in ("0.0.0.0", ""):
        print("⚠ 全ネットワークインターフェースで公開中です。ログイン認証はありますが、")
        print("  HTTPのままインターネットに直接さらすとパスワードが平文で流れます。")
        print("  AWSのセキュリティグループ/ファイアウォールで接続元を絞り、外部公開時は")
        print("  リバースプロキシ(Nginx/ALB等)でHTTPS化してください。")
        print("  同一マシン内のみに制限するには HOST=127.0.0.1 を指定してください。")
    print("停止: Ctrl+C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n停止しました。")
        server.shutdown()


if __name__ == "__main__":
    main()
