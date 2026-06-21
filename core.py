#!/usr/bin/env python3
"""共有モジュール: 設定・DB・各種ヘルパー(HTTP非依存)。

server.py / routes.py の両方から利用される。DBアクセス、パスワードハッシュ、
Slack送信、JSON直列化、入力サニタイズなどをまとめる。
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import ssl
import threading
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

from const import (
    BOOTSTRAP_ADMIN_PASS,
    BOOTSTRAP_ADMIN_USER,
    DB_PATH,
    PBKDF2_ITERATIONS,
    VALID_ITER_STATUS,
    VALID_PRIORITY,
)

# このモジュールが公開するのはヘルパー関数のみ(定数は const.py を参照)
__all__ = [
    "get_db", "now_iso", "hash_password", "verify_password",
    "init_db", "prune_sessions",
    "is_valid_slack_webhook", "post_to_slack", "notify_slack_async",
    "task_to_dict", "column_to_dict", "user_to_dict",
    "sanitize_priority", "sanitize_iter_status", "sanitize_iteration_id",
    "project_column_ids", "sanitize_column_id", "sanitize_type_id",
    "sanitize_assignee_id",
]


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
            login_id      TEXT    NOT NULL UNIQUE,
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
            assignee_id INTEGER,
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

    # 既存DBへのマイグレーション: users にログイン用ID(login_id)列を追加
    # 既存ユーザーは login_id = username で初期化(従来のユーザー名でログインできる)
    ucols = [r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
    if "login_id" not in ucols:
        conn.execute("ALTER TABLE users ADD COLUMN login_id TEXT NOT NULL DEFAULT ''")
        conn.execute("UPDATE users SET login_id = username WHERE login_id = ''")
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_login_id ON users(login_id)"
        )

    # 既存DBへのマイグレーション: projects に Slack Webhook URL 列を追加
    pcols = [r[1] for r in conn.execute("PRAGMA table_info(projects)").fetchall()]
    if "slack_webhook_url" not in pcols:
        conn.execute("ALTER TABLE projects ADD COLUMN slack_webhook_url TEXT NOT NULL DEFAULT ''")

    # 既存DBへのマイグレーション: tasks に種別(type_id)/担当者(assignee_id)列を追加
    tcols = [r[1] for r in conn.execute("PRAGMA table_info(tasks)").fetchall()]
    if "type_id" not in tcols:
        conn.execute("ALTER TABLE tasks ADD COLUMN type_id INTEGER")
    if "assignee_id" not in tcols:
        conn.execute("ALTER TABLE tasks ADD COLUMN assignee_id INTEGER")

    # 管理者アカウントのブートストラップ(ユーザーが1人もいない初回のみ)
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        ts = now_iso()
        conn.execute(
            "INSERT INTO users (login_id, username, password_hash, is_admin, created_at, updated_at)"
            " VALUES (?,?,?,1,?,?)",
            (BOOTSTRAP_ADMIN_USER, BOOTSTRAP_ADMIN_USER, hash_password(BOOTSTRAP_ADMIN_PASS), ts, ts),
        )
        print(f"★ 管理者アカウントを作成しました: ログインID '{BOOTSTRAP_ADMIN_USER}'")
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
        "login_id": row["login_id"],
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


def sanitize_assignee_id(value, conn, project_id):
    """担当者IDを正規化。未指定/不正/そのプロジェクトの非メンバーは None。"""
    if value in (None, "", "null"):
        return None
    try:
        v = int(value)
    except (TypeError, ValueError):
        return None
    row = conn.execute(
        "SELECT 1 FROM project_members WHERE user_id = ? AND project_id = ?",
        (v, project_id),
    ).fetchone()
    return v if row else None
