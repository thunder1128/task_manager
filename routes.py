#!/usr/bin/env python3
"""APIエンドポイントとルーティング(ディスパッチ)。

ApiRoutes は BaseHTTPRequestHandler に組み込むミックスイン。
HTTPの低レベル処理(_send_json / _read_json / _query / _path /
_get_cookie / serve_static)は server.Handler 側で実装される。

ルート一覧:
  認証      POST /api/auth/login, POST /api/auth/logout,
            GET /api/auth/me, PUT /api/auth/me(自分のユーザー名変更)
  ユーザー   GET/POST /api/users, PUT/DELETE /api/users/<id>           (管理者のみ)
  プロジェクト GET/POST /api/projects, PUT/DELETE /api/projects/<id>
             GET/POST /api/projects/<id>/members,
             DELETE /api/projects/<id>/members/<user_id>
  タスク     GET/POST /api/tasks, POST /api/tasks/reorder, PUT/DELETE /api/tasks/<id>
  列        GET/POST /api/columns, POST /api/columns/reorder, PUT/DELETE /api/columns/<id>
  イテレーション GET/POST /api/iterations, PUT/DELETE /api/iterations/<id>
  種別      GET/POST /api/task_types, PUT/DELETE /api/task_types/<id>
"""

import re
import secrets
import sqlite3
from datetime import datetime, timezone

from const import DEFAULT_COLUMNS, DEFAULT_TASK_TYPES, SESSION_COOKIE, SESSION_TTL
from core import *


class ApiRoutes:
    """APIルート群(server.Handler に組み込むミックスイン)。"""

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
        # ログインはユーザーID(login_id)で行う(旧クライアント互換で username も受ける)
        login_id = (data.get("login_id") or data.get("username") or "").strip()
        password = data.get("password") or ""
        conn = get_db()
        try:
            row = conn.execute(
                "SELECT * FROM users WHERE login_id = ?", (login_id,)
            ).fetchone()
            if row is None or not verify_password(password, row["password_hash"]):
                return self._send_json({"error": "ユーザーIDまたはパスワードが違います"}, 401)
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

    def update_me(self, user):
        """ログイン中のユーザー自身がプロフィール(ユーザー名/パスワード)を更新する。

        body 例:
          {"username": "newname"}                                    # 名前変更
          {"current_password": "...", "new_password": "..."}         # パスワード変更
        パスワード変更には現在のパスワードの一致を必須とする。
        """
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)

        ts = now_iso()
        changed = False
        conn = get_db()

        # ログイン用ユーザーIDの変更
        if "login_id" in data:
            login_id = (data.get("login_id") or "").strip()
            if not login_id:
                conn.close()
                return self._send_json({"error": "ユーザーIDは必須です"}, 400)
            try:
                conn.execute(
                    "UPDATE users SET login_id = ?, updated_at = ? WHERE id = ?",
                    (login_id, ts, user["id"]),
                )
            except sqlite3.IntegrityError:
                conn.close()
                return self._send_json({"error": "そのユーザーIDは既に使われています"}, 409)
            changed = True

        # ユーザー名(表示名)の変更
        if "username" in data:
            username = (data.get("username") or "").strip()
            if not username:
                conn.close()
                return self._send_json({"error": "ユーザー名は必須です"}, 400)
            try:
                conn.execute(
                    "UPDATE users SET username = ?, updated_at = ? WHERE id = ?",
                    (username, ts, user["id"]),
                )
            except sqlite3.IntegrityError:
                conn.close()
                return self._send_json({"error": "そのユーザー名は既に使われています"}, 409)
            changed = True

        # パスワードの変更(現在のパスワード確認が必須)
        if "new_password" in data:
            new_pw = data.get("new_password") or ""
            cur_pw = data.get("current_password") or ""
            row = conn.execute(
                "SELECT password_hash FROM users WHERE id = ?", (user["id"],)
            ).fetchone()
            if not verify_password(cur_pw, row["password_hash"]):
                conn.close()
                return self._send_json({"error": "現在のパスワードが違います"}, 403)
            if len(new_pw) < 4:
                conn.close()
                return self._send_json({"error": "新しいパスワードは4文字以上にしてください"}, 400)
            conn.execute(
                "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
                (hash_password(new_pw), ts, user["id"]),
            )
            # 他端末のセッションは失効させる(今使っているセッションは維持)
            token = self._get_cookie(SESSION_COOKIE)
            conn.execute(
                "DELETE FROM sessions WHERE user_id = ? AND token != ?", (user["id"], token)
            )
            changed = True

        if not changed:
            conn.close()
            return self._send_json({"error": "更新項目がありません"}, 400)

        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
        conn.close()
        self._send_json(user_to_dict(row))

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
        if path == "/api/auth/me":
            return self.update_me(user)
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
        login_id = (data.get("login_id") or "").strip()
        username = (data.get("username") or "").strip() or login_id
        password = data.get("password") or ""
        if not login_id:
            return self._send_json({"error": "ユーザーIDは必須です"}, 400)
        if len(password) < 4:
            return self._send_json({"error": "パスワードは4文字以上にしてください"}, 400)
        ts = now_iso()
        conn = get_db()
        try:
            cur = conn.execute(
                "INSERT INTO users (login_id, username, password_hash, is_admin, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?)",
                (login_id, username, hash_password(password), 1 if data.get("is_admin") else 0, ts, ts),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
        except sqlite3.IntegrityError:
            conn.close()
            return self._send_json({"error": "そのユーザーID/ユーザー名は既に使われています"}, 409)
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
        if "login_id" in data:
            login_id = (data.get("login_id") or "").strip()
            if not login_id:
                conn.close()
                return self._send_json({"error": "ユーザーIDは必須です"}, 400)
            fields["login_id"] = login_id
        if "username" in data:
            username = (data.get("username") or "").strip()
            if not username:
                conn.close()
                return self._send_json({"error": "ユーザー名は必須です"}, 400)
            fields["username"] = username
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
        try:
            conn.execute(f"UPDATE users SET {sets} WHERE id = ?", list(fields.values()) + [target_id])
        except sqlite3.IntegrityError:
            conn.close()
            return self._send_json({"error": "そのユーザーID/ユーザー名は既に使われています"}, 409)
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
        # 外したメンバーが担当だったタスクは「未割り当て」に戻す
        conn.execute(
            "UPDATE tasks SET assignee_id = NULL WHERE project_id = ? AND assignee_id = ?",
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
                column_id, iteration_id, type_id, assignee_id, position, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                sanitize_assignee_id(data.get("assignee_id"), conn, pid),
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
        if "assignee_id" in data:
            fields["assignee_id"] = sanitize_assignee_id(data.get("assignee_id"), conn, pid)
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
