#!/usr/bin/env python3
"""タスク管理WEBアプリ バックエンド。

Python標準ライブラリのみで動作する軽量HTTPサーバー。
データは同じディレクトリの tasks.db (SQLite) に永続化する。
追加インストール不要。実行:  python3 server.py

API:
  GET    /api/tasks               タスク一覧
  POST   /api/tasks               タスク作成
  POST   /api/tasks/reorder       グループ内の並び順を保存
  PUT    /api/tasks/<id>          タスク更新
  DELETE /api/tasks/<id>          タスク削除
  GET    /api/columns             かんばん列一覧
  POST   /api/columns             列作成
  POST   /api/columns/reorder     列の並び順を保存
  PUT    /api/columns/<id>        列更新
  DELETE /api/columns/<id>        列削除(配下タスクは別の列へ退避)
  GET    /api/iterations          イテレーション一覧
  POST   /api/iterations          イテレーション作成
  PUT    /api/iterations/<id>     イテレーション更新
  DELETE /api/iterations/<id>     イテレーション削除(配下タスクはバックログへ戻す)
それ以外のパスは静的ファイル(index.html等)を返す。
"""

import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "tasks.db")
HOST = "127.0.0.1"
PORT = 8000

VALID_PRIORITY = {"low", "mid", "high"}
# イテレーションの状態
VALID_ITER_STATUS = {"planned", "active", "done"}
# 初期かんばん列 (名前, 完了扱いか)
DEFAULT_COLUMNS = [("未着手", 0), ("進行中", 0), ("完了", 1)]
# 旧status文字列 → 初期列インデックスの対応(マイグレーション用)
LEGACY_STATUS_INDEX = {"todo": 0, "doing": 1, "done": 2}


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS tasks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT    NOT NULL,
            description TEXT    NOT NULL DEFAULT '',
            status      TEXT    NOT NULL DEFAULT 'todo',
            priority    TEXT    NOT NULL DEFAULT 'mid',
            due_date    TEXT,
            category    TEXT    NOT NULL DEFAULT '',
            tags        TEXT    NOT NULL DEFAULT '',
            position    INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT    NOT NULL,
            updated_at  TEXT    NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS columns (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL,
            is_done     INTEGER NOT NULL DEFAULT 0,
            position    INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT    NOT NULL,
            updated_at  TEXT    NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS iterations (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL,
            goal        TEXT    NOT NULL DEFAULT '',
            start_date  TEXT,
            end_date    TEXT,
            status      TEXT    NOT NULL DEFAULT 'planned',
            position    INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT    NOT NULL,
            updated_at  TEXT    NOT NULL
        )
        """
    )

    ts = now_iso()
    # 初期列をシード(列が1つも無いときだけ)
    if conn.execute("SELECT COUNT(*) FROM columns").fetchone()[0] == 0:
        for i, (name, is_done) in enumerate(DEFAULT_COLUMNS):
            conn.execute(
                "INSERT INTO columns (name, is_done, position, created_at, updated_at)"
                " VALUES (?,?,?,?,?)",
                (name, is_done, i, ts, ts),
            )

    # 既存DBへのマイグレーション: tasks に iteration_id / column_id 列を追加
    cols = [r[1] for r in conn.execute("PRAGMA table_info(tasks)").fetchall()]
    if "iteration_id" not in cols:
        conn.execute("ALTER TABLE tasks ADD COLUMN iteration_id INTEGER")
    if "column_id" not in cols:
        conn.execute("ALTER TABLE tasks ADD COLUMN column_id INTEGER")

    # column_id 未設定のタスクを、旧statusから初期列へ割り当て
    col_ids = [
        r[0] for r in conn.execute(
            "SELECT id FROM columns ORDER BY position ASC, id ASC"
        ).fetchall()
    ]
    if col_ids:
        first_col = col_ids[0]
        unset = conn.execute(
            "SELECT id, status FROM tasks WHERE column_id IS NULL"
        ).fetchall()
        for row in unset:
            idx = LEGACY_STATUS_INDEX.get(row["status"], 0)
            target = col_ids[idx] if idx < len(col_ids) else first_col
            conn.execute(
                "UPDATE tasks SET column_id = ? WHERE id = ?", (target, row["id"])
            )

    conn.commit()
    conn.close()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def task_to_dict(row):
    d = dict(row)
    d["tags"] = [t for t in (d.get("tags") or "").split(",") if t]
    return d


def column_to_dict(row):
    d = dict(row)
    d["is_done"] = bool(d.get("is_done"))
    return d


def sanitize_priority(value, default="mid"):
    return value if value in VALID_PRIORITY else default


def sanitize_iter_status(value, default="planned"):
    return value if value in VALID_ITER_STATUS else default


def sanitize_iteration_id(value):
    if value in (None, "", "null"):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def column_ids(conn):
    return [
        r[0] for r in conn.execute(
            "SELECT id FROM columns ORDER BY position ASC, id ASC"
        ).fetchall()
    ]


def sanitize_column_id(value, conn, default=None):
    """既存の列IDに正規化する。不正なら default、それも無ければ先頭列。"""
    ids = column_ids(conn)
    try:
        v = int(value)
    except (TypeError, ValueError):
        v = None
    if v in ids:
        return v
    if default in ids:
        return default
    return ids[0] if ids else None


class Handler(BaseHTTPRequestHandler):
    server_version = "TaskManager/1.2"

    # ---- レスポンス補助 ----
    def _send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
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

    def log_message(self, fmt, *args):
        print(f"  {self.command} {self.path} -> {args[1] if len(args) > 1 else ''}")

    # ---- ルーティング ----
    def do_GET(self):
        if self.path == "/api/tasks":
            return self.list_tasks()
        if self.path == "/api/columns":
            return self.list_columns()
        if self.path == "/api/iterations":
            return self.list_iterations()
        return self.serve_static()

    def do_POST(self):
        if self.path == "/api/tasks/reorder":
            return self.reorder_tasks()
        if self.path == "/api/tasks":
            return self.create_task()
        if self.path == "/api/columns/reorder":
            return self.reorder_columns()
        if self.path == "/api/columns":
            return self.create_column()
        if self.path == "/api/iterations":
            return self.create_iteration()
        self._send_json({"error": "not found"}, 404)

    def do_PUT(self):
        m = re.match(r"^/api/tasks/(\d+)$", self.path)
        if m:
            return self.update_task(int(m.group(1)))
        m = re.match(r"^/api/columns/(\d+)$", self.path)
        if m:
            return self.update_column(int(m.group(1)))
        m = re.match(r"^/api/iterations/(\d+)$", self.path)
        if m:
            return self.update_iteration(int(m.group(1)))
        self._send_json({"error": "not found"}, 404)

    def do_DELETE(self):
        m = re.match(r"^/api/tasks/(\d+)$", self.path)
        if m:
            return self.delete_task(int(m.group(1)))
        m = re.match(r"^/api/columns/(\d+)$", self.path)
        if m:
            return self.delete_column(int(m.group(1)))
        m = re.match(r"^/api/iterations/(\d+)$", self.path)
        if m:
            return self.delete_iteration(int(m.group(1)))
        self._send_json({"error": "not found"}, 404)

    # ---- タスクAPI ----
    def list_tasks(self):
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM tasks ORDER BY position ASC, id ASC"
        ).fetchall()
        conn.close()
        self._send_json([task_to_dict(r) for r in rows])

    def create_task(self):
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)
        title = (data.get("title") or "").strip()
        if not title:
            return self._send_json({"error": "title is required"}, 400)

        ts = now_iso()
        tags = ",".join(t.strip() for t in (data.get("tags") or []) if str(t).strip())
        conn = get_db()
        column_id = sanitize_column_id(data.get("column_id"), conn)
        if column_id is None:
            conn.close()
            return self._send_json({"error": "no columns exist"}, 400)
        maxpos = conn.execute(
            "SELECT COALESCE(MAX(position), 0) FROM tasks WHERE column_id = ?",
            (column_id,),
        ).fetchone()[0]
        cur = conn.execute(
            """INSERT INTO tasks
               (title, description, priority, due_date, category, tags,
                column_id, iteration_id, position, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                title,
                (data.get("description") or "").strip(),
                sanitize_priority(data.get("priority")),
                (data.get("due_date") or None),
                (data.get("category") or "").strip(),
                tags,
                column_id,
                sanitize_iteration_id(data.get("iteration_id")),
                maxpos + 1,
                ts,
                ts,
            ),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (cur.lastrowid,)).fetchone()
        conn.close()
        self._send_json(task_to_dict(row), 201)

    def update_task(self, task_id):
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)

        conn = get_db()
        existing = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if existing is None:
            conn.close()
            return self._send_json({"error": "not found"}, 404)

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
                data.get("column_id"), conn, cur["column_id"]
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
            fields["iteration_id"] = sanitize_iteration_id(data.get("iteration_id"))
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

    def reorder_tasks(self):
        """グループ内の並び順を保存する。

        body 例:
          {"ids": [3,1,2],            # このグループ内の新しい並び順(task id)
           "moved_id": 1,             # (任意) 移動したタスク
           "iteration_id": 5 | null,  # (任意) moved_id に設定するイテレーション
           "column_id": 4}            # (任意) moved_id に設定する列
        ids の各タスクに position を保存し、全タスク一覧を返す。
        """
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)
        ids = data.get("ids")
        if not isinstance(ids, list):
            return self._send_json({"error": "ids must be a list"}, 400)

        ts = now_iso()
        conn = get_db()
        for i, tid in enumerate(ids):
            try:
                tid = int(tid)
            except (TypeError, ValueError):
                continue
            conn.execute(
                "UPDATE tasks SET position = ?, updated_at = ? WHERE id = ?",
                (i, ts, tid),
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
                    "UPDATE tasks SET iteration_id = ?, updated_at = ? WHERE id = ?",
                    (sanitize_iteration_id(data.get("iteration_id")), ts, moved),
                )
            if "column_id" in data:
                conn.execute(
                    "UPDATE tasks SET column_id = ?, updated_at = ? WHERE id = ?",
                    (sanitize_column_id(data.get("column_id"), conn), ts, moved),
                )

        conn.commit()
        rows = conn.execute(
            "SELECT * FROM tasks ORDER BY position ASC, id ASC"
        ).fetchall()
        conn.close()
        self._send_json([task_to_dict(r) for r in rows])

    def delete_task(self, task_id):
        conn = get_db()
        cur = conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
        conn.commit()
        deleted = cur.rowcount
        conn.close()
        if deleted == 0:
            return self._send_json({"error": "not found"}, 404)
        self._send_json({"ok": True})

    # ---- 列(かんばん)API ----
    def list_columns(self):
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM columns ORDER BY position ASC, id ASC"
        ).fetchall()
        conn.close()
        self._send_json([column_to_dict(r) for r in rows])

    def create_column(self):
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)
        name = (data.get("name") or "").strip()
        if not name:
            return self._send_json({"error": "name is required"}, 400)

        ts = now_iso()
        conn = get_db()
        maxpos = conn.execute(
            "SELECT COALESCE(MAX(position), -1) FROM columns"
        ).fetchone()[0]
        cur = conn.execute(
            "INSERT INTO columns (name, is_done, position, created_at, updated_at)"
            " VALUES (?,?,?,?,?)",
            (name, 1 if data.get("is_done") else 0, maxpos + 1, ts, ts),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM columns WHERE id = ?", (cur.lastrowid,)
        ).fetchone()
        conn.close()
        self._send_json(column_to_dict(row), 201)

    def update_column(self, col_id):
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)
        conn = get_db()
        existing = conn.execute(
            "SELECT * FROM columns WHERE id = ?", (col_id,)
        ).fetchone()
        if existing is None:
            conn.close()
            return self._send_json({"error": "not found"}, 404)

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
        params = list(fields.values()) + [col_id]
        conn.execute(f"UPDATE columns SET {sets} WHERE id = ?", params)
        conn.commit()
        row = conn.execute("SELECT * FROM columns WHERE id = ?", (col_id,)).fetchone()
        conn.close()
        self._send_json(column_to_dict(row))

    def reorder_columns(self):
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)
        ids = data.get("ids")
        if not isinstance(ids, list):
            return self._send_json({"error": "ids must be a list"}, 400)
        ts = now_iso()
        conn = get_db()
        for i, cid in enumerate(ids):
            try:
                cid = int(cid)
            except (TypeError, ValueError):
                continue
            conn.execute(
                "UPDATE columns SET position = ?, updated_at = ? WHERE id = ?",
                (i, ts, cid),
            )
        conn.commit()
        rows = conn.execute(
            "SELECT * FROM columns ORDER BY position ASC, id ASC"
        ).fetchall()
        conn.close()
        self._send_json([column_to_dict(r) for r in rows])

    def delete_column(self, col_id):
        conn = get_db()
        existing = conn.execute(
            "SELECT id FROM columns WHERE id = ?", (col_id,)
        ).fetchone()
        if existing is None:
            conn.close()
            return self._send_json({"error": "not found"}, 404)
        ids = column_ids(conn)
        if len(ids) <= 1:
            conn.close()
            return self._send_json({"error": "最後の列は削除できません"}, 400)
        # 配下タスクを左隣(無ければ右隣)の列へ退避
        remaining = [i for i in ids if i != col_id]
        idx = ids.index(col_id)
        target = ids[idx - 1] if idx > 0 else remaining[0]
        conn.execute(
            "UPDATE tasks SET column_id = ? WHERE column_id = ?", (target, col_id)
        )
        conn.execute("DELETE FROM columns WHERE id = ?", (col_id,))
        conn.commit()
        conn.close()
        self._send_json({"ok": True, "moved_to": target})

    # ---- イテレーションAPI ----
    def list_iterations(self):
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM iterations ORDER BY position ASC, id ASC"
        ).fetchall()
        conn.close()
        self._send_json([dict(r) for r in rows])

    def create_iteration(self):
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)
        name = (data.get("name") or "").strip()
        if not name:
            return self._send_json({"error": "name is required"}, 400)

        ts = now_iso()
        conn = get_db()
        maxpos = conn.execute(
            "SELECT COALESCE(MAX(position), 0) FROM iterations"
        ).fetchone()[0]
        cur = conn.execute(
            """INSERT INTO iterations
               (name, goal, start_date, end_date, status, position, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
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
        row = conn.execute(
            "SELECT * FROM iterations WHERE id = ?", (cur.lastrowid,)
        ).fetchone()
        conn.close()
        self._send_json(dict(row), 201)

    def update_iteration(self, iter_id):
        data = self._read_json()
        if data is None:
            return self._send_json({"error": "invalid json"}, 400)

        conn = get_db()
        existing = conn.execute(
            "SELECT * FROM iterations WHERE id = ?", (iter_id,)
        ).fetchone()
        if existing is None:
            conn.close()
            return self._send_json({"error": "not found"}, 404)

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
        params = list(fields.values()) + [iter_id]
        conn.execute(f"UPDATE iterations SET {sets} WHERE id = ?", params)
        conn.commit()
        row = conn.execute("SELECT * FROM iterations WHERE id = ?", (iter_id,)).fetchone()
        conn.close()
        self._send_json(dict(row))

    def delete_iteration(self, iter_id):
        conn = get_db()
        existing = conn.execute(
            "SELECT id FROM iterations WHERE id = ?", (iter_id,)
        ).fetchone()
        if existing is None:
            conn.close()
            return self._send_json({"error": "not found"}, 404)
        conn.execute(
            "UPDATE tasks SET iteration_id = NULL WHERE iteration_id = ?", (iter_id,)
        )
        conn.execute("DELETE FROM iterations WHERE id = ?", (iter_id,))
        conn.commit()
        conn.close()
        self._send_json({"ok": True})

    # ---- 静的ファイル配信 ----
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
    print(f"タスク管理アプリ起動: http://{HOST}:{PORT}")
    print(f"DB: {DB_PATH}")
    print("停止: Ctrl+C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n停止しました。")
        server.shutdown()


if __name__ == "__main__":
    main()
