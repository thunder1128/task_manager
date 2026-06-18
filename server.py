#!/usr/bin/env python3
"""タスク管理WEBアプリ バックエンド(エントリポイント)。

Python標準ライブラリのみで動作する軽量HTTPサーバー。
データは tasks.db (SQLite) に永続化する。追加インストール不要。
  実行:  python3 server.py

構成:
  const.py  … 定数・設定値(他モジュールに依存しないリーフ)
  core.py   … DB・各種ヘルパー(HTTP非依存)
  routes.py … 認証・全APIエンドポイント・ルーティング(ApiRoutes ミックスイン)
  server.py … HTTPサーバ起動・低レベルなリクエスト/レスポンス処理・静的配信(このファイル)

ログイン認証 + プロジェクト単位のアクセス制御つき。API仕様は routes.py を参照。
"""

import json
import os
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from const import BASE_DIR, DB_PATH, HOST, PORT
from core import init_db
from routes import ApiRoutes


class Handler(ApiRoutes, BaseHTTPRequestHandler):
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

    # ---- Cookie 取得 ----
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
