#!/usr/bin/env python3
"""アプリ全体の定数・設定値を集約するモジュール(他モジュールに依存しないリーフ)。

環境変数で上書きできる設定値もここで解決する。
const.py ← core.py / routes.py / server.py から参照される。
"""

import os
from datetime import timedelta

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

# セッション
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
