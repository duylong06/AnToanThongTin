"""
Tác giả: Nguyễn Quỳnh Phiếu
Mô tả: Tầng truy xuất dữ liệu SQLite cho sigtool
"""

import sqlite3
from typing import Optional, List
from dt19.models import KeyPair, ReasonCode


class Repository:
    def __init__(self, db_path: str = "data/sigtool.db"):
        self.db_path = db_path

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self, schema_path: str = "data/schema.sql") -> None:
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = f.read()
        with self.get_connection() as conn:
            conn.executescript(schema)

    def save_key(self, key: KeyPair) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO keys (key_id, algorithm, public_key_pem, owner, created_at, status, revoked_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (key.key_id, key.algorithm, key.public_key_pem, key.owner, key.created_at, key.status, key.revoked_at)
            )

    def get_key(self, key_id: str) -> Optional[KeyPair]:
        with self.get_connection() as conn:
            cursor = conn.execute("SELECT * FROM keys WHERE key_id = ?", (key_id,))
            row = cursor.fetchone()
            if row:
                return KeyPair(
                    key_id=row["key_id"],
                    algorithm=row["algorithm"],
                    public_key_pem=row["public_key_pem"],
                    owner=row["owner"],
                    created_at=row["created_at"],
                    status=row["status"],
                    revoked_at=row["revoked_at"]
                )
            return None

    def log_verification(self, sig_id: str, status: str, reason_code: ReasonCode, verified_at: str, details: str = "") -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO verify_logs (sig_id, status, reason_code, verified_at, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (sig_id, status, reason_code.value, verified_at, details)
            )