"""
Tác giả: Nguyễn Quỳnh Phiếu (tầng lưu trữ gốc) — Nguyễn Duy Long (phần bổ sung)
Mô tả: Tầng truy xuất dữ liệu SQLite cho hệ thống sigtool

GHI CHÚ VỀ PR NÀY (Long):
Giữ nguyên lớp Repository, cách mở kết nối và ba phương thức gốc. Phần thêm
vào là các cột và phương thức mà việc ký, thu hồi khóa bắt buộc phải có
(FR-17 đến FR-19), đều đánh dấu "Long bổ sung".
"""

import sqlite3
from datetime import datetime
from typing import List, Optional

from dt19.models import KeyPair, ReasonCode, Signature


class Repository:
    def __init__(self, db_path: str = "data/sigtool.db"):
        self.db_path = db_path
        self._memory_conn = None

        # Xử lý riêng cho bản test trong bộ nhớ: giữ 1 kết nối duy nhất để không mất bảng
        if self.db_path == ":memory:":
            self._memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._memory_conn.row_factory = sqlite3.Row

    def get_connection(self) -> sqlite3.Connection:
        # Tái sử dụng kết nối nếu là in-memory, ngược lại mở kết nối mới tới file
        if self.db_path == ":memory:":
            return self._memory_conn

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self, schema_path: str = "data/schema.sql") -> None:
        """Khởi tạo cơ sở dữ liệu từ file schema.sql"""
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = f.read()
        with self.get_connection() as conn:
            conn.executescript(schema)

    def save_key(self, key: KeyPair) -> None:
        """Lưu hoặc cập nhật thông tin cặp khóa vào database"""
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO keys
                    (key_id, algorithm, public_key_pem, owner, created_at, status,
                     revoked_at, private_key_path, expires_at, fingerprint)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    key.key_id, key.algorithm, key.public_key_pem, key.owner,
                    key.created_at, key.status, key.revoked_at,
                    # === Long bổ sung: ba cột mới ===
                    key.private_key_path, key.expires_at, key.fingerprint,
                )
            )

    def get_key(self, key_id: str) -> Optional[KeyPair]:
        """Lấy thông tin cặp khóa theo ID, trả về đối tượng KeyPair"""
        conn = self.get_connection()
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
                revoked_at=row["revoked_at"],
                # === Long bổ sung ===
                private_key_path=row["private_key_path"],
                expires_at=row["expires_at"],
                fingerprint=row["fingerprint"],
            )
        return None

    def log_verification(self, sig_id: str, status: str, reason_code: ReasonCode, verified_at: str, details: str = "") -> None:
        """Ghi nhật ký xác minh chỉ ghi thêm (Append-only)"""
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO verify_logs (sig_id, status, reason_code, verified_at, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (sig_id, status, reason_code.value, verified_at, details)
            )

    # ==================================================================
    # Long bổ sung — chữ ký và thu hồi khóa (FR-17, FR-18, FR-19)
    # ==================================================================

    def set_key_status(self, key_id: str, status: str) -> None:
        """Đổi trạng thái khóa, dùng khi thu hồi."""
        with self.get_connection() as conn:
            conn.execute(
                "UPDATE keys SET status = ? WHERE key_id = ?", (status, key_id)
            )

    def save_signature(self, sig: Signature) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO signatures
                    (signature_id, target_id, target_kind, key_id, algorithm,
                     sig_path, sig_size_bytes, signed_at, timestamp_token)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sig.signature_id, sig.target_id, sig.target_kind, sig.key_id,
                    sig.algorithm, sig.sig_path, sig.sig_size_bytes,
                    sig.signed_at.isoformat(), sig.timestamp_token,
                )
            )

    @staticmethod
    def _row_to_signature(row: sqlite3.Row) -> Signature:
        return Signature(
            signature_id=row["signature_id"],
            target_id=row["target_id"],
            target_kind=row["target_kind"],
            key_id=row["key_id"],
            algorithm=row["algorithm"],
            sig_path=row["sig_path"],
            sig_size_bytes=row["sig_size_bytes"],
            signed_at=datetime.fromisoformat(row["signed_at"]),
            timestamp_token=row["timestamp_token"],
        )

    def get_signature(self, signature_id: str) -> Optional[Signature]:
        conn = self.get_connection()
        row = conn.execute(
            "SELECT * FROM signatures WHERE signature_id = ?", (signature_id,)
        ).fetchone()
        return self._row_to_signature(row) if row else None

    def find_signatures_by_key(self, key_id: str) -> List[Signature]:
        """Mọi chữ ký tạo bằng một khóa. Đầu vào của bước đánh giá thiệt hại."""
        conn = self.get_connection()
        rows = conn.execute(
            "SELECT * FROM signatures WHERE key_id = ? ORDER BY signed_at", (key_id,)
        ).fetchall()
        return [self._row_to_signature(r) for r in rows]

    def save_revocation(
        self, key_id: str, reason: str, revoked_at: datetime, affected: int
    ) -> None:
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO revocations
                    (key_id, reason, revoked_at, affected_signatures)
                VALUES (?, ?, ?, ?)
                """,
                (key_id, reason, revoked_at.isoformat(), affected)
            )

    def get_revocation(self, key_id: str) -> Optional[datetime]:
        """Mốc cắt hiệu lực của khóa, hoặc None nếu khóa chưa bị thu hồi."""
        conn = self.get_connection()
        row = conn.execute(
            "SELECT revoked_at FROM revocations WHERE key_id = ?", (key_id,)
        ).fetchone()
        return datetime.fromisoformat(row["revoked_at"]) if row else None
