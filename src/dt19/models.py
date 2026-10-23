"""
Tác giả: Nguyễn Quỳnh Phiếu
Mô tả: Lớp miền cho hệ thống sigtool (KeyPair, Manifest, ReasonCode)
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Optional
from datetime import datetime, timezone


class ReasonCode(Enum):
    """Mã lý do phản ánh kết quả xác minh chữ ký"""
    SUCCESS = "SUCCESS"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    FILE_MODIFIED = "FILE_MODIFIED"
    FILE_MISSING = "FILE_MISSING"
    KEY_REVOKED = "KEY_REVOKED"
    KEY_NOT_TRUSTED = "KEY_NOT_TRUSTED"
    MANIFEST_TAMPERED = "MANIFEST_TAMPERED"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


@dataclass
class KeyPair:
    """Quản lý thông tin cặp khóa và trạng thái vòng đời"""
    key_id: str
    algorithm: str  # rsa-pss, ecdsa, ed25519
    public_key_pem: str
    owner: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "ACTIVE"  # ACTIVE, REVOKED
    revoked_at: Optional[str] = None


@dataclass
class Manifest:
    """Quản lý danh sách các tệp tin và giá trị băm SHA-256 tương ứng"""
    files: Dict[str, str]  # { "path/to/file": "sha256_hash" }
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    version: str = "1.0"

    def add_file(self, file_path: str, file_hash: str) -> None:
        self.files[file_path] = file_hash

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "created_at": self.created_at,
            "files": self.files
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Manifest':
        return cls(
            files=data.get("files", {}),
            created_at=data.get("created_at", ""),
            version=data.get("version", "1.0")
        )