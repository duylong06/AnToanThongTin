"""
Tác giả: Nguyễn Quỳnh Phiếu
Mô tả: Kiểm thử Lớp miền (models.py) và Tầng lưu trữ SQLite (repository.py)
"""

import os
import pytest
from dt19.models import KeyPair, Manifest, ReasonCode
from dt19.repository import Repository


def test_reason_codes():
    """Kiểm tra các mã lý do kết quả xác minh"""
    assert ReasonCode.SUCCESS.value == "SUCCESS"
    assert ReasonCode.FILE_MODIFIED.value == "FILE_MODIFIED"
    assert ReasonCode.KEY_REVOKED.value == "KEY_REVOKED"


def test_manifest_operations():
    """Kiểm tra khởi tạo và chuyển đổi Manifest"""
    manifest = Manifest(files={"artifacts/demo.txt": "a665a45920422f9d417e4867efdc4fb8"})
    assert "artifacts/demo.txt" in manifest.files
    
    data = manifest.to_dict()
    assert data["version"] == "1.0"
    assert data["files"]["artifacts/demo.txt"] == "a665a45920422f9d417e4867efdc4fb8"


def test_sqlite_repository(tmp_path):
    """Kiểm thử khởi tạo DB, lưu khóa và ghi nhật ký xác minh"""
    db_file = tmp_path / "test_sigtool.db"
    repo = Repository(db_path=str(db_file))
    
    # Định nghĩa trực tiếp Schema tạo bảng để đảm bảo test luôn chạy độc lập thành công
    schema_sql = """
    CREATE TABLE IF NOT EXISTS keys (
        key_id TEXT PRIMARY KEY,
        algorithm TEXT NOT NULL,
        public_key_pem TEXT NOT NULL,
        owner TEXT NOT NULL,
        created_at TEXT NOT NULL,
        status TEXT DEFAULT 'ACTIVE',
        revoked_at TEXT
    );

    CREATE TABLE IF NOT EXISTS verify_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sig_id TEXT NOT NULL,
        status TEXT NOT NULL,
        reason_code TEXT NOT NULL,
        verified_at TEXT NOT NULL,
        details TEXT
    );
    """
    
    # Khởi tạo bảng trong DB thử nghiệm
    with repo.get_connection() as conn:
        conn.executescript(schema_sql)

    # 1. Lưu cặp khóa
    key = KeyPair(
        key_id="key-phieu-01",
        algorithm="ed25519",
        public_key_pem="PUBLIC_KEY_DEMO_DATA",
        owner="Nguyễn Quỳnh Phiếu"
    )
    repo.save_key(key)

    # 2. Truy vấn khóa ra kiểm tra
    saved_key = repo.get_key("key-phieu-01")
    assert saved_key is not None
    assert saved_key.owner == "Nguyễn Quỳnh Phiếu"
    assert saved_key.status == "ACTIVE"

    # 3. Ghi nhật ký xác minh
    repo.log_verification(
        sig_id="sig-001",
        status="FAIL",
        reason_code=ReasonCode.FILE_MODIFIED,
        verified_at="2026-10-21T08:00:00",
        details="File artifacts/demo.txt bị sửa đổi"
    )