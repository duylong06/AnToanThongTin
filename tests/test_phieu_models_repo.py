"""
Tác giả: Nguyễn Quỳnh Phiếu
Mô tả: Kiểm thử đơn vị cho Lớp miền (models.py) và Tầng lưu trữ (repository.py)
"""

import pytest
from dt19.models import ReasonCode, KeyPair, Manifest
from dt19.repository import Repository


def test_reason_codes():
    """Kiểm tra mã lý do (ReasonCode) ánh xạ chính xác"""
    assert ReasonCode.SUCCESS.value == "SUCCESS"
    assert ReasonCode.MANIFEST_TAMPERED.value == "MANIFEST_TAMPERED"


def test_manifest_operations():
    """Kiểm tra các thao tác trên Manifest (thêm file, chuyển đổi dict)"""
    manifest = Manifest(files={})
    manifest.add_file("docs/report.pdf", "a665a45920422f9d417e4867efdc4fb8")
    
    # Test to_dict
    data = manifest.to_dict()
    assert data["version"] == "1.0"
    assert "docs/report.pdf" in data["files"]
    
    # Test from_dict
    loaded_manifest = Manifest.from_dict(data)
    assert loaded_manifest.files["docs/report.pdf"] == "a665a45920422f9d417e4867efdc4fb8"


def test_sqlite_repository():
    """Kiểm tra tầng lưu trữ dùng SQLite in-memory (bộ nhớ tạm không tạo tệp rác)"""
    # Dùng :memory: để test chạy nhanh trên RAM
    repo = Repository(db_path=":memory:")
    repo.init_db(schema_path="data/schema.sql")

    # 1. Test lưu và lấy KeyPair
    new_key = KeyPair(
        key_id="test-key-01",
        algorithm="ed25519",
        public_key_pem="-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----",
        owner="Nguyễn Quỳnh Phiếu"
    )
    repo.save_key(new_key)

    fetched_key = repo.get_key("test-key-01")
    assert fetched_key is not None
    assert fetched_key.algorithm == "ed25519"
    assert fetched_key.status == "ACTIVE"

    # 2. Test ghi nhật ký xác minh (log_verification)
    repo.log_verification(
        sig_id="sig-999",
        status="FAILED",
        reason_code=ReasonCode.FILE_MODIFIED,
        verified_at="2026-10-23T08:00:00Z",
        details="Mã băm không khớp"
    )
    
    with repo.get_connection() as conn:
        cursor = conn.execute("SELECT * FROM verify_logs WHERE sig_id = 'sig-999'")
        log_entry = cursor.fetchone()
        assert log_entry is not None
        assert log_entry["reason_code"] == "FILE_MODIFIED"