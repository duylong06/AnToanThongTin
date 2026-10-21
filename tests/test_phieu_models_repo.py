"""
Tác giả: Nguyễn Quỳnh Phiếu
Mô tả: Kiểm thử Lớp miền (models.py), Tầng lưu trữ SQLite (repository.py) và Service Manifest
"""

import os
import json
import pytest
from dt19.models import KeyPair, Manifest, ReasonCode
from dt19.repository import Repository
from dt19.services import create_manifest


def test_reason_codes():
    assert ReasonCode.SUCCESS.value == "SUCCESS"
    assert ReasonCode.FILE_MODIFIED.value == "FILE_MODIFIED"


def test_manifest_operations():
    manifest = Manifest(files={"artifacts/demo.txt": "a665a45920422f9d417e4867efdc4fb8"})
    assert "artifacts/demo.txt" in manifest.files


def test_sqlite_repository(tmp_path):
    db_file = tmp_path / "test_sigtool.db"
    repo = Repository(db_path=str(db_file))
    
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
    with repo.get_connection() as conn:
        conn.executescript(schema_sql)

    key = KeyPair(
        key_id="key-phieu-01",
        algorithm="ed25519",
        public_key_pem="PUBLIC_KEY_DEMO_DATA",
        owner="Nguyễn Quỳnh Phiếu"
    )
    repo.save_key(key)
    saved_key = repo.get_key("key-phieu-01")
    assert saved_key is not None
    assert saved_key.owner == "Nguyễn Quỳnh Phiếu"


def test_create_manifest_service(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    sample_file = artifacts / "sample.txt"
    sample_file.write_text("Hello Sigtool 2026", encoding="utf-8")

    output_json = artifacts / "manifest.json"
    manifest = create_manifest(str(artifacts), str(output_json))

    assert "sample.txt" in manifest.files
    assert os.path.exists(str(output_json))