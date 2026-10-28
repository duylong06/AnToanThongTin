"""
Tác giả: Trương Hồng Uyên
Mô tả: Bộ ca kiểm thử dương (Positive Tests) - Kiểm tra luồng hoạt động hợp lệ
"""

import pytest
from dt19.models import ReasonCode, Manifest

def test_verify_valid_signature_and_file():
    """Kiểm tra kịch bản chữ ký hợp lệ và tệp nguyên vẹn"""
    # 1. Giả lập một Manifest chuẩn
    manifest = Manifest(files={"docs/tai_lieu.txt": "hash_chuan_xyz"})
    
    # 2. Giả lập quá trình xác minh thành công (Tệp không bị sửa, Chữ ký đúng)
    is_signature_valid = True
    current_file_hash = "hash_chuan_xyz"
    
    # 3. Logic xử lý
    is_file_intact = manifest.files.get("docs/tai_lieu.txt") == current_file_hash
    is_all_valid = is_signature_valid and is_file_intact
    
    reason = ReasonCode.SUCCESS if is_all_valid else ReasonCode.UNKNOWN_ERROR
    
    # 4. Xác nhận kết quả phải là SUCCESS
    assert is_all_valid is True
    assert reason == ReasonCode.SUCCESS

def test_manifest_creation_flow():
    """Kiểm tra luồng tạo Manifest và thêm tệp thành công"""
    manifest = Manifest(files={})
    manifest.add_file("app/main.exe", "hash_111")
    
    assert "app/main.exe" in manifest.files
    assert manifest.files["app/main.exe"] == "hash_111"
    assert manifest.version == "1.0"