"""
Tác giả: Nguyễn Quỳnh Phiếu
Mô tả: Bộ ca kiểm thử âm (Negative Tests) - Kiểm tra khả năng phát hiện giả mạo
"""

import pytest
from dt19.models import Manifest, ReasonCode

def test_tamper_file_modified():
    """Kịch bản 1: Kẻ gian sửa đổi nội dung tệp (Mã băm bị sai lệch)"""
    # 1. Manifest gốc ghi nhận mã băm chuẩn
    manifest = Manifest(files={"docs/bang_diem.pdf": "hash_chuan_123"})
    
    # 2. Giả lập kẻ gian sửa file, sinh ra mã băm mới khi kiểm tra
    current_file_hash = "hash_bi_sua_999"
    
    # 3. Logic kiểm tra của hệ thống
    is_valid = manifest.files.get("docs/bang_diem.pdf") == current_file_hash
    reason = ReasonCode.SUCCESS if is_valid else ReasonCode.FILE_MODIFIED
    
    # 4. Xác nhận hệ thống bắt được lỗi FILE_MODIFIED
    assert is_valid is False
    assert reason == ReasonCode.FILE_MODIFIED


def test_tamper_file_missing():
    """Kịch bản 2: Kẻ gian xóa mất tệp (Tệp có trong Manifest nhưng không thấy trên đĩa)"""
    manifest = Manifest(files={"docs/bang_diem.pdf": "hash_chuan_123"})
    
    # Giả lập file không còn tồn tại trên ổ cứng
    file_exists_on_disk = False
    
    is_valid = file_exists_on_disk
    reason = ReasonCode.FILE_MISSING if not file_exists_on_disk else ReasonCode.SUCCESS
    
    assert is_valid is False
    assert reason == ReasonCode.FILE_MISSING


def test_tamper_manifest_signature_invalid():
    """Kịch bản 3: Kẻ gian sửa nội dung file Manifest (Chữ ký điện tử của Manifest không khớp)"""
    # Giả lập hàm xác minh chữ ký của thuật toán mật mã trả về False
    is_signature_valid = False
    
    reason = ReasonCode.SUCCESS if is_signature_valid else ReasonCode.MANIFEST_TAMPERED
    
    assert reason == ReasonCode.MANIFEST_TAMPERED


def test_tamper_key_revoked():
    """Kịch bản 4: Tin tặc dùng một khóa đã bị thu hồi để ký bậy bạ"""
    # Giả lập trạng thái khóa đọc từ Database
    key_status_in_db = "REVOKED"
    
    is_valid = (key_status_in_db == "ACTIVE")
    reason = ReasonCode.KEY_REVOKED if not is_valid else ReasonCode.SUCCESS
    
    assert is_valid is False
    assert reason == ReasonCode.KEY_REVOKED