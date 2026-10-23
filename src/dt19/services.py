"""
Tác giả: Nguyễn Quỳnh Phiếu
Mô tả: Tầng Dịch vụ (Services) - Quản lý Nhật ký xác minh
"""

from datetime import datetime, timezone
from dt19.models import ReasonCode
from dt19.repository import Repository


class VerificationLogService:
    """Dịch vụ quản lý việc ghi nhật ký xác minh chữ ký (Append-only)"""
    
    def __init__(self, repository: Repository):
        self.repo = repository

    def log_result(self, sig_id: str, is_valid: bool, reason: ReasonCode, details: str = "") -> None:
        """
        Xử lý logic nghiệp vụ trước khi ghi log:
        - Tự động lấy thời gian hiện tại chuẩn UTC.
        - Chuyển đổi trạng thái is_valid (True/False) thành chuỗi SUCCESS/FAILED.
        - Gọi tầng lưu trữ (Repository) để ghi xuống Database.
        """
        status = "SUCCESS" if is_valid else "FAILED"
        verified_at = datetime.now(timezone.utc).isoformat()
        
        self.repo.log_verification(
            sig_id=sig_id,
            status=status,
            reason_code=reason,
            verified_at=verified_at,
            details=details
        )