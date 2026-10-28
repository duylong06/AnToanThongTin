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
import csv
import statistics
from pathlib import Path

class BenchmarkService:
    """Dịch vụ đo lường hiệu năng các thuật toán (Trương Hồng Uyên)"""
    
    def __init__(self, iterations: int = 100):
        self.iterations = iterations
        self.results = []

    def run_benchmark(self, algorithm: str, data_size: int = 1024) -> dict:
        """Mô phỏng khung đo lường tốc độ ký và xác minh (đơn vị: ms)"""
        # (Tầng signers.py của Long sẽ truyền thời gian thật vào đây sau, 
        # Uyên chuẩn bị sẵn khung tính toán thống kê chuẩn xác)
        sign_times = [1.5 for _ in range(self.iterations)]  # Dummy data
        verify_times = [0.5 for _ in range(self.iterations)]
        
        # Tính toán thống kê theo yêu cầu đồ án (Trung vị và Phân vị 95)
        median_sign = statistics.median(sign_times)
        p95_sign = statistics.quantiles(sign_times, n=100)[94] if self.iterations >= 100 else max(sign_times)
        
        median_verify = statistics.median(verify_times)
        p95_verify = statistics.quantiles(verify_times, n=100)[94] if self.iterations >= 100 else max(verify_times)
        
        record = {
            "algorithm": algorithm,
            "data_size_bytes": data_size,
            "iterations": self.iterations,
            "median_sign_ms": median_sign,
            "p95_sign_ms": p95_sign,
            "median_verify_ms": median_verify,
            "p95_verify_ms": p95_verify
        }
        self.results.append(record)
        return record

    def export_to_csv(self, file_path: str = "results/bench.csv") -> None:
        """Xuất kết quả đo lường ra tệp CSV"""
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        
        if not self.results:
            return
            
        keys = self.results[0].keys()
        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(self.results)