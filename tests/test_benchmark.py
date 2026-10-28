"""
Tác giả: Trương Hồng Uyên
Mô tả: Kiểm thử dịch vụ đo lường hiệu năng và xuất CSV
"""
import pytest
from dt19.services import BenchmarkService

def test_benchmark_execution():
    """Kiểm tra chạy benchmark và tính toán đúng số lần lặp (tối thiểu 100)"""
    bench = BenchmarkService(iterations=100)
    result = bench.run_benchmark(algorithm="ed25519", data_size=1024)
    
    assert result["algorithm"] == "ed25519"
    assert result["iterations"] == 100
    assert "median_sign_ms" in result
    assert "p95_sign_ms" in result

def test_benchmark_csv_export(tmp_path):
    """Kiểm tra xuất file CSV thành công mà không để lại rác trên đĩa"""
    bench = BenchmarkService(iterations=100)
    bench.run_benchmark(algorithm="rsa-pss")
    
    # Dùng tmp_path của pytest để tạo file tạm
    csv_file = tmp_path / "bench.csv"
    bench.export_to_csv(str(csv_file))
    
    assert csv_file.exists()
    content = csv_file.read_text(encoding="utf-8")
    
    # Kiểm tra CSV có chứa header và dữ liệu không
    assert "algorithm,data_size_bytes,iterations" in content
    assert "rsa-pss" in content