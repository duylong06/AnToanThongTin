"""
Tác giả: Trương Hồng Uyên
Mô tả: Kiểm thử dịch vụ đo lường hiệu năng và xuất CSV

Bộ ca này dùng số lần lặp nhỏ để chạy nhanh. Số liệu đưa vào báo cáo phải
chạy bằng lệnh thật với tối thiểu 100 lần lặp theo chỉ số CS-3:

    python -m dt19 bench --iterations 100 --size 1048576 --out results/bench.csv
"""

import csv

import pytest

from dt19.models import Algorithm
from dt19.services import BenchmarkService


@pytest.fixture
def bench(workdir):
    """Số lần lặp nhỏ cho kiểm thử; khóa sinh trong thư mục tạm."""
    return BenchmarkService(iterations=5, keys_dir=str(workdir / "keys"))


def test_benchmark_execution(bench):
    """Chạy đo thật và trả về đủ các trường thống kê."""
    result = bench.run_benchmark(algorithm="ed25519", data_size=1024)

    assert result["algorithm"] == "ed25519"
    assert result["iterations"] == 5
    assert "median_sign_ms" in result
    assert "p95_sign_ms" in result


def test_so_do_phai_la_so_that_khong_phai_hang_so(bench):
    """Chốt chặn quan trọng nhất của tệp này.

    Nếu ai đó thay vòng đo bằng dữ liệu giả kiểu [1.5, 1.5, ...] thì mọi
    lần đo sẽ bằng nhau và phương sai bằng 0. Ca này sẽ đỏ ngay.
    """
    bench.iterations = 20
    bench.run_benchmark(algorithm="ed25519", data_size=1024)

    gia_tri = [r["sign_ms"] for r in bench.raw]
    assert len(gia_tri) == 20
    assert len(set(gia_tri)) > 1, "mọi lần đo giống hệt nhau — đây là số giả"
    assert all(v > 0 for v in gia_tri), "thời gian đo phải lớn hơn 0"


def test_kich_thuoc_chu_ky_dung_voi_tung_thuat_toan(bench):
    """CS-2: Ed25519 phải cho chữ ký nhỏ hơn hẳn RSA-PSS.

    Ca này cũng không qua được bằng số giả, vì nó so kết quả giữa hai
    thuật toán khác nhau chứ không chỉ kiểm tra trường có tồn tại.
    """
    ed = bench.run_benchmark(algorithm=Algorithm.ED25519.value, data_size=1024)
    rsa = bench.run_benchmark(algorithm=Algorithm.RSA_PSS.value, data_size=1024)

    assert ed["signature_size_bytes"] == 64
    assert rsa["signature_size_bytes"] == 256
    assert ed["signature_size_bytes"] < rsa["signature_size_bytes"]


def test_rsa_ky_cham_hon_ed25519(bench):
    """Kết luận định tính phải tái lập được trên mọi máy.

    Con số tuyệt đối đổi theo máy, nhưng THỨ TỰ giữa các thuật toán thì
    không. RSA-PSS 2048 ký chậm hơn Ed25519 vài chục tới vài trăm lần.
    """
    ed = bench.run_benchmark(algorithm="ed25519", data_size=1024)
    rsa = bench.run_benchmark(algorithm="rsa-pss", data_size=1024)

    assert rsa["median_sign_ms"] > ed["median_sign_ms"]


def test_p95_khong_nho_hon_trung_vi(bench):
    """Kiểm tra tính đúng của phép thống kê: phân vị 95 luôn ≥ trung vị."""
    bench.iterations = 20
    r = bench.run_benchmark(algorithm="ed25519", data_size=1024)

    assert r["p95_sign_ms"] >= r["median_sign_ms"]
    assert r["p95_verify_ms"] >= r["median_verify_ms"]


def test_benchmark_csv_export(bench, workdir):
    """Xuất CSV tổng hợp và CSV dữ liệu thô, không để lại rác trên đĩa."""
    bench.run_benchmark(algorithm="rsa-pss", data_size=1024)

    csv_file = workdir / "results" / "bench.csv"
    bench.export_to_csv(str(csv_file))

    assert csv_file.exists()
    content = csv_file.read_text(encoding="utf-8")
    assert "algorithm,data_size_bytes,iterations" in content
    assert "rsa-pss" in content

    # Dữ liệu thô phải đi kèm, nếu không thì không ai kiểm chứng lại được
    # con số trung vị trong báo cáo (CS-3).
    raw_file = workdir / "results" / "bench_raw.csv"
    assert raw_file.exists()
    rows = list(csv.DictReader(raw_file.open(encoding="utf-8")))
    assert len(rows) == 5, "mỗi lần lặp phải có một dòng dữ liệu thô"
    assert {"sign_ms", "verify_ms", "signature_size_bytes"} <= set(rows[0])
