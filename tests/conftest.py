"""Fixture dùng chung.

Người phụ trách: Phiêu | Tuần: 3 — bản này do Long dựng để test_rotation.py
chạy được; Phiêu bổ sung thêm fixture cho test_tamper.py khi cần.

Nguyên tắc: mỗi ca kiểm thử bắt đầu từ trạng thái sạch, chạy trong thư mục
tạm riêng, dùng cơ sở dữ liệu trong bộ nhớ và ĐỒNG HỒ CỐ ĐỊNH. Đồng hồ cố
định là điều kiện để kết quả tái lập được: nếu lấy thời gian thật, ca kiểm
thử về hạn hiệu lực sẽ đổi kết quả theo ngày chạy.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from dt19.models import Algorithm, KeyPair
from dt19.repository import Repository
from dt19.services import SigningService, TimestampService, VerificationService
from dt19.signers import SignerFactory
from dt19.trust import KeyRotationService, TrustList

# Thời điểm tham chiếu cố định cho toàn bộ bộ kiểm thử.
NOW = datetime(2026, 10, 1, 9, 0, 0)

# Đường dẫn tuyệt đối tới gốc kho mã: ca kiểm thử có đổi thư mục làm việc
# thì vẫn tìm được data/schema.sql.
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    """Thư mục làm việc tạm, có sẵn hai artifact mẫu."""
    for sub in ("artifacts", "keys", "signatures", "results"):
        (tmp_path / sub).mkdir()

    # Một tệp nhị phân và một tệp văn bản: đủ để kiểm tra việc ký không phụ
    # thuộc kiểu nội dung.
    (tmp_path / "artifacts" / "app.bin").write_bytes(bytes(range(256)) * 8)
    (tmp_path / "artifacts" / "tailieu.txt").write_text(
        "Tai lieu mau cua De tai 19.\n", encoding="utf-8"
    )

    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def clock():
    """Đồng hồ đứng yên tại NOW."""
    return TimestampService(fixed_now=NOW)


@pytest.fixture
def repo():
    """Cơ sở dữ liệu trong bộ nhớ, dựng từ đúng lược đồ thật."""
    r = Repository(db_path=":memory:")
    r.init_db(schema_path=str(ROOT / "data" / "schema.sql"))
    return r


@pytest.fixture
def key_factory(repo, workdir):
    """Sinh khóa cho thuật toán bất kỳ và đăng ký vào kho.

    Đặt lại ``created_at`` và ``expires_at`` theo NOW thay vì theo thời gian
    thật. Nếu không, khóa sinh lúc chạy kiểm thử sẽ có created_at ở tương
    lai so với đồng hồ cố định, và mọi phép xác minh đều trượt oan.
    """

    def make(alg: Algorithm, owner: str = "nhom19") -> KeyPair:
        signer = SignerFactory.create(alg)
        key = signer.generate_key(keys_dir=workdir / "keys", owner=owner)
        key.created_at = (NOW - timedelta(days=1)).isoformat()
        key.expires_at = (NOW + timedelta(days=365)).isoformat()
        repo.save_key(key)
        return key

    return make


@pytest.fixture
def trust_list():
    """Trust list rỗng, phiên bản 1. Ca kiểm thử tự thêm mục cần thiết."""
    return TrustList(version=1, created_at=NOW, entries=[])


@pytest.fixture
def manifest(workdir):
    """Manifest thật, băm hai artifact mẫu trong workdir/artifacts."""
    from dt19.models import Manifest

    m = Manifest(files={}, manifest_id="manifest")
    for p in sorted((workdir / "artifacts").iterdir()):
        m.add_path(p)
    return m


@pytest.fixture
def cli_workdir(workdir):
    """Thư mục làm việc cho ca kiểm thử dòng lệnh.

    Dòng lệnh dùng đường dẫn tương đối (data/sigtool.db, data/schema.sql),
    nên phải chép lược đồ thật vào thư mục tạm rồi chạy `init`.
    """
    import shutil

    (workdir / "data").mkdir(exist_ok=True)
    shutil.copy(ROOT / "data" / "schema.sql", workdir / "data" / "schema.sql")
    return workdir


@pytest.fixture
def rotation(workdir):
    """Dịch vụ luân chuyển khóa, giai đoạn chồng lấn mặc định 14 ngày."""
    return KeyRotationService(keys_dir=workdir / "keys", overlap_days=14)


@pytest.fixture
def signing(repo, clock, workdir):
    return SigningService(repo, clock, sig_dir=workdir / "signatures")


@pytest.fixture
def verifying(repo, trust_list, clock, workdir):
    """Trả về một hàm dựng VerificationService, để ca kiểm thử truyền trust
    list khác khi cần."""

    def make(tl: TrustList | None = None) -> VerificationService:
        return VerificationService(
            repo,
            tl or trust_list,
            clock,
            log_path=workdir / "results" / "verify_log.jsonl",
        )

    return make
