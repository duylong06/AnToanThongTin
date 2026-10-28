"""Luân chuyển khóa, giai đoạn chồng lấn và thu hồi.

Người phụ trách: Long | Tuần: 5

Phần này kiểm chứng vòng đời khóa — nội dung mục 4.8 của bài giảng và là
một trong những yêu cầu thực nghiệm của đề tài (CH3 trong đề cương).

Các ca theo kế hoạch kiểm thử:
- TC-09 Trong giai đoạn chồng lấn     → vẫn OK
- TC-10 Sau giai đoạn chồng lấn       → KEY_EXPIRED
- TC-11 Chữ ký sau mốc thu hồi        → KEY_REVOKED
- TC-12 Đếm đúng số artifact bị ảnh hưởng

Bốn ca cuối là phần Long bổ sung sau khi viết docs/05 và docs/06; cần đồng
bộ số hiệu với docs/04 của Uyên trước khi nộp.

Các ca ở đây cố ý chỉ ký ARTIFACT chứ không ký manifest, để phần kiểm thử
vòng đời khóa chạy độc lập với lớp Manifest của Phiêu.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from conftest import NOW
from dt19.models import Algorithm, ReasonCode
from dt19.services import (
    RevocationService,
    SigningService,
    TimestampService,
    VerificationService,
)
from dt19.trust import TrustEntry


# ---------------------------------------------------------------------------
# TC-09 đến TC-12 — theo kế hoạch kiểm thử
# ---------------------------------------------------------------------------


def test_tc09_trong_giai_doan_chong_lan_khoa_cu_van_duoc_tin(
    repo, key_factory, rotation, signing, verifying, workdir
):
    """TC-09 — chữ ký bằng khóa cũ vẫn xác minh được trong 14 ngày chồng lấn.

    Đây là lý do tồn tại của giai đoạn chồng lấn: luân chuyển khóa không
    được phép làm hỏng những chữ ký đã tạo hợp lệ trước đó.
    """
    cu = key_factory(Algorithm.ED25519, owner="khoa-cu")
    moi = key_factory(Algorithm.ED25519, owner="khoa-moi")

    rotation.publish_initial(cu.key_id, NOW)
    sig = signing.sign_artifact(workdir / "artifacts" / "app.bin", cu.key_id)
    tl = rotation.rotate(cu.key_id, moi.key_id, NOW)

    assert tl.version == 2
    assert tl.is_trusted(cu.key_id, NOW + timedelta(days=7)), "khóa cũ phải còn được tin"
    assert tl.is_trusted(moi.key_id, NOW), "khóa mới có hiệu lực ngay"

    result = verifying(tl).verify_artifact(workdir / "artifacts" / "app.bin", sig)
    assert result.passed
    assert result.reason is ReasonCode.SUCCESS


def test_tc10_sau_giai_doan_chong_lan_khoa_cu_het_hieu_luc(
    repo, key_factory, rotation, verifying, workdir
):
    """TC-10 — quá 14 ngày, chữ ký bằng khóa cũ bị từ chối. Kỳ vọng KEY_EXPIRED.

    Mã lý do phải là KEY_EXPIRED chứ không phải KEY_UNKNOWN: khóa vẫn nằm
    trong trust list, chỉ là đã ngoài khoảng hiệu lực.
    """
    cu = key_factory(Algorithm.ED25519)
    moi = key_factory(Algorithm.ED25519)

    rotation.publish_initial(cu.key_id, NOW)
    tl = rotation.rotate(cu.key_id, moi.key_id, NOW)

    # Ký ở thời điểm đã quá giai đoạn chồng lấn.
    muon = NOW + timedelta(days=20)
    signing_muon = SigningService(
        repo, TimestampService(fixed_now=muon), sig_dir=workdir / "signatures"
    )
    sig = signing_muon.sign_artifact(workdir / "artifacts" / "app.bin", cu.key_id)

    service = VerificationService(
        repo,
        tl,
        TimestampService(fixed_now=muon),
        log_path=workdir / "results" / "verify_log.jsonl",
    )
    result = service.verify_artifact(workdir / "artifacts" / "app.bin", sig)

    assert not result.passed
    assert result.reason is ReasonCode.KEY_EXPIRED


def test_tc11_khoa_bi_thu_hoi_thi_chu_ky_sau_moc_do_bi_tu_choi(
    repo, key_factory, trust_list, signing, verifying, workdir
):
    """TC-11 — chữ ký tạo sau thời điểm thu hồi. Kỳ vọng KEY_REVOKED."""
    key = key_factory(Algorithm.ED25519)
    trust_list.add(TrustEntry(key_id=key.key_id, valid_from=key.created_at))

    sig = signing.sign_artifact(workdir / "artifacts" / "app.bin", key.key_id)

    # Mốc thu hồi đặt TRƯỚC thời điểm ký một giờ, mô phỏng tình huống phát
    # hiện ra rằng khóa đã bị lộ từ trước khi chữ ký này được tạo.
    RevocationService(repo).revoke(key.key_id, "khoa bi lo", NOW - timedelta(hours=1))

    result = verifying().verify_artifact(workdir / "artifacts" / "app.bin", sig)

    assert not result.passed
    assert result.reason is ReasonCode.KEY_REVOKED


def test_tc12_liet_ke_dung_so_artifact_bi_anh_huong(
    repo, key_factory, signing, workdir
):
    """TC-12 — đếm đúng số chữ ký của khóa bị lộ, đầu vào của runbook (FR-18).

    Chỉ đếm chữ ký của ĐÚNG khóa bị lộ. Chữ ký của khóa khác không bị ảnh
    hưởng, và nếu đếm lẫn thì đội vận hành sẽ ký lại thừa hàng loạt artifact.
    """
    key = key_factory(Algorithm.ED25519)
    khac = key_factory(Algorithm.ECDSA_P256)

    signing.sign_artifact(workdir / "artifacts" / "app.bin", key.key_id)
    signing.sign_artifact(workdir / "artifacts" / "tailieu.txt", key.key_id)
    signing.sign_artifact(workdir / "artifacts" / "app.bin", khac.key_id)

    service = RevocationService(repo)
    assert len(service.list_affected(key.key_id)) == 2
    assert service.revoke(key.key_id, "khoa bi lo", NOW) == 2
    assert repo.get_key(key.key_id).status == "REVOKED"


# ---------------------------------------------------------------------------
# Các ca Long bổ sung — đồng bộ số hiệu với docs/04 trước khi nộp
# ---------------------------------------------------------------------------


def test_khoa_la_khong_trong_trust_list_tra_ve_key_unknown(
    repo, key_factory, trust_list, signing, verifying, workdir
):
    """Khóa chưa bao giờ được tin phải trả KEY_UNKNOWN, không phải KEY_EXPIRED.

    Hai mã lý do dẫn tới hai hành động khác nhau: KEY_EXPIRED thì đi cập
    nhật trust list, còn KEY_UNKNOWN thì phải đặt câu hỏi ai đã ký thứ này.
    """
    key = key_factory(Algorithm.ED25519)
    # Cố ý KHÔNG thêm khóa vào trust_list.
    sig = signing.sign_artifact(workdir / "artifacts" / "app.bin", key.key_id)

    result = verifying().verify_artifact(workdir / "artifacts" / "app.bin", sig)

    assert not result.passed
    assert result.reason is ReasonCode.KEY_NOT_TRUSTED


def test_thu_hoi_khong_biet_moc_lo_thi_coi_moi_chu_ky_la_dang_ngo(
    repo, key_factory, signing, workdir
):
    """Bỏ trống suspected_since nghĩa là KHÔNG BIẾT, phải giả định xấu nhất.

    Trả về 0 trong trường hợp này là sai nguy hiểm: báo cáo sẽ nói không có
    artifact nào bị ảnh hưởng, trong khi thực tế là chưa ai biết.
    """
    key = key_factory(Algorithm.ED25519)
    signing.sign_artifact(workdir / "artifacts" / "app.bin", key.key_id)
    signing.sign_artifact(workdir / "artifacts" / "tailieu.txt", key.key_id)

    service = RevocationService(repo)

    # Không truyền suspected_since: mọi chữ ký đều đáng ngờ.
    assert service.revoke(key.key_id, "khong ro moc lo", NOW) == 2

    # Có mốc nghi ngờ nằm sau mọi chữ ký: không chữ ký nào bị ảnh hưởng.
    sau = NOW + timedelta(days=1)
    assert len(service.list_affected(key.key_id, since=sau)) == 0


def test_ed25519_ky_hai_lan_cho_chu_ky_giong_het_nhau(key_factory, workdir):
    """Nonce tất định: Ed25519 ký cùng dữ liệu hai lần cho chữ ký trùng khớp.

    Bằng chứng trực tiếp cho k = H(prefix ‖ M) trong RFC 8032. Không cần
    nguồn ngẫu nhiên lúc ký, nên bộ sinh số ngẫu nhiên kém không làm lộ khóa.
    """
    from dt19.signers import SignerFactory

    key = key_factory(Algorithm.ED25519)
    signer = SignerFactory.create(Algorithm.ED25519)
    data = (workdir / "artifacts" / "app.bin").read_bytes()

    a = signer.sign(data, key.private_key_path)
    b = signer.sign(data, key.private_key_path)

    assert a == b
    assert len(a) == 64, "chữ ký Ed25519 luôn 64 byte"


@pytest.mark.parametrize("alg", [Algorithm.ECDSA_P256, Algorithm.RSA_PSS])
def test_ecdsa_va_rsa_pss_ky_hai_lan_cho_chu_ky_khac_nhau(alg, key_factory, workdir):
    """Nonce và muối ngẫu nhiên: hai lần ký cho hai chữ ký khác nhau.

    Đối chiếu với ca trên để thấy khác biệt thiết kế giữa ba thuật toán.
    Với ECDSA, sự ngẫu nhiên này là bắt buộc: lặp lại nonce k cho hai thông
    điệp khác nhau làm lộ toàn bộ khóa riêng.
    """
    from dt19.signers import SignerFactory

    key = key_factory(alg)
    signer = SignerFactory.create(alg)
    data = (workdir / "artifacts" / "app.bin").read_bytes()

    a = signer.sign(data, key.private_key_path)
    b = signer.sign(data, key.private_key_path)

    assert a != b
    # Cả hai đều phải xác minh đúng, dù khác nhau từng byte.
    assert signer.verify(data, a, key.public_key_pem)
    assert signer.verify(data, b, key.public_key_pem)
