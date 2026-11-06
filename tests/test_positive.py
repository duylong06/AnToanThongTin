"""
Tác giả: Trương Hồng Uyên
Mô tả: Bộ ca kiểm thử dương (Positive Tests) - Kiểm tra luồng hoạt động hợp lệ

Bộ ca này chạy trọn vòng ký rồi xác minh bằng mã thật, cho CẢ BA thuật toán.
Nó là mốc so sánh cho bộ ca âm trong test_tamper.py: nếu ca dương không đạt
thì mọi kết quả "trượt" ở bộ ca âm đều không nói lên điều gì.
"""

import pytest

from dt19.models import Algorithm, ReasonCode
from dt19.signers import SignerFactory
from dt19.trust import TrustEntry

BA_THUAT_TOAN = [Algorithm.ED25519, Algorithm.ECDSA_P256, Algorithm.RSA_PSS]


@pytest.mark.parametrize("alg", BA_THUAT_TOAN)
def test_ky_roi_xac_minh_artifact_dat(alg, key_factory, trust_list, signing, verifying, workdir):
    """Vòng ký → xác minh chạy thông trên cả ba thuật toán.

    Tham số hóa thay vì viết ba hàm giống nhau: thêm thuật toán thứ tư chỉ
    cần thêm một phần tử vào danh sách.
    """
    key = key_factory(alg)
    trust_list.add(TrustEntry(key_id=key.key_id, valid_from=key.created_dt))

    sig = signing.sign_artifact(workdir / "artifacts" / "app.bin", key.key_id)
    result = verifying().verify_artifact(workdir / "artifacts" / "app.bin", sig)

    assert result.passed
    assert result.reason is ReasonCode.SUCCESS
    assert sig.algorithm == alg.value


@pytest.mark.parametrize("alg", BA_THUAT_TOAN)
def test_ky_roi_xac_minh_manifest_dat(alg, key_factory, trust_list, signing, verifying, manifest, workdir):
    """Một chữ ký trên manifest bảo vệ được cả bộ artifact."""
    key = key_factory(alg)
    trust_list.add(TrustEntry(key_id=key.key_id, valid_from=key.created_dt))

    sig = signing.sign_manifest(manifest, key.key_id)
    result = verifying().verify_manifest(manifest, sig, workdir / "artifacts")

    assert result.passed
    assert result.reason is ReasonCode.SUCCESS
    assert len(manifest.files) == 2


def test_manifest_creation_flow(workdir):
    """Luồng tạo Manifest: băm tệp thật trên đĩa, không gán mã băm bằng tay."""
    from dt19.models import Manifest, sha256_file

    m = Manifest(files={})
    digest = m.add_path(workdir / "artifacts" / "app.bin")

    assert "app.bin" in m.files
    assert m.files["app.bin"] == digest
    assert digest == sha256_file(workdir / "artifacts" / "app.bin")
    assert len(digest) == 64, "SHA-256 ở dạng hex luôn 64 ký tự"
    assert m.version == "1.0"


def test_canonical_bytes_on_dinh(workdir):
    """Chuỗi byte chuẩn hóa phải ổn định bất kể thứ tự chèn vào.

    Nếu không ổn định thì hai máy cùng một manifest sẽ cho hai chữ ký khác
    nhau, và việc xác minh chéo giữa các máy sẽ trượt oan.
    """
    from dt19.models import Manifest

    a = Manifest(files={}, created_at="2026-10-01T00:00:00", manifest_id="m")
    a.add_file("z.bin", "a" * 64)
    a.add_file("a.bin", "b" * 64)

    b = Manifest(files={}, created_at="2026-10-01T00:00:00", manifest_id="m")
    b.add_file("a.bin", "b" * 64)   # chèn theo thứ tự ngược lại
    b.add_file("z.bin", "a" * 64)

    assert a.canonical_bytes() == b.canonical_bytes()


@pytest.mark.parametrize("alg", BA_THUAT_TOAN)
def test_kich_thuoc_chu_ky_dung_nhu_ly_thuyet(alg, key_factory, workdir):
    """CS-2: kích thước chữ ký khớp với lý thuyết của từng lược đồ.

    Ed25519 cố định 64 byte. ECDSA P-256 khoảng 70–72 byte vì mã hóa DER
    cắt bỏ byte 0 ở đầu số nguyên nên độ dài thay đổi chút ít. RSA-PSS bằng
    đúng kích thước khóa, tức 256 byte với khóa 2048 bit.
    """
    key = key_factory(alg)
    signer = SignerFactory.create(alg)
    data = (workdir / "artifacts" / "app.bin").read_bytes()
    sig = signer.sign(data, key.private_key_path)

    ky_vong = {
        Algorithm.ED25519: (64, 64),
        Algorithm.ECDSA_P256: (68, 72),
        Algorithm.RSA_PSS: (256, 256),
    }[alg]
    assert ky_vong[0] <= len(sig) <= ky_vong[1], f"{alg.value}: {len(sig)} byte"


def test_nhat_ky_xac_minh_chi_ghi_them(key_factory, trust_list, signing, verifying, workdir):
    """NFR-05: mỗi lần xác minh thêm đúng một dòng, không sửa dòng cũ."""
    import json

    key = key_factory(Algorithm.ED25519)
    trust_list.add(TrustEntry(key_id=key.key_id, valid_from=key.created_dt))
    sig = signing.sign_artifact(workdir / "artifacts" / "app.bin", key.key_id)

    service = verifying()
    for _ in range(3):
        service.verify_artifact(workdir / "artifacts" / "app.bin", sig)

    dong = (workdir / "results" / "verify_log.jsonl").read_text(
        encoding="utf-8"
    ).strip().splitlines()
    assert len(dong) == 3
    for d in dong:
        ban_ghi = json.loads(d)
        assert ban_ghi["result"] == "pass"
        assert ban_ghi["reason_code"] == "SUCCESS"
        assert ban_ghi["key_id"] == key.key_id
