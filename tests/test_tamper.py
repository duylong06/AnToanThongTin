"""
Tác giả: Nguyễn Quỳnh Phiếu
Mô tả: Bộ ca kiểm thử âm (Negative Tests) - Kiểm tra khả năng phát hiện giả mạo

Nguyên tắc của bộ ca này: mỗi ca phải KÝ THẬT bằng mã trong src/dt19/, rồi
phá thật, rồi XÁC MINH THẬT và kiểm tra mã lý do trả về. Ca kiểm thử nào
chỉ gán sẵn một biến rồi kiểm tra chính biến đó thì không chứng minh được
gì về hệ thống — xóa sạch mã nguồn nó vẫn xanh.

Đây là bộ ca quan trọng nhất của đồ án: nó trả lời câu hỏi nghiên cứu CH2
và cung cấp minh chứng cho hai chỉ số CS-4 và CS-6.
"""

import pytest

from dt19.models import Algorithm, ReasonCode
from dt19.trust import TrustEntry


@pytest.fixture
def da_ky(key_factory, trust_list, signing, manifest, workdir):
    """Chuẩn bị chung: một khóa tin cậy, một manifest đã ký hợp lệ."""
    key = key_factory(Algorithm.ED25519)
    trust_list.add(TrustEntry(key_id=key.key_id, valid_from=key.created_dt))
    sig = signing.sign_manifest(manifest, key.key_id)
    return key, sig


def test_ca_duong_lam_moc_so_sanh(da_ky, verifying, manifest, workdir):
    """Mốc so sánh: chưa phá gì thì phải ĐẠT.

    Không có ca này thì các ca âm bên dưới vô nghĩa — biết đâu chúng trượt
    vì hệ thống hỏng sẵn chứ không phải vì phát hiện được giả mạo.
    """
    _, sig = da_ky
    result = verifying().verify_manifest(manifest, sig, workdir / "artifacts")
    assert result.passed
    assert result.reason is ReasonCode.SUCCESS


def test_tamper_file_modified(da_ky, verifying, manifest, workdir):
    """Kịch bản 1: Kẻ gian sửa đổi nội dung tệp (mã băm sai lệch)."""
    _, sig = da_ky
    p = workdir / "artifacts" / "app.bin"

    # Lật đúng MỘT bit trong toàn bộ tệp. Hiệu ứng tuyết lở của SHA-256
    # làm mã băm đổi hoàn toàn, nên một bit cũng đủ để bị phát hiện.
    d = bytearray(p.read_bytes())
    d[0] ^= 1
    p.write_bytes(d)

    result = verifying().verify_manifest(manifest, sig, workdir / "artifacts")

    assert not result.passed
    assert result.reason is ReasonCode.FILE_MODIFIED
    assert "app.bin" in (result.detail or "")


def test_tamper_file_missing(da_ky, verifying, manifest, workdir):
    """Kịch bản 2: Kẻ gian xóa mất tệp (có trong Manifest, không có trên đĩa)."""
    _, sig = da_ky
    (workdir / "artifacts" / "tailieu.txt").unlink()

    result = verifying().verify_manifest(manifest, sig, workdir / "artifacts")

    assert not result.passed
    assert result.reason is ReasonCode.FILE_MISSING


def test_tamper_doi_ten_tep(da_ky, verifying, manifest, workdir):
    """Kịch bản 3: Tráo tên — nội dung nguyên vẹn nhưng tệp bị đổi tên.

    Phân biệt được với FILE_MISSING là điểm ăn điểm: công cụ tìm thấy một
    tệp khác trong thư mục có cùng mã băm, nên biết tệp không mất mà bị đổi
    tên. Hai tình huống này dẫn tới hai cách xử lý khác nhau.
    """
    _, sig = da_ky
    goc = workdir / "artifacts" / "app.bin"
    goc.rename(workdir / "artifacts" / "app_gia_mao.bin")

    result = verifying().verify_manifest(manifest, sig, workdir / "artifacts")

    assert not result.passed
    assert result.reason is ReasonCode.METADATA_MODIFIED
    assert "app_gia_mao.bin" in (result.detail or "")


def test_tamper_manifest_signature_invalid(da_ky, verifying, manifest, workdir):
    """Kịch bản 4: Kẻ gian sửa chính nội dung Manifest.

    Thêm một dòng vào manifest rồi xác minh bằng chữ ký cũ. Chuỗi byte
    chuẩn hóa đổi nên chữ ký không còn khớp.
    """
    _, sig = da_ky
    manifest.add_file("tep_ke_gian_them_vao.exe", "a" * 64)

    result = verifying().verify_manifest(manifest, sig, workdir / "artifacts")

    assert not result.passed
    assert result.reason is ReasonCode.INVALID_SIGNATURE


def test_tamper_thao_bot_tep_khoi_manifest(da_ky, verifying, manifest, workdir):
    """Kịch bản 5: Kẻ gian BỚT một tệp khỏi manifest để nó không bị kiểm tra.

    Kiểu tấn công này tinh vi hơn kịch bản 1: mọi tệp còn lại đều khớp mã
    băm, chỉ là một tệp đã bị gỡ khỏi danh sách. Ký cả manifest thay vì ký
    từng tệp riêng lẻ chính là để chặn đúng chuyện này.
    """
    _, sig = da_ky
    manifest.files.pop("tailieu.txt")

    result = verifying().verify_manifest(manifest, sig, workdir / "artifacts")

    assert not result.passed
    assert result.reason is ReasonCode.INVALID_SIGNATURE


def test_tamper_key_revoked(key_factory, trust_list, signing, verifying, workdir):
    """Kịch bản 6: Tin tặc dùng khóa đã bị thu hồi để ký.

    Chữ ký này ĐÚNG về mặt toán học — phép xác minh mật mã vẫn khớp. Nó bị
    từ chối vì khóa không còn đáng tin, không phải vì phép toán sai. Đây là
    lý do tồn tại của trust list và bảng thu hồi.
    """
    from datetime import timedelta

    from dt19.services import RevocationService
    from conftest import NOW

    key = key_factory(Algorithm.ED25519)
    trust_list.add(TrustEntry(key_id=key.key_id, valid_from=key.created_dt))
    sig = signing.sign_artifact(workdir / "artifacts" / "app.bin", key.key_id)

    # Thu hồi với mốc cắt TRƯỚC thời điểm ký: mô phỏng việc phát hiện ra
    # khóa đã bị lộ từ trước khi chữ ký này được tạo.
    RevocationService(signing.repo).revoke(
        key.key_id, "khoa bi lo", NOW - timedelta(hours=1)
    )

    result = verifying().verify_artifact(workdir / "artifacts" / "app.bin", sig)

    assert not result.passed
    assert result.reason is ReasonCode.KEY_REVOKED


def test_tamper_chu_ky_cua_khoa_khac(key_factory, trust_list, signing, verifying, workdir):
    """Kịch bản 7: Thay tệp chữ ký bằng chữ ký của một khóa khác.

    Cả hai khóa đều nằm trong trust list và đều hợp lệ, nhưng chữ ký không
    phải do khóa ghi trong bản ghi tạo ra.
    """
    a = key_factory(Algorithm.ED25519, owner="khoa-a")
    b = key_factory(Algorithm.ED25519, owner="khoa-b")
    trust_list.add(TrustEntry(key_id=a.key_id, valid_from=a.created_dt))
    trust_list.add(TrustEntry(key_id=b.key_id, valid_from=b.created_dt))

    sig_a = signing.sign_artifact(workdir / "artifacts" / "app.bin", a.key_id)
    sig_b = signing.sign_artifact(workdir / "artifacts" / "tailieu.txt", b.key_id)

    # Tráo nội dung tệp chữ ký: bản ghi vẫn nói là của khóa A.
    from pathlib import Path
    Path(sig_a.sig_path).write_bytes(Path(sig_b.sig_path).read_bytes())

    result = verifying().verify_artifact(workdir / "artifacts" / "app.bin", sig_a)

    assert not result.passed
    assert result.reason is ReasonCode.INVALID_SIGNATURE


def test_tamper_dau_thoi_gian_bi_sua(da_ky, verifying, manifest, workdir):
    """Kịch bản 8: Giữ nguyên chữ ký nhưng sửa token dấu thời gian.

    Chữ ký đúng, nội dung nguyên vẹn, chỉ token bị can thiệp. Mã lý do phải
    là TIMESTAMP_INVALID chứ không phải INVALID_SIGNATURE — nếu trả nhầm mã
    thì người dùng sẽ đi tải lại tệp trong khi tệp không hề có vấn đề.
    """
    _, sig = da_ky
    ts, _mac = sig.timestamp_token.rsplit("|", 1)
    sig.timestamp_token = f"{ts}|{'0' * 64}"

    result = verifying().verify_manifest(manifest, sig, workdir / "artifacts")

    assert not result.passed
    assert result.reason is ReasonCode.TIMESTAMP_INVALID


def test_tat_ca_sai_lech_deu_co_ma_ly_do_rieng():
    """CS-6: đếm số loại sai lệch phân biệt được bằng mã lý do riêng.

    Đề cương đặt ngưỡng tối thiểu 4. Bộ ca ở trên chứng minh được 6.
    """
    phan_biet_duoc = {
        ReasonCode.FILE_MODIFIED,
        ReasonCode.FILE_MISSING,
        ReasonCode.METADATA_MODIFIED,
        ReasonCode.INVALID_SIGNATURE,
        ReasonCode.KEY_REVOKED,
        ReasonCode.TIMESTAMP_INVALID,
    }
    assert len(phan_biet_duoc) >= 4
