"""
Tác giả: Trương Hồng Uyên
Mô tả: Ca kiểm thử cho Giao diện dòng lệnh (CLI)

Hai nhóm ca. Nhóm đầu kiểm tra việc phân tích tham số. Nhóm sau chạy TRỌN
lệnh thật trong thư mục tạm rồi kiểm tra mã thoát và tệp sinh ra — đây mới
là thứ chứng minh công cụ dùng được, vì phân tích tham số đúng mà lệnh
không làm gì thì vẫn vô dụng.

Quy ước mã thoát:
    0  thành công
    1  xác minh thất bại
    2  sai tham số hoặc không tìm thấy đối tượng
"""

import sqlite3

import pytest

from dt19.cli import create_parser, main

# ---------------------------------------------------------------------------
# Nhóm 1 — phân tích tham số
# ---------------------------------------------------------------------------


def test_cli_parser_creation():
    """Kiểm tra parser được tạo thành công"""
    parser = create_parser()
    assert parser is not None


def test_cli_parse_keygen():
    """Kiểm tra phân tích tham số lệnh sinh khóa"""
    parser = create_parser()
    args = parser.parse_args(["keygen"])
    assert args.command == "keygen"
    assert args.alg == "ed25519", "mặc định phải là thuật toán gọn nhất"


def test_cli_parse_sign():
    """Kiểm tra phân tích tham số lệnh ký tệp"""
    parser = create_parser()
    args = parser.parse_args(["sign", "docs/test.txt", "--key", "key-123"])
    assert args.command == "sign"
    assert args.file == "docs/test.txt"
    assert args.key == "key-123"


def test_cli_tu_choi_thuat_toan_la():
    """Thuật toán không hỗ trợ phải bị chặn ngay ở bước phân tích tham số."""
    parser = create_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["keygen", "--alg", "md5"])


def test_cli_khong_co_lenh_thi_in_huong_dan(capsys):
    """Gọi trần không tham số thì in hướng dẫn và thoát 0."""
    assert main([]) == 0
    assert "usage" in capsys.readouterr().out.lower()


# ---------------------------------------------------------------------------
# Nhóm 2 — chạy lệnh thật từ đầu đến cuối
# ---------------------------------------------------------------------------


def _key_id(workdir) -> str:
    conn = sqlite3.connect(workdir / "data" / "sigtool.db")
    return conn.execute("SELECT key_id FROM keys LIMIT 1").fetchone()[0]


def _sig_id(workdir) -> str:
    conn = sqlite3.connect(workdir / "data" / "sigtool.db")
    return conn.execute("SELECT signature_id FROM signatures LIMIT 1").fetchone()[0]


def test_init_tao_co_so_du_lieu(cli_workdir):
    assert main(["init"]) == 0
    assert (cli_workdir / "data" / "sigtool.db").exists()


def test_keygen_sinh_khoa_va_cong_bo_trust_list(cli_workdir):
    """Lệnh keygen phải sinh tệp khóa thật và trust list phiên bản 1."""
    main(["init"])
    assert main(["keygen", "--alg", "ed25519", "--owner", "nhom19"]) == 0

    key_id = _key_id(cli_workdir)
    assert (cli_workdir / "keys" / "ed25519" / f"{key_id}.key").exists()
    assert (cli_workdir / "keys" / "ed25519" / f"{key_id}.public.pem").exists()
    assert (cli_workdir / "keys" / "trust_list_v1.json").exists()


def test_vong_ky_va_xac_minh_qua_dong_lenh(cli_workdir, capsys):
    """Ký rồi xác minh qua dòng lệnh phải thoát 0 và in ĐẠT."""
    main(["init"])
    main(["keygen", "--alg", "ed25519"])
    key_id = _key_id(cli_workdir)

    assert main(["sign", "artifacts/app.bin", "--key", key_id]) == 0
    sig_id = _sig_id(cli_workdir)

    capsys.readouterr()
    assert main(["verify", "artifacts/app.bin", "--sig", sig_id]) == 0
    out = capsys.readouterr().out
    assert "ĐẠT" in out
    assert "SUCCESS" in out


def test_sua_tep_roi_xac_minh_thi_thoat_ma_1(cli_workdir, capsys):
    """Mã thoát 1 khi xác minh trượt, để script tự động bắt được."""
    main(["init"])
    main(["keygen", "--alg", "ed25519"])
    key_id = _key_id(cli_workdir)
    main(["sign", "artifacts/app.bin", "--key", key_id])
    sig_id = _sig_id(cli_workdir)

    p = cli_workdir / "artifacts" / "app.bin"
    d = bytearray(p.read_bytes())
    d[0] ^= 1
    p.write_bytes(d)

    capsys.readouterr()
    assert main(["verify", "artifacts/app.bin", "--sig", sig_id]) == 1
    out = capsys.readouterr().out
    assert "TRƯỢT" in out
    assert "INVALID_SIGNATURE" in out


def test_manifest_va_ky_manifest(cli_workdir):
    """Lập manifest rồi ký cả bộ bằng một chữ ký."""
    main(["init"])
    main(["keygen", "--alg", "ed25519"])
    key_id = _key_id(cli_workdir)

    assert main(["manifest", "--dir", "artifacts", "--out", "artifacts/manifest.json"]) == 0
    assert (cli_workdir / "artifacts" / "manifest.json").exists()

    assert main(["sign", "artifacts/manifest.json", "--key", key_id, "--manifest"]) == 0
    sig_id = _sig_id(cli_workdir)
    assert main(["verify", "artifacts/manifest.json", "--sig", sig_id,
                 "--root", "artifacts"]) == 0


def test_thu_hoi_roi_xac_minh_thi_bao_key_revoked(cli_workdir, capsys):
    """Sau khi thu hồi, chữ ký cũ phải bị từ chối với mã KEY_REVOKED."""
    main(["init"])
    main(["keygen", "--alg", "ed25519"])
    key_id = _key_id(cli_workdir)
    main(["sign", "artifacts/app.bin", "--key", key_id])
    sig_id = _sig_id(cli_workdir)

    assert main(["revoke", "--key", key_id, "--reason", "khoa bi lo"]) == 0

    capsys.readouterr()
    assert main(["verify", "artifacts/app.bin", "--sig", sig_id]) == 1
    assert "KEY_REVOKED" in capsys.readouterr().out


def test_affected_dem_dung_so_chu_ky(cli_workdir, capsys):
    """Lệnh affected liệt kê đúng chữ ký của khóa bị lộ (FR-18)."""
    main(["init"])
    main(["keygen", "--alg", "ed25519"])
    key_id = _key_id(cli_workdir)
    main(["sign", "artifacts/app.bin", "--key", key_id])
    main(["sign", "artifacts/tailieu.txt", "--key", key_id])

    capsys.readouterr()
    assert main(["affected", "--key", key_id]) == 0
    out = capsys.readouterr().out
    assert "2 chữ ký" in out
    assert "app.bin" in out and "tailieu.txt" in out


def test_thu_hoi_khong_ro_moc_lo_thi_chu_ky_cu_cung_bi_tu_choi(cli_workdir, capsys):
    """Ca hồi quy cho một lỗi logic đã từng mắc.

    Thu hồi mà không truyền --since nghĩa là KHÔNG BIẾT khóa lộ từ bao giờ.
    Khi đó lệnh `affected` coi mọi chữ ký là đáng ngờ, nên phần xác minh
    BẮT BUỘC phải nhất quán và cũng từ chối chúng. Bản đầu tiên lấy mốc cắt
    là thời điểm hiện tại, nên `affected` báo 2 chữ ký bị ảnh hưởng mà
    `verify` vẫn trả ĐẠT cho đúng hai chữ ký đó.
    """
    main(["init"])
    main(["keygen", "--alg", "ed25519"])
    key_id = _key_id(cli_workdir)
    main(["sign", "artifacts/app.bin", "--key", key_id])
    sig_id = _sig_id(cli_workdir)

    main(["revoke", "--key", key_id, "--reason", "khong ro moc lo"])

    capsys.readouterr()
    ma_thoat = main(["verify", "artifacts/app.bin", "--sig", sig_id])
    out = capsys.readouterr().out

    assert ma_thoat == 1, "chữ ký cũ phải bị từ chối khi không rõ mốc lộ"
    assert "KEY_REVOKED" in out


def test_verify_khong_co_chu_ky_thi_thoat_ma_2(cli_workdir, capsys):
    """Chữ ký không tồn tại là lỗi tham số, không phải lỗi xác minh."""
    main(["init"])
    assert main(["verify", "artifacts/app.bin", "--sig", "khong-ton-tai"]) == 2
    assert "Không tìm thấy chữ ký" in capsys.readouterr().out
