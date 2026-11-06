"""Sinh toàn bộ minh chứng thực nghiệm cho báo cáo.

Tác giả: Trương Hồng Uyên và Nguyễn Duy Long

Chạy từ gốc kho mã:
    python scripts/sinh_minh_chung.py

Script này dựng lại từ đầu mọi thứ nộp kèm báo cáo:
  - artifacts mẫu (sinh có seed cố định nên tái lập được)
  - khóa thử nghiệm và trust list
  - chữ ký
  - results/verify_log.jsonl — nhật ký đủ sáu mã lý do khác nhau
  - results/bang_ma_ly_do.csv — bảng đối chiếu kịch bản và mã trả về

Benchmark chạy riêng vì tốn thời gian:
    python -m dt19 bench --iterations 100 --size 1048576 --out results/bench.csv
    python -m dt19 bench --iterations 100 --size 1024    --out results/bench_1kb.csv
"""

import csv
import json
import random
import shutil
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dt19.cli import main as cli  # noqa: E402

SEED = 19  # số nhóm, để người khác chạy lại ra đúng bộ dữ liệu


def buoc(tieu_de: str) -> None:
    print(f"\n=== {tieu_de}")


def sinh_artifacts() -> None:
    """Ba artifact mẫu, nội dung cố định theo seed nên tái lập được."""
    d = ROOT / "artifacts"
    d.mkdir(exist_ok=True)
    rng = random.Random(SEED)
    (d / "app.bin").write_bytes(bytes(rng.randrange(256) for _ in range(4096)))
    (d / "tailieu.txt").write_text(
        "Tai lieu huong dan su dung sigtool.\n"
        "De tai 19 - An toan thong tin (123033).\n"
        "Day la du lieu gia lap phuc vu do an.\n",
        encoding="utf-8",
    )
    (d / "cauhinh.json").write_text(
        json.dumps({"ten": "sigtool", "phien_ban": "0.1.0", "che_do": "thu_nghiem"},
                   indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print("  đã sinh 3 artifact mẫu")


def key_id() -> str:
    conn = sqlite3.connect(ROOT / "data" / "sigtool.db")
    try:
        return conn.execute("SELECT key_id FROM keys LIMIT 1").fetchone()[0]
    finally:
        conn.close()


def sig_id(target: str) -> str:
    conn = sqlite3.connect(ROOT / "data" / "sigtool.db")
    try:
        return conn.execute(
            "SELECT signature_id FROM signatures WHERE target_id = ? "
            "ORDER BY signed_at DESC LIMIT 1", (target,)
        ).fetchone()[0]
    finally:
        conn.close()


def doc_ma_cuoi() -> str:
    """Mã lý do của dòng cuối trong nhật ký xác minh."""
    dong = (ROOT / "results" / "verify_log.jsonl").read_text(
        encoding="utf-8").strip().splitlines()
    return json.loads(dong[-1])["reason_code"]


def main() -> int:
    import os
    os.chdir(ROOT)

    # Dọn sạch để chạy lại cho kết quả giống hệt.
    buoc("Dọn trạng thái cũ")
    for p in [ROOT / "data" / "sigtool.db", ROOT / "results" / "verify_log.jsonl"]:
        p.unlink(missing_ok=True)
    for p in [ROOT / "keys", ROOT / "signatures"]:
        if p.exists():
            for sub in p.iterdir():
                if sub.is_dir():
                    shutil.rmtree(sub)
                elif sub.name != ".gitkeep":
                    sub.unlink()
    print("  đã dọn")

    buoc("Sinh artifact mẫu")
    sinh_artifacts()

    buoc("Khởi tạo và sinh khóa")
    cli(["init"])
    cli(["keygen", "--alg", "ed25519", "--owner", "Nhom 19"])
    k = key_id()

    buoc("Lập manifest và ký")
    cli(["manifest", "--dir", "artifacts", "--out", "artifacts/manifest.json"])
    cli(["sign", "artifacts/manifest.json", "--key", k, "--manifest"])
    s = sig_id("manifest")

    app = ROOT / "artifacts" / "app.bin"
    goc = app.read_bytes()
    ket_qua = []

    def kich_ban(ten: str, mong_doi: str, pha, hoan_nguyen):
        pha()
        cli(["verify", "artifacts/manifest.json", "--sig", s, "--root", "artifacts"])
        thuc_te = doc_ma_cuoi()
        hoan_nguyen()
        dat = "ĐẠT" if thuc_te == mong_doi else "KHÔNG KHỚP"
        ket_qua.append({"kich_ban": ten, "ma_mong_doi": mong_doi,
                        "ma_thuc_te": thuc_te, "ket_luan": dat})
        print(f"  {ten:<34} mong đợi {mong_doi:<18} thực tế {thuc_te:<18} {dat}")

    buoc("Sáu kịch bản xác minh")
    kich_ban("1. Nguyên vẹn", "SUCCESS", lambda: None, lambda: None)

    def sua_byte():
        d = bytearray(goc); d[0] ^= 1; app.write_bytes(bytes(d))
    kich_ban("2. Sửa một bit trong app.bin", "FILE_MODIFIED",
             sua_byte, lambda: app.write_bytes(goc))

    doi = ROOT / "artifacts" / "app_gia_mao.bin"
    kich_ban("3. Đổi tên tệp", "METADATA_MODIFIED",
             lambda: app.rename(doi), lambda: doi.rename(app))

    # Chuyển tệp RA NGOÀI thư mục artifacts. Nếu chỉ đổi tên trong cùng thư
    # mục thì công cụ tìm thấy tệp cùng mã băm và báo METADATA_MODIFIED —
    # đúng hành vi, nhưng không phải kịch bản "mất tệp" mà ta muốn thử.
    tam = ROOT / "data" / "_tam_xoa_tep.bin"
    kich_ban("4. Xóa hẳn tệp", "FILE_MISSING",
             lambda: app.rename(tam), lambda: tam.rename(app))

    man = ROOT / "artifacts" / "manifest.json"
    man_goc = man.read_text(encoding="utf-8")

    def sua_manifest():
        d = json.loads(man_goc)
        d["files"]["tep_la.exe"] = "0" * 64
        man.write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")
    kich_ban("5. Sửa nội dung manifest", "INVALID_SIGNATURE",
             sua_manifest, lambda: man.write_text(man_goc, encoding="utf-8"))

    buoc("Thu hồi khóa và xác minh lại")
    cli(["revoke", "--key", k, "--reason", "khoa bi lo trong dien tap"])
    cli(["verify", "artifacts/manifest.json", "--sig", s, "--root", "artifacts"])
    thuc_te = doc_ma_cuoi()
    ket_qua.append({"kich_ban": "6. Khóa đã bị thu hồi", "ma_mong_doi": "KEY_REVOKED",
                    "ma_thuc_te": thuc_te,
                    "ket_luan": "ĐẠT" if thuc_te == "KEY_REVOKED" else "KHÔNG KHỚP"})
    print(f"  6. Khóa đã bị thu hồi{'':<14} mong đợi KEY_REVOKED        "
          f"thực tế {thuc_te:<18} {ket_qua[-1]['ket_luan']}")

    buoc("Ghi bảng đối chiếu")
    out = ROOT / "results" / "bang_ma_ly_do.csv"
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(ket_qua[0].keys()))
        w.writeheader()
        w.writerows(ket_qua)
    print(f"  đã ghi {out.relative_to(ROOT)}")

    so_dat = sum(1 for r in ket_qua if r["ket_luan"] == "ĐẠT")
    print(f"\nKết quả: {so_dat}/{len(ket_qua)} kịch bản trả đúng mã lý do mong đợi.")
    print("Nhật ký đầy đủ: results/verify_log.jsonl")
    return 0 if so_dat == len(ket_qua) else 1


if __name__ == "__main__":
    raise SystemExit(main())
