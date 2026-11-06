"""
Tác giả: Trương Hồng Uyên
Mô tả: Giao diện dòng lệnh (CLI) cho hệ thống sigtool

Tầng này KHÔNG chứa logic nghiệp vụ. Nhiệm vụ của nó đúng ba việc: phân
tích tham số, gọi tầng dịch vụ, in kết quả và trả mã thoát. Mọi quyết định
về mật mã, tin cậy hay thu hồi đều nằm ở services.py và trust.py.

Mã thoát, để script khác dùng được:
    0  thành công
    1  xác minh thất bại (đây là kết quả hợp lệ, không phải lỗi chương trình)
    2  sai tham số hoặc không tìm thấy đối tượng
"""

import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path

from dt19.models import Algorithm, Manifest, ReasonCode, MESSAGES_VI
from dt19.repository import Repository
from dt19.services import (
    BenchmarkService,
    RevocationService,
    SigningService,
    TimestampService,
    VerificationService,
)
from dt19.signers import SignerFactory
from dt19.trust import KeyRotationService, TrustEntry, TrustList

DB_PATH = "data/sigtool.db"
KEYS_DIR = "keys"
SIG_DIR = "signatures"
SCHEMA = "data/schema.sql"

EXIT_OK = 0
EXIT_VERIFY_FAILED = 1
EXIT_USAGE = 2


# ---------------------------------------------------------------------------
# Tiện ích dùng chung
# ---------------------------------------------------------------------------

def _repo() -> Repository:
    repo = Repository(db_path=DB_PATH)
    return repo


def _trust_list() -> TrustList:
    """Trust list phiên bản cao nhất trong keys/. Chưa có thì trả bản rỗng."""
    tl = TrustList.latest_in(KEYS_DIR)
    return tl or TrustList(version=0, created_at=datetime.now(), entries=[])


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        print(f"Thời điểm không hợp lệ: {value}. Định dạng: 2026-10-15T08:00")
        raise SystemExit(EXIT_USAGE)


def _print_result(result, target: str) -> int:
    """In kết quả xác minh kèm thông điệp tiếng Việt, trả mã thoát."""
    nhan = "[ĐẠT]" if result.passed else "[TRƯỢT]"
    print(f"{nhan} {target}")
    print(f"       mã lý do : {result.reason.value}")
    print(f"       ý nghĩa  : {MESSAGES_VI.get(result.reason, '')}")
    if result.detail:
        print(f"       chi tiết : {result.detail}")
    print(f"       thời gian: {result.duration_ms:.3f} ms")
    return EXIT_OK if result.passed else EXIT_VERIFY_FAILED


# ---------------------------------------------------------------------------
# Các lệnh
# ---------------------------------------------------------------------------

def cmd_init(args) -> int:
    """Dựng cơ sở dữ liệu và các thư mục làm việc."""
    for d in ("data", KEYS_DIR, SIG_DIR, "artifacts", "results"):
        Path(d).mkdir(parents=True, exist_ok=True)
    _repo().init_db(schema_path=SCHEMA)
    print(f"Đã khởi tạo cơ sở dữ liệu tại {DB_PATH}")
    return EXIT_OK


def cmd_keygen(args) -> int:
    """Sinh cặp khóa mới, đăng ký vào kho và công bố trust list nếu chưa có."""
    repo = _repo()
    signer = SignerFactory.create(Algorithm(args.alg))
    key = signer.generate_key(keys_dir=KEYS_DIR, owner=args.owner)
    repo.save_key(key)

    print(f"Đã sinh khóa {key.key_id}")
    print(f"  thuật toán   : {key.algorithm}")
    print(f"  chủ sở hữu   : {key.owner}")
    print(f"  dấu vân tay  : {key.fingerprint}")
    print(f"  khóa riêng   : {key.private_key_path}  (KHÔNG commit tệp này)")
    print(f"  hết hạn      : {key.expires_at}")

    # Khóa đầu tiên thì tự công bố trust list phiên bản 1, để người dùng
    # chạy thử được ngay mà không phải nhớ thêm một lệnh nữa.
    if TrustList.latest_in(KEYS_DIR) is None:
        rotation = KeyRotationService(keys_dir=KEYS_DIR)
        tl = rotation.publish_initial(key.key_id, key.created_dt or datetime.now())
        print(f"  trust list   : đã công bố phiên bản {tl.version}")
    return EXIT_OK


def cmd_keys(args) -> int:
    """Liệt kê khóa đang có trong kho."""
    keys = _repo().list_keys()
    if not keys:
        print("Chưa có khóa nào. Chạy: python -m dt19 keygen --alg ed25519")
        return EXIT_OK
    print(f"{'key_id':<18} {'thuật toán':<12} {'trạng thái':<10} chủ sở hữu")
    for k in keys:
        print(f"{k.key_id:<18} {k.algorithm:<12} {k.status:<10} {k.owner}")
    return EXIT_OK


def cmd_manifest(args) -> int:
    """Lập manifest cho toàn bộ tệp trong một thư mục."""
    src = Path(args.dir)
    if not src.is_dir():
        print(f"Không tìm thấy thư mục {src}")
        return EXIT_USAGE

    m = Manifest(files={}, manifest_id=args.name)
    # Bỏ qua chính tệp manifest và các tệp ẩn như .gitkeep: chúng không phải
    # artifact được phát hành, đưa vào chỉ làm nhiễu bộ minh chứng.
    files = sorted(
        p for p in src.iterdir()
        if p.is_file() and p.name != Path(args.out).name and not p.name.startswith(".")
    )
    for p in files:
        m.add_path(p)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(
        __import__("json").dumps(m.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"Đã lập manifest {args.out} gồm {len(m.files)} tệp:")
    for name, digest in sorted(m.files.items()):
        print(f"  {name:<24} {digest[:16]}…")
    return EXIT_OK


def cmd_sign(args) -> int:
    """Ký một artifact, hoặc ký manifest khi có cờ --manifest."""
    repo = _repo()
    service = SigningService(repo, sig_dir=SIG_DIR)
    target = Path(args.file)
    if not target.exists():
        print(f"Không tìm thấy tệp {target}")
        return EXIT_USAGE

    try:
        if args.manifest:
            data = __import__("json").loads(target.read_text(encoding="utf-8"))
            sig = service.sign_manifest(Manifest.from_dict(data), args.key)
        else:
            sig = service.sign_artifact(target, args.key)
    except ValueError as e:
        print(f"Lỗi: {e}")
        return EXIT_USAGE

    print(f"Đã ký {target}")
    print(f"  signature_id : {sig.signature_id}")
    print(f"  thuật toán   : {sig.algorithm}")
    print(f"  kích thước   : {sig.sig_size_bytes} byte")
    print(f"  tệp chữ ký   : {sig.sig_path}")
    print(f"  ký lúc       : {sig.signed_at.isoformat(timespec='seconds')}")
    return EXIT_OK


def cmd_verify(args) -> int:
    """Xác minh một artifact hoặc một manifest."""
    repo = _repo()
    sig = repo.get_signature(args.sig)
    if sig is None:
        print(f"Không tìm thấy chữ ký {args.sig}")
        return EXIT_USAGE

    service = VerificationService(repo, _trust_list(), verifier=args.verifier)
    target = Path(args.file)
    if sig.target_kind == "manifest":
        data = __import__("json").loads(target.read_text(encoding="utf-8"))
        result = service.verify_manifest(
            Manifest.from_dict(data), sig, args.root or target.parent
        )
    else:
        result = service.verify_artifact(target, sig)
    return _print_result(result, str(target))


def cmd_rotate(args) -> int:
    """Luân chuyển khóa, khóa cũ còn hiệu lực hết giai đoạn chồng lấn."""
    rotation = KeyRotationService(keys_dir=KEYS_DIR, overlap_days=args.overlap_days)
    tl = rotation.rotate(args.old, args.new, datetime.now())
    print(f"Đã công bố trust list phiên bản {tl.version}")
    print(f"  khóa cũ {args.old} còn hiệu lực thêm {args.overlap_days} ngày")
    print(f"  khóa mới {args.new} có hiệu lực ngay")
    for e in sorted(tl.entries, key=lambda x: x.key_id):
        den = e.valid_to.strftime("%d/%m/%Y") if e.valid_to else "không hạn"
        print(f"  {e.key_id}  từ {e.valid_from:%d/%m/%Y}  đến {den}")
    return EXIT_OK


def cmd_revoke(args) -> int:
    """Thu hồi khóa và cắt hiệu lực trong trust list."""
    repo = _repo()
    now = datetime.now()
    suspected = _parse_time(args.since)

    # Mốc cắt hiệu lực. Biết khóa lộ từ bao giờ thì cắt tại đó.
    #
    # KHÔNG biết thì phải cắt từ lúc SINH KHÓA, không phải từ bây giờ. Cắt
    # từ bây giờ nghĩa là ngầm khẳng định mọi chữ ký cũ vẫn đáng tin, trong
    # khi sự thật là không ai biết. Khi đó phần liệt kê sẽ báo "3 chữ ký bị
    # ảnh hưởng" còn phần xác minh lại trả ĐẠT cho đúng ba chữ ký ấy — hai
    # câu trả lời mâu thuẫn nhau cho cùng một câu hỏi.
    key = repo.get_key(args.key)
    if key is None:
        print(f"Không tìm thấy khóa {args.key}")
        return EXIT_USAGE
    cut = suspected or key.created_dt or now

    affected = RevocationService(repo).revoke(
        args.key, args.reason, cut, suspected_since=suspected
    )
    KeyRotationService(keys_dir=KEYS_DIR).revoke_in_trust_list(args.key, cut, now)

    print(f"Đã thu hồi khóa {args.key}")
    print(f"  lý do              : {args.reason}")
    print(f"  cắt hiệu lực từ    : {cut.isoformat(timespec='seconds')}")
    if suspected is None:
        print("  CẢNH BÁO: không rõ khóa lộ từ bao giờ, nên COI MỌI chữ ký")
        print("            của khóa này là đáng ngờ. Xem docs/06 bước 2.")
    print(f"  số chữ ký ảnh hưởng: {affected}")
    return EXIT_OK


def cmd_affected(args) -> int:
    """Liệt kê chữ ký đã tạo bằng một khóa."""
    repo = _repo()
    sigs = RevocationService(repo).list_affected(args.key, _parse_time(args.since))
    if not sigs:
        print(f"Không có chữ ký nào của khóa {args.key} trong phạm vi đã chọn.")
        return EXIT_OK
    print(f"{len(sigs)} chữ ký của khóa {args.key}:")
    for s in sigs:
        print(f"  {s.signed_at:%d/%m/%Y %H:%M}  {s.target_kind:<9} {s.target_id}")
    return EXIT_OK


def cmd_resign(args) -> int:
    """Ký lại bằng khóa mới toàn bộ artifact đã ký bằng khóa cũ."""
    repo = _repo()
    sigs = RevocationService(repo).list_affected(args.old, _parse_time(args.since))
    artifacts = [s for s in sigs if s.target_kind == "artifact"]
    if not artifacts:
        print("Không có artifact nào cần ký lại.")
        return EXIT_OK

    service = SigningService(repo, sig_dir=SIG_DIR)
    done, missing = 0, []
    for s in artifacts:
        path = Path(args.dir) / s.target_id
        if not path.exists():
            missing.append(s.target_id)
            continue
        new_sig = service.sign_artifact(path, args.new)
        print(f"  {s.target_id:<24} -> {new_sig.signature_id}")
        done += 1

    print(f"Đã ký lại {done}/{len(artifacts)} artifact bằng khóa {args.new}")
    if missing:
        print(f"  không tìm thấy trên đĩa: {', '.join(missing)}")
    return EXIT_OK


def cmd_bench(args) -> int:
    """Đo tốc độ ký và xác minh của cả ba thuật toán."""
    bench = BenchmarkService(iterations=args.iterations)
    print(
        f"Đang đo {args.iterations} lần mỗi thuật toán, "
        f"dữ liệu {args.size} byte…"
    )
    for alg in SignerFactory.all_algorithms():
        r = bench.run_benchmark(alg.value, data_size=args.size)
        print(
            f"  {alg.value:<10} ký {r['median_sign_ms']:7.3f} ms  "
            f"xác minh {r['median_verify_ms']:7.3f} ms  "
            f"chữ ký {r['signature_size_bytes']:4d} byte"
        )
    bench.export_to_csv(args.out)
    print(f"Đã ghi dữ liệu thô vào {args.out}")
    print("So sánh bằng TRUNG VỊ, đừng so một lần đo đơn lẻ.")
    return EXIT_OK


# ---------------------------------------------------------------------------
# Khai báo tham số
# ---------------------------------------------------------------------------

def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dt19",
        description="Công cụ ký và xác minh chữ ký số (sigtool) — Đề tài 19",
    )
    sub = parser.add_subparsers(dest="command", help="Các lệnh hỗ trợ")

    sub.add_parser("init", help="Khởi tạo cơ sở dữ liệu và thư mục làm việc")

    p = sub.add_parser("keygen", help="Sinh cặp khóa mới")
    p.add_argument("--alg", default="ed25519",
                   choices=[a.value for a in Algorithm], help="Thuật toán ký")
    p.add_argument("--owner", default="nhom19", help="Chủ sở hữu khóa")

    sub.add_parser("keys", help="Liệt kê khóa trong kho")

    p = sub.add_parser("manifest", help="Lập manifest cho một thư mục")
    p.add_argument("--dir", default="artifacts", help="Thư mục chứa artifact")
    p.add_argument("--out", default="artifacts/manifest.json", help="Tệp manifest")
    p.add_argument("--name", default="manifest", help="Định danh manifest")

    p = sub.add_parser("sign", help="Ký tệp tin")
    p.add_argument("file", type=str, help="Đường dẫn tệp cần ký")
    p.add_argument("--key", type=str, required=True, help="ID của khóa ký")
    p.add_argument("--manifest", action="store_true", help="Tệp này là manifest")

    p = sub.add_parser("verify", help="Xác minh chữ ký")
    p.add_argument("file", type=str, help="Đường dẫn tệp cần xác minh")
    p.add_argument("--sig", type=str, required=True, help="ID của chữ ký")
    p.add_argument("--root", type=str, default=None,
                   help="Thư mục gốc để đối chiếu tệp trong manifest")
    p.add_argument("--verifier", type=str, default=None, help="Tên người xác minh")

    p = sub.add_parser("rotate", help="Luân chuyển khóa")
    p.add_argument("--old", required=True, help="Khóa cũ")
    p.add_argument("--new", required=True, help="Khóa mới")
    p.add_argument("--overlap-days", type=int, default=14,
                   dest="overlap_days", help="Số ngày chồng lấn")

    p = sub.add_parser("revoke", help="Thu hồi khóa")
    p.add_argument("--key", required=True, help="Khóa cần thu hồi")
    p.add_argument("--reason", default="khoa bi lo", help="Lý do thu hồi")
    p.add_argument("--since", default=None,
                   help="Thời điểm NGHI NGỜ bị lộ, ví dụ 2026-10-15T08:00")

    p = sub.add_parser("affected", help="Liệt kê chữ ký của một khóa")
    p.add_argument("--key", required=True)
    p.add_argument("--since", default=None, help="Chỉ lấy từ thời điểm này trở đi")

    p = sub.add_parser("resign", help="Ký lại artifact bằng khóa mới")
    p.add_argument("--old", required=True, help="Khóa cũ")
    p.add_argument("--new", required=True, help="Khóa mới")
    p.add_argument("--dir", default="artifacts", help="Thư mục chứa artifact")
    p.add_argument("--since", default=None, help="Chỉ ký lại từ thời điểm này")

    p = sub.add_parser("bench", help="Đo lường hiệu năng các thuật toán")
    p.add_argument("--iterations", type=int, default=100,
                   help="Số lần lặp mỗi phép đo, tối thiểu 100 theo CS-3")
    p.add_argument("--size", type=int, default=1024 * 1024,
                   help="Kích thước dữ liệu thử, đơn vị byte")
    p.add_argument("--out", default="results/bench.csv", help="Tệp CSV kết quả")

    return parser


HANDLERS = {
    "init": cmd_init,
    "keygen": cmd_keygen,
    "keys": cmd_keys,
    "manifest": cmd_manifest,
    "sign": cmd_sign,
    "verify": cmd_verify,
    "rotate": cmd_rotate,
    "revoke": cmd_revoke,
    "affected": cmd_affected,
    "resign": cmd_resign,
    "bench": cmd_bench,
}


def main(argv: list[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return EXIT_OK

    return HANDLERS[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
