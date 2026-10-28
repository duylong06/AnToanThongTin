"""Tầng nghiệp vụ: ký, xác minh, thu hồi, đo hiệu năng.

Người phụ trách: Long (ký, xác minh, thu hồi) và Uyên (benchmark) | Tuần 3–5

Tầng này không biết thuật toán nào đang chạy, chỉ làm việc qua giao diện
``Signer``. Mã lý do dùng đúng bảng ``ReasonCode`` của Phiêu trong models.py.

THỨ TỰ KIỂM TRA trong VerificationService quyết định mã lý do trả về:
  1. Khóa có trong kho không?
  2. Khóa đã bị thu hồi chưa?
  3. Khóa có được tin tại THỜI ĐIỂM KÝ không?
  4. Chữ ký có khớp không?
  5. Dấu thời gian có kiểm chứng được không?
Làm sai thứ tự này thì chương trình vẫn chạy, vẫn báo "sai", nhưng báo sai
chỗ — và đề tài chấm điểm đúng ở chỗ phân biệt được nguyên nhân.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import json
import secrets
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from .models import (
    ReasonCode,
    Signature,
    VerificationResult,
    sha256_bytes,
)
from .repository import Repository
from .signers import SignerFactory
from .trust import TrustList

# Khóa bí mật của dịch vụ dấu thời gian mô phỏng. Trong hệ thống thật đây là
# khóa của một TSA độc lập mà nhóm không giữ; ở đồ án nhóm giữ cục bộ và nêu
# rõ đây là giả lập. Xem phần GIỚI HẠN trong TimestampService.
_TSA_SECRET = b"dt19-tsa-khoa-mo-phong-chi-dung-cho-do-an"


class TimestampService:
    """Dấu thời gian mô phỏng cục bộ (FR-08).

    Tách thành lớp riêng vì hai lý do.

    Thứ nhất, kiểm thử cần bơm thời gian giả. Muốn kiểm tra "khóa đã hết hạn
    tại thời điểm ký" mà phải chờ khóa hết hạn thật thì không kiểm thử được.
    Tham số ``fixed_now`` làm đồng hồ đứng yên, nhờ vậy kết quả tái lập được.

    Thứ hai, nếu sau này thay bằng TSA chuẩn RFC 3161 thì chỉ đổi lớp này,
    không đụng tới phần ký và xác minh.

    GIỚI HẠN phải nêu trong báo cáo: đây KHÔNG phải dấu thời gian có giá trị
    trước bên thứ ba. Chính nhóm giữ khóa ký dấu, nên nhóm tự tạo được dấu
    thời gian bất kỳ. Một TSA thật có giá trị vì nó độc lập với người ký.
    """

    def __init__(self, fixed_now: datetime | None = None) -> None:
        self._fixed_now = fixed_now

    def now(self) -> datetime:
        return self._fixed_now or datetime.now()

    def issue_token(self, digest: str) -> str:
        """Token = thời điểm ‖ HMAC(thời điểm ‖ mã băm dữ liệu).

        Gắn token với mã băm của dữ liệu chứ không chỉ với thời điểm. Nếu chỉ
        ký thời điểm thì token tháo ra khỏi tệp này gắn sang tệp khác vẫn
        hợp lệ.
        """
        ts = self.now().isoformat()
        mac = hmac.new(
            _TSA_SECRET, f"{ts}|{digest}".encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return f"{ts}|{mac}"

    def check_token(self, token: str, digest: str) -> bool:
        try:
            ts, mac = token.rsplit("|", 1)
        except ValueError:
            return False
        expected = hmac.new(
            _TSA_SECRET, f"{ts}|{digest}".encode("utf-8"), hashlib.sha256
        ).hexdigest()
        # So sánh bằng compare_digest chứ không bằng "==": phép so sánh chuỗi
        # thông thường dừng ngay tại byte đầu tiên khác nhau, nên thời gian
        # chạy tiết lộ đã khớp được bao nhiêu byte.
        return hmac.compare_digest(mac, expected)

    def token_time(self, token: str) -> datetime | None:
        try:
            return datetime.fromisoformat(token.rsplit("|", 1)[0])
        except (ValueError, IndexError):
            return None


class SigningService:
    """Ký artifact và manifest (FR-06 đến FR-09)."""

    def __init__(
        self,
        repo: Repository,
        clock: TimestampService | None = None,
        sig_dir: str | Path = "signatures",
    ) -> None:
        self.repo = repo
        self.clock = clock or TimestampService()
        self.sig_dir = Path(sig_dir)

    def _sign_bytes(
        self, data: bytes, key_id: str, target_id: str, target_kind: str
    ) -> Signature:
        """Phần chung của mọi phép ký: tra khóa, ký, ghi tệp, lưu bản ghi."""
        key = self.repo.get_key(key_id)
        if key is None:
            raise ValueError(f"Khong tim thay khoa {key_id}")
        if not key.private_key_path:
            raise ValueError(f"Khoa {key_id} khong co duong dan khoa rieng")

        signer = SignerFactory.create(key.algorithm)
        sig_bytes = signer.sign(data, key.private_key_path)

        # Chữ ký TÁCH RỜI: ghi ra tệp riêng, artifact gốc không bị đụng vào
        # (FR-09). Nhờ vậy mã băm của artifact vẫn đối chiếu được với bản
        # phát hành gốc, và một artifact mang được nhiều chữ ký.
        self.sig_dir.mkdir(parents=True, exist_ok=True)
        sig_path = self.sig_dir / f"{target_id}.{key.algorithm}.sig"
        sig_path.write_bytes(sig_bytes)

        digest = sha256_bytes(data)
        signature = Signature(
            signature_id=f"{target_id}:{key_id}:{secrets.token_hex(4)}",
            target_id=target_id,
            target_kind=target_kind,
            key_id=key_id,
            algorithm=key.algorithm,
            sig_path=str(sig_path),
            sig_size_bytes=len(sig_bytes),
            signed_at=self.clock.now(),
            timestamp_token=self.clock.issue_token(digest),
        )
        self.repo.save_signature(signature)
        return signature

    def sign_artifact(self, path: str | Path, key_id: str) -> Signature:
        """Ký trực tiếp nội dung một tệp."""
        data = Path(path).read_bytes()
        return self._sign_bytes(data, key_id, Path(path).name, "artifact")

    def sign_manifest(self, manifest, key_id: str) -> Signature:
        """Ký manifest: một chữ ký bảo vệ cả bộ artifact.

        Dùng ``Manifest.canonical_bytes()`` của Phiêu, nên thêm hay bớt một
        tệp khỏi bộ phát hành đều làm chữ ký không còn khớp.
        """
        return self._sign_bytes(
            manifest.canonical_bytes(), key_id, manifest.manifest_id, "manifest"
        )


class VerificationService:
    """Xác minh chữ ký và ghi nhật ký (FR-10 đến FR-14).

    THỨ TỰ KIỂM TRA CÓ CHỦ Ý, và đây là chi tiết đáng viết nhất trong báo
    cáo: tra trust list TRƯỚC khi kiểm tra chữ ký.

    Nếu làm ngược lại, một khóa lạ nhưng ký đúng sẽ qua được bước mật mã rồi
    mới bị chặn, và thông báo lỗi sẽ không nói được rằng vấn đề nằm ở SỰ TIN
    CẬY chứ không ở phép toán. Về mặt an toàn, phép toán đúng mà khóa không
    đáng tin thì vẫn là không hợp lệ — thứ tự kiểm tra phản ánh đúng điều đó.
    """

    def __init__(
        self,
        repo: Repository,
        trust_list: TrustList,
        clock: TimestampService | None = None,
        log_path: str | Path = "results/verify_log.jsonl",
        verifier: str | None = None,
    ) -> None:
        self.repo = repo
        self.trust_list = trust_list
        self.clock = clock or TimestampService()
        self.log_path = Path(log_path)
        self.verifier = verifier

    def _log(self, sig: Signature | None, result: VerificationResult) -> None:
        """Ghi nhật ký chỉ cho phép ghi thêm (NFR-05).

        Hai nơi: tệp JSONL mở ở chế độ "a" (qua API này không có đường nào
        sửa dòng cũ), và bảng ``verify_logs`` của Phiêu để truy vấn.
        """
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "verified_at": datetime.now().isoformat(),
            "signature_id": sig.signature_id if sig else None,
            "target_id": sig.target_id if sig else None,
            "key_id": sig.key_id if sig else None,
            "algorithm": sig.algorithm if sig else None,
            "result": "pass" if result.passed else "fail",
            "reason_code": result.reason.value,
            "detail": result.detail,
            "trust_list_version": self.trust_list.version,
            "verifier": self.verifier,
            "duration_ms": round(result.duration_ms, 4),
        }
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

        if sig is not None:
            try:
                self.repo.log_verification(
                    sig_id=sig.signature_id,
                    status="PASSED" if result.passed else "FAILED",
                    reason_code=result.reason,
                    verified_at=record["verified_at"],
                    details=result.detail or "",
                )
            except Exception:
                # Nhật ký JSONL là nguồn chính. Lỗi khi ghi cơ sở dữ liệu
                # không được phép làm hỏng kết quả xác minh.
                pass

    def _check_key(self, sig: Signature) -> tuple[ReasonCode, str | None]:
        """Bước 1 đến 3: khóa có đáng tin tại THỜI ĐIỂM KÝ không.

        Mọi phép so sánh ở đây dùng ``sig.signed_at``, không dùng thời điểm
        hiện tại. Một chữ ký tạo hôm qua bằng khóa hôm nay đã hết hiệu lực
        vẫn phải hợp lệ, vì lúc ký nó hoàn toàn đúng.
        """
        key = self.repo.get_key(sig.key_id)
        if key is None:
            return ReasonCode.KEY_NOT_TRUSTED, f"khong tim thay khoa {sig.key_id}"

        # Thu hồi xét trước trust list: khóa bị lộ là tình huống nặng hơn,
        # và mã lý do KEY_REVOKED nói rõ nguyên nhân hơn KEY_EXPIRED.
        revoked_at = self.repo.get_revocation(sig.key_id)
        if revoked_at is not None and sig.signed_at >= revoked_at:
            return ReasonCode.KEY_REVOKED, f"thu hoi luc {revoked_at:%d/%m/%Y %H:%M}"

        if not self.trust_list.is_trusted(sig.key_id, sig.signed_at):
            # Phân biệt hai tình huống khác hẳn nhau:
            #  - khóa có trong danh sách nhưng ngoài khoảng hiệu lực
            #    → đã từng được tin, nay hết hạn hoặc quá giai đoạn chồng lấn
            #  - khóa chưa bao giờ có trong danh sách → hoàn toàn xa lạ
            in_list = any(e.key_id == sig.key_id for e in self.trust_list.entries)
            if in_list:
                return ReasonCode.KEY_EXPIRED, "ngoai khoang hieu luc"
            return (
                ReasonCode.KEY_NOT_TRUSTED,
                f"khoa {sig.key_id} khong trong trust list",
            )

        expires = key.expires_dt
        if expires is not None and sig.signed_at > expires:
            return ReasonCode.KEY_EXPIRED, "khoa het han"

        return ReasonCode.SUCCESS, None

    def verify_signature(
        self, data: bytes, sig: Signature, sig_bytes: bytes | None = None
    ) -> VerificationResult:
        """Xác minh một chuỗi byte đã biết trước. Lối vào chung của mọi phép xác minh."""
        started = time.perf_counter()

        # --- Bước 1 đến 3: khóa ---
        reason, detail = self._check_key(sig)
        if reason is not ReasonCode.SUCCESS:
            result = VerificationResult(
                False, reason, (time.perf_counter() - started) * 1000, detail
            )
            self._log(sig, result)
            return result

        # --- Bước 4: chữ ký ---
        # Kiểm chữ ký TRƯỚC dấu thời gian. Dấu thời gian gắn với mã băm của
        # dữ liệu, nên mọi sửa đổi nội dung đều làm nó sai theo. Nếu kiểm dấu
        # thời gian trước, một tệp bị sửa sẽ báo TIMESTAMP_INVALID trong khi
        # nguyên nhân thật là chữ ký không còn khớp — thông báo đúng về mặt
        # kỹ thuật nhưng sai chỗ, và người dùng sẽ đi sửa nhầm thứ.
        key = self.repo.get_key(sig.key_id)
        signer = SignerFactory.create(sig.algorithm)
        if sig_bytes is None:
            sig_bytes = Path(sig.sig_path).read_bytes()

        if not signer.verify(data, sig_bytes, key.public_key_pem):
            result = VerificationResult(
                False,
                ReasonCode.INVALID_SIGNATURE,
                (time.perf_counter() - started) * 1000,
                "noi dung da ky bi sua hoac chu ky khong dung",
            )
            self._log(sig, result)
            return result

        # --- Bước 5: dấu thời gian ---
        # Tới đây chữ ký đã đúng, nghĩa là dữ liệu nguyên vẹn. Nếu dấu thời
        # gian vẫn sai thì nguyên nhân chỉ có thể là chính token bị sửa.
        if sig.timestamp_token:
            if not self.clock.check_token(sig.timestamp_token, sha256_bytes(data)):
                result = VerificationResult(
                    False,
                    ReasonCode.TIMESTAMP_INVALID,
                    (time.perf_counter() - started) * 1000,
                    "token dau thoi gian khong khop",
                )
                self._log(sig, result)
                return result

        result = VerificationResult(
            True, ReasonCode.SUCCESS, (time.perf_counter() - started) * 1000
        )
        self._log(sig, result)
        return result

    def verify_artifact(self, path: str | Path, sig: Signature) -> VerificationResult:
        """Xác minh một tệp đơn lẻ."""
        return self.verify_signature(Path(path).read_bytes(), sig)

    def verify_manifest(
        self, manifest, sig: Signature, root_dir: str | Path
    ) -> VerificationResult:
        """Xác minh manifest rồi đối chiếu từng tệp trên đĩa.

        Hai bước tách bạch và trả hai nhóm mã lý do khác nhau: manifest bị
        can thiệp thì chữ ký không khớp (INVALID_SIGNATURE), còn manifest
        nguyên vẹn mà tệp trên đĩa bị sửa thì là FILE_MODIFIED,
        METADATA_MODIFIED hoặc FILE_MISSING. Đây là hai sự cố khác nhau và
        cách xử lý cũng khác nhau.
        """
        result = self.verify_signature(manifest.canonical_bytes(), sig)
        if not result.passed:
            return result

        started = time.perf_counter()
        reason, detail = manifest.verify_contents(root_dir)
        if reason is not ReasonCode.SUCCESS:
            bad = VerificationResult(
                False, reason, (time.perf_counter() - started) * 1000, detail
            )
            self._log(sig, bad)
            return bad
        return result


class RevocationService:
    """Thu hồi khóa và xử lý hậu quả (FR-17, FR-18, FR-19).

    Thu hồi không chỉ là đánh dấu một khóa là hỏng. Câu hỏi thật sự là:
    những gì đã ký bằng khóa đó giờ còn tin được không? Trả lời câu đó là
    việc của ``list_affected``, và nó là đầu vào của runbook docs/06.
    """

    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def revoke(
        self,
        key_id: str,
        reason: str,
        revoked_at: datetime,
        suspected_since: datetime | None = None,
    ) -> int:
        """Thu hồi khóa, trả về số chữ ký bị ảnh hưởng.

        Hai mốc thời gian khác nhau, đừng nhầm:

        ``revoked_at`` là mốc cắt hiệu lực ghi vào trust list.

        ``suspected_since`` là thời điểm NGHI NGỜ BỊ LỘ, thường sớm hơn
        nhiều so với lúc phát hiện. Chữ ký tạo từ mốc này trở đi bị coi là
        không đáng tin. Dùng mốc phát hiện thay cho mốc nghi ngờ là bỏ sót
        đúng những chữ ký nguy hiểm nhất.

        Bỏ trống ``suspected_since`` nghĩa là KHÔNG BIẾT khóa lộ từ bao giờ.
        Khi đó phải giả định trường hợp xấu nhất và coi mọi chữ ký của khóa
        này đều đáng ngờ, thay vì báo con số 0 gây hiểu nhầm là an toàn.
        """
        affected = self.list_affected(key_id, suspected_since)
        self.repo.set_key_status(key_id, "REVOKED")
        self.repo.save_revocation(key_id, reason, revoked_at, len(affected))
        return len(affected)

    def list_affected(
        self, key_id: str, since: datetime | None = None
    ) -> list[Signature]:
        """Chữ ký tạo bằng khóa này; có ``since`` thì chỉ lấy từ mốc đó trở đi."""
        sigs = self.repo.find_signatures_by_key(key_id)
        if since is None:
            return sigs
        return [s for s in sigs if s.signed_at >= since]


# ==========================================================================
# Phần của Phiêu và Uyên, giữ nguyên từ PR #5 — Long chỉ gộp vào cùng tệp
# ==========================================================================

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
