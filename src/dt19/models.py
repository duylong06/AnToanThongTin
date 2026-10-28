"""
Tác giả: Nguyễn Quỳnh Phiếu (lớp miền gốc) — Nguyễn Duy Long (phần bổ sung)
Mô tả: Lớp miền cho hệ thống sigtool (KeyPair, Manifest, ReasonCode)

GHI CHÚ VỀ PR NÀY (Long):
Toàn bộ mã gốc của Phiêu giữ nguyên, không đổi tên và không xóa gì. Phần
thêm vào đều nằm trong các khối đánh dấu "Long bổ sung" và đều có giá trị
mặc định, nên mọi ca kiểm thử cũ vẫn chạy đúng như trước.
"""

import hashlib
import json
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple, Union


class ReasonCode(Enum):
    """Mã lý do phản ánh kết quả xác minh chữ ký"""
    SUCCESS = "SUCCESS"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    FILE_MODIFIED = "FILE_MODIFIED"
    FILE_MISSING = "FILE_MISSING"
    KEY_REVOKED = "KEY_REVOKED"
    KEY_NOT_TRUSTED = "KEY_NOT_TRUSTED"
    MANIFEST_TAMPERED = "MANIFEST_TAMPERED"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"

    # === Long bổ sung: ba mã đề bài yêu cầu mà bảng hiện tại chưa có ===
    # KEY_EXPIRED khác KEY_REVOKED: hết hạn là vòng đời bình thường, còn thu
    # hồi là sự cố. Hai tình huống dẫn tới hai hành động khác nhau.
    KEY_EXPIRED = "KEY_EXPIRED"
    # Dấu thời gian không kiểm chứng được, trong khi chữ ký vẫn đúng.
    TIMESTAMP_INVALID = "TIMESTAMP_INVALID"
    # Nội dung còn nguyên nhưng tên tệp bị đổi — tấn công tráo tên.
    METADATA_MODIFIED = "METADATA_MODIFIED"


# === Long bổ sung ===============================================
MESSAGES_VI: Dict[ReasonCode, str] = {
    ReasonCode.SUCCESS: "Xác minh thành công.",
    ReasonCode.INVALID_SIGNATURE: "Chữ ký không khớp với nội dung tệp.",
    ReasonCode.FILE_MODIFIED: "Nội dung tệp đã bị sửa so với lúc ký.",
    ReasonCode.FILE_MISSING: "Tệp ghi trong manifest không còn trên đĩa.",
    ReasonCode.KEY_REVOKED: "Khóa ký đã bị thu hồi.",
    ReasonCode.KEY_NOT_TRUSTED: "Khóa ký không nằm trong danh sách tin cậy.",
    ReasonCode.MANIFEST_TAMPERED: "Manifest đã bị can thiệp.",
    ReasonCode.KEY_EXPIRED: "Khóa ký đã hết hiệu lực tại thời điểm ký.",
    ReasonCode.TIMESTAMP_INVALID: "Dấu thời gian không kiểm chứng được.",
    ReasonCode.METADATA_MODIFIED: "Tệp bị đổi tên so với lúc ký.",
    ReasonCode.UNKNOWN_ERROR: "Lỗi không xác định.",
}


class Algorithm(str, Enum):
    """Ba thuật toán chữ ký đề tài yêu cầu so sánh.

    Giá trị giữ đúng chuỗi Phiêu đã dùng trong models và schema
    ("rsa-pss", "ecdsa", "ed25519"), nên cột ``algorithm`` trong bảng ``keys``
    không phải đổi và ca kiểm thử cũ so sánh với chuỗi vẫn đúng.
    """

    ED25519 = "ed25519"
    ECDSA_P256 = "ecdsa"
    RSA_PSS = "rsa-pss"


ISO = "%Y-%m-%dT%H:%M:%S.%f"


def _to_dt(value: Union[str, datetime, None]) -> Optional[datetime]:
    """Đổi chuỗi ISO sang datetime. Chịu được cả hai định dạng đang dùng."""
    if value is None or isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def sha256_file(path: Union[str, Path]) -> str:
    """Mã băm SHA-256 của một tệp, đọc theo khối để không nuốt hết bộ nhớ."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Mã băm SHA-256 của một chuỗi byte."""
    return hashlib.sha256(data).hexdigest()
# === hết phần Long bổ sung ======================================


@dataclass
class KeyPair:
    """Quản lý thông tin cặp khóa và trạng thái vòng đời"""
    key_id: str
    algorithm: str  # rsa-pss, ecdsa, ed25519
    public_key_pem: str
    owner: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "ACTIVE"  # ACTIVE, REVOKED
    revoked_at: Optional[str] = None

    # === Long bổ sung: ba trường phần ký và xác minh bắt buộc phải có ===
    # Tất cả đều có mặc định None nên KeyPair(...) kiểu cũ vẫn dựng được.
    #
    # private_key_path: chỉ lưu ĐƯỜNG DẪN, không bao giờ lưu nội dung khóa
    #   riêng vào cơ sở dữ liệu hay vào nhật ký (NFR-04, NFR-06).
    # expires_at: cần để phân biệt KEY_EXPIRED với KEY_REVOKED.
    # fingerprint: SHA-256 của khóa công khai, dùng để người xác minh đối
    #   chiếu khóa mà không cần hỏi hệ thống nào.
    private_key_path: Optional[str] = None
    expires_at: Optional[str] = None
    fingerprint: Optional[str] = None

    @property
    def created_dt(self) -> Optional[datetime]:
        return _to_dt(self.created_at)

    @property
    def expires_dt(self) -> Optional[datetime]:
        return _to_dt(self.expires_at)

    def is_valid_at(self, moment: datetime) -> bool:
        """Khóa còn hiệu lực tại thời điểm ``moment`` hay không.

        Khóa đã thu hồi thì không bao giờ hợp lệ, kể cả với thời điểm trong
        quá khứ. Việc phân loại chữ ký cũ trước và sau mốc nghi ngờ bị lộ là
        việc của RevocationService, không phải của hàm này.
        """
        if self.status == "REVOKED":
            return False
        created = self.created_dt
        expires = self.expires_dt
        if created is not None and moment < created:
            return False
        if expires is not None and moment > expires:
            return False
        return True


@dataclass
class Manifest:
    """Quản lý danh sách các tệp tin và giá trị băm SHA-256 tương ứng"""
    files: Dict[str, str]  # { "path/to/file": "sha256_hash" }
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    version: str = "1.0"
    # === Long bổ sung: định danh để đặt tên tệp chữ ký ===
    manifest_id: str = "manifest"

    def add_file(self, file_path: str, file_hash: str) -> None:
        self.files[file_path] = file_hash

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "created_at": self.created_at,
            "files": self.files,
            "manifest_id": self.manifest_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Manifest':
        return cls(
            files=data.get("files", {}),
            created_at=data.get("created_at", ""),
            version=data.get("version", "1.0"),
            manifest_id=data.get("manifest_id", "manifest"),
        )

    # === Long bổ sung ===========================================
    def add_path(self, path: Union[str, Path], name: Optional[str] = None) -> str:
        """Băm một tệp trên đĩa rồi thêm vào manifest. Trả về mã băm."""
        p = Path(path)
        digest = sha256_file(p)
        self.add_file(name or p.name, digest)
        return digest

    def canonical_bytes(self) -> bytes:
        """Chuỗi byte chuẩn hóa dùng để ký.

        Phải ổn định tuyệt đối: cùng nội dung luôn cho cùng chuỗi byte, bất
        kể thứ tự chèn vào dict hay hệ điều hành đang chạy. Nếu không chuẩn
        hóa, hai máy cùng một manifest sẽ cho hai chữ ký khác nhau và xác
        minh chéo sẽ trượt oan.

        Hai biện pháp: sắp khóa trong JSON và cố định dấu phân cách.
        """
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def verify_contents(
        self, root_dir: Union[str, Path]
    ) -> Tuple[ReasonCode, Optional[str]]:
        """Đối chiếu từng tệp trên đĩa với mã băm ghi trong manifest.

        Phân biệt ba loại sai lệch, vì nguyên nhân và cách xử lý khác nhau:

        - ``FILE_MODIFIED``: tệp còn đó nhưng ruột đã khác.
        - ``METADATA_MODIFIED``: ruột vẫn nguyên nhưng tên tệp bị đổi. Phát
          hiện bằng cách tìm trong thư mục xem có tệp nào cùng mã băm không.
          Đây là tấn công tráo tên: nội dung hợp lệ, nhưng được đặt vào vị
          trí mà người dùng tưởng là thứ khác.
        - ``FILE_MISSING``: tệp biến mất hẳn.
        """
        root = Path(root_dir)
        for rel_path, expected in self.files.items():
            target = root / rel_path
            if not target.exists():
                for other in root.glob("*"):
                    if other.is_file() and sha256_file(other) == expected:
                        return (
                            ReasonCode.METADATA_MODIFIED,
                            f"{rel_path} bi doi ten thanh {other.name}",
                        )
                return ReasonCode.FILE_MISSING, f"{rel_path} khong ton tai"
            if sha256_file(target) != expected:
                return ReasonCode.FILE_MODIFIED, rel_path
        return ReasonCode.SUCCESS, None


# === Long bổ sung: hai lớp phần ký và xác minh cần ==============
@dataclass
class Signature:
    """Chữ ký tách rời: không sửa artifact gốc, chữ ký nằm ở tệp riêng.

    Ký tách rời chứ không nhúng vào tệp vì hai lý do. Một là artifact giữ
    nguyên mã băm, nên đối chiếu được với bản phát hành gốc. Hai là một
    artifact có thể mang nhiều chữ ký của nhiều khóa khác nhau.
    """

    signature_id: str
    target_id: str
    target_kind: str  # artifact | manifest
    key_id: str
    algorithm: str
    sig_path: str
    sig_size_bytes: int
    signed_at: datetime
    timestamp_token: Optional[str] = None


@dataclass
class VerificationResult:
    """Kết quả xác minh.

    Trả về cả mã lý do chứ không chỉ True/False. Một hàm trả bool không ghi
    nổi nhật ký có ý nghĩa và không giúp người dùng sửa sai.
    """

    passed: bool
    reason: ReasonCode
    duration_ms: float = 0.0
    detail: Optional[str] = None

    @property
    def message_vi(self) -> str:
        base = MESSAGES_VI.get(self.reason, self.reason.value)
        return f"{base} ({self.detail})" if self.detail else base
