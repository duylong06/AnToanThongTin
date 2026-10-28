"""Giao diện Signer và ba cài đặt cho ba thuật toán.

Người phụ trách: Long | Tuần: 3 và 4

KHÔNG tự cài đặt lại thuật toán mật mã. Mọi phép toán gọi qua thư viện
``cryptography``. Tự viết lại phép ký là cách nhanh nhất để tạo ra lỗ hổng:
riêng việc sinh nonce cho ECDSA đã đủ làm lộ khóa riêng nếu làm sai, xem
ghi chú trong lớp EcdsaSigner.

Ý tưởng thiết kế: ba thuật toán khác nhau hoàn toàn về toán học, nhưng
cùng làm ba việc — sinh khóa, ký, xác minh. Nên tách ba việc đó thành giao
diện chung, phần khác nhau đẩy xuống lớp con. Phép thử: thêm ECDSA và
RSA-PSS ở tuần 4 mà phải sửa tầng nghiệp vụ thì trừu tượng ở tuần 3 đã sai.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from .models import Algorithm, KeyPair

# Hạn dùng mặc định của khóa thử nghiệm: 1 năm.
DEFAULT_VALIDITY_DAYS = 365


def _fingerprint(public_pem: str) -> str:
    """Dấu vân tay = SHA-256 của khóa công khai dạng PEM (FR-02).

    Định danh khóa sinh ra từ chính khóa, không do ai cấp phát. Nhờ vậy hai
    người cầm cùng một khóa công khai luôn tính ra cùng một mã, và người
    xác minh đối chiếu được mà không cần hỏi hệ thống nào cả.
    """
    return hashlib.sha256(public_pem.encode("utf-8")).hexdigest()


class Signer(ABC):
    """Giao diện chung cho ba thuật toán.

    Bốn phương thức trừu tượng là chỗ ba thuật toán khác nhau. Ba phương
    thức công khai (generate_key, sign, verify) viết một lần ở đây và dùng
    chung, vì phần ghi tệp, tính dấu vân tay và bắt ngoại lệ thì thuật toán
    nào cũng như nhau.

    Nhờ lớp trừu tượng này, SigningService và BenchmarkRunner chạy được trên
    cả ba thuật toán mà không cần biết bên trong chúng khác nhau ra sao.
    Thêm thuật toán thứ tư chỉ cần thêm một lớp con và một dòng trong
    SignerFactory.
    """

    alg: Algorithm

    # ---- phần mỗi thuật toán tự lo ----
    @abstractmethod
    def _generate_private_key(self):
        """Sinh đối tượng khóa riêng của thư viện cryptography."""

    @abstractmethod
    def _load_private_key(self, pem_bytes: bytes):
        """Nạp khóa riêng từ chuỗi byte PEM."""

    @abstractmethod
    def _sign_with(self, private_key, data: bytes) -> bytes:
        """Ký, trả chuỗi byte chữ ký."""

    @abstractmethod
    def _verify_with(self, public_key, data: bytes, signature: bytes) -> None:
        """Xác minh; ném InvalidSignature nếu không khớp."""

    # ---- phần dùng chung ----
    def generate_key(
        self, keys_dir: str | Path = "keys", owner: str | None = None
    ) -> KeyPair:
        """Sinh cặp khóa mới và ghi ra đĩa (FR-01, FR-02, FR-03).

        Khóa riêng ghi với quyền 600 để người dùng khác trên cùng máy không
        đọc được. Khóa công khai ghi riêng một tệp .public.pem để chia sẻ.
        """
        private_key = self._generate_private_key()
        public_key = private_key.public_key()

        # PKCS8 và SubjectPublicKeyInfo là hai định dạng chuẩn, đọc được bằng
        # OpenSSL và các công cụ khác. Dùng định dạng riêng thì không ai
        # ngoài chương trình này kiểm chứng lại được kết quả.
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        fp = _fingerprint(public_pem)
        key_id = fp[:16]

        alg_dir = Path(keys_dir) / self.alg.value
        alg_dir.mkdir(parents=True, exist_ok=True)
        private_path = alg_dir / f"{key_id}.key"
        private_path.write_bytes(private_pem)
        try:
            private_path.chmod(0o600)
        except (OSError, NotImplementedError):
            # Windows không có quyền kiểu POSIX. Ghi chú hạn chế này trong
            # báo cáo thay vì giả vờ rằng tệp đã được bảo vệ.
            pass
        (alg_dir / f"{key_id}.public.pem").write_text(public_pem, encoding="utf-8")

        now = datetime.now()
        return KeyPair(
            key_id=key_id,
            algorithm=self.alg.value,
            public_key_pem=public_pem,
            owner=owner or "",
            created_at=now.isoformat(),
            status="ACTIVE",
            private_key_path=str(private_path),
            expires_at=(now + timedelta(days=DEFAULT_VALIDITY_DAYS)).isoformat(),
            fingerprint=fp,
        )

    def sign(self, data: bytes, private_key_path: str) -> bytes:
        """Ký ``data``, trả chuỗi byte chữ ký (FR-06).

        Khóa riêng đọc từ đĩa ngay tại đây rồi thả ra sau khi dùng, không
        giữ trong thuộc tính của đối tượng. Giữ lâu trong bộ nhớ là tăng cơ
        hội nó lọt vào tệp kết xuất khi chương trình đổ vỡ.
        """
        pem = Path(private_key_path).read_bytes()
        private_key = self._load_private_key(pem)
        return self._sign_with(private_key, data)

    def verify(self, data: bytes, signature: bytes, public_key_pem: str) -> bool:
        """Trả True nếu chữ ký khớp.

        KHÔNG ném ngoại lệ khi chữ ký sai. Chữ ký sai là kết quả bình thường
        của việc xác minh chứ không phải lỗi chương trình; nếu ném ngoại lệ
        thì mọi chỗ gọi đều phải bọc try/except và sớm muộn sẽ có chỗ quên,
        làm chương trình dừng giữa chừng thay vì báo "không hợp lệ".
        """
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        try:
            self._verify_with(public_key, data, signature)
            return True
        except InvalidSignature:
            return False
        except Exception:
            # Chữ ký méo mó, sai độ dài, sai định dạng: vẫn là không khớp.
            return False


class RsaPssSigner(Signer):
    """RSA với lược đồ đệm PSS.

    Vì sao phải có đệm. RSA thô là phép biến đổi xác định: cùng một thông
    điệp luôn cho cùng một kết quả, nên kẻ tấn công đoán thử bản rõ được.
    PSS nhúng thêm một lượng ngẫu nhiên gọi là muối trước khi đưa vào phép
    lũy thừa modulo, biến RSA thành lược đồ xác suất.

    Hệ quả quan sát được: ký cùng một dữ liệu hai lần bằng RSA-PSS cho ra
    hai chữ ký KHÁC nhau, và cả hai đều xác minh đúng. Đây là một ca kiểm
    thử đáng viết, vì nó chứng minh muối thật sự ngẫu nhiên.

    Đánh đổi: chữ ký bằng đúng kích thước khóa, tức 256 byte với khóa 2048
    bit — gấp bốn lần Ed25519. Số liệu này vào bảng so sánh ở mục kết quả.
    """

    alg = Algorithm.RSA_PSS

    def __init__(self, key_size: int = 2048) -> None:
        # Kích thước khóa là tham số của lớp chứ không phải một thuật toán
        # riêng, nên cột ``algorithm`` trong bảng keys chỉ có ba giá trị.
        self.key_size = key_size

    def _generate_private_key(self):
        # 65537 là số mũ công khai chuẩn: đủ lớn để tránh các tấn công số mũ
        # nhỏ, lại có dạng nhị phân thưa nên tính nhanh.
        return rsa.generate_private_key(public_exponent=65537, key_size=self.key_size)

    def _load_private_key(self, pem_bytes: bytes):
        return serialization.load_pem_private_key(pem_bytes, password=None)

    @staticmethod
    def _padding() -> padding.PSS:
        """MAX_LENGTH cho muối dài nhất mà kích thước khóa cho phép."""
        return padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        )

    def _sign_with(self, private_key, data: bytes) -> bytes:
        return private_key.sign(data, self._padding(), hashes.SHA256())

    def _verify_with(self, public_key, data: bytes, signature: bytes) -> None:
        public_key.verify(signature, data, self._padding(), hashes.SHA256())


class EcdsaSigner(Signer):
    """ECDSA trên đường cong P-256 (secp256r1).

    Điểm phải nêu trong báo cáo: nonce k phải ngẫu nhiên và KHÔNG BAO GIỜ
    lặp lại. Nếu cùng một khóa riêng d ký hai thông điệp khác nhau bằng cùng
    một k, kẻ tấn công lập được hai phương trình chữ ký, khử k đi và giải ra
    d chỉ bằng vài phép số học. Mất k một lần là mất toàn bộ khóa riêng, chứ
    không phải mất riêng chữ ký đó.

    Thư viện chuẩn đã lo việc sinh nonce từ nguồn ngẫu nhiên của hệ điều
    hành. Đây chính là lý do cụ thể của quy tắc "không tự cài đặt lại thuật
    toán mật mã".

    Vì nonce ngẫu nhiên nên ECDSA cũng cho chữ ký khác nhau mỗi lần ký, như
    RSA-PSS. Kích thước chữ ký khoảng 70 đến 72 byte, thay đổi chút ít giữa
    các lần vì mã hóa DER cắt bỏ byte 0 ở đầu số nguyên.
    """

    alg = Algorithm.ECDSA_P256

    def _generate_private_key(self):
        return ec.generate_private_key(ec.SECP256R1())

    def _load_private_key(self, pem_bytes: bytes):
        return serialization.load_pem_private_key(pem_bytes, password=None)

    def _sign_with(self, private_key, data: bytes) -> bytes:
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

    def _verify_with(self, public_key, data: bytes, signature: bytes) -> None:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))


class Ed25519Signer(Signer):
    """EdDSA trên đường cong Edwards xoắn Ed25519 (RFC 8032).

    Cải tiến cốt lõi so với ECDSA: nonce sinh TẤT ĐỊNH theo công thức
    k = H(prefix ‖ M), trong đó prefix là chuỗi byte bí mật trích từ chính
    khóa riêng, còn M là thông điệp. Hệ quả:

    - Cùng một thông điệp luôn cho cùng một nonce. Không cần nguồn ngẫu
      nhiên lúc ký, nên bộ sinh số ngẫu nhiên kém không làm lộ khóa được.
    - Hai thông điệp khác nhau cho hai nonce khác nhau, vì hàm băm kháng va
      chạm. Rủi ro trùng nonce của ECDSA bị triệt tiêu ngay từ thiết kế.

    Hệ quả quan sát được trong thực nghiệm, và là ca kiểm thử nên viết: ký
    cùng một dữ liệu hai lần bằng Ed25519 cho ra hai chữ ký GIỐNG HỆT nhau,
    còn RSA-PSS và ECDSA thì không. Đây là bằng chứng trực tiếp cho sự khác
    nhau giữa nonce tất định và nonce ngẫu nhiên.

    Chữ ký cố định 64 byte, khóa công khai 32 byte. Nhỏ nhất trong ba thuật
    toán, và không có tham số nào để cấu hình sai.
    """

    alg = Algorithm.ED25519

    def _generate_private_key(self):
        return ed25519.Ed25519PrivateKey.generate()

    def _load_private_key(self, pem_bytes: bytes):
        return serialization.load_pem_private_key(pem_bytes, password=None)

    def _sign_with(self, private_key, data: bytes) -> bytes:
        # Ed25519 tự băm bên trong theo RFC 8032, nên không truyền hàm băm
        # như hai thuật toán trên. Ít tham số hơn cũng là ít chỗ cấu hình sai.
        return private_key.sign(data)

    def _verify_with(self, public_key, data: bytes, signature: bytes) -> None:
        public_key.verify(signature, data)


class SignerFactory:
    """Chọn cài đặt theo thuật toán.

    Đây là chỗ DUY NHẤT trong hệ thống biết tên cả ba lớp con. Mọi nơi khác
    chỉ cầm một đối tượng Signer. Nhờ vậy thêm thuật toán thứ tư chỉ phải
    sửa đúng tệp này.
    """

    @staticmethod
    def create(alg: Algorithm | str, key_size: int = 2048) -> Signer:
        alg = Algorithm(alg)
        if alg == Algorithm.RSA_PSS:
            return RsaPssSigner(key_size)
        if alg == Algorithm.ECDSA_P256:
            return EcdsaSigner()
        if alg == Algorithm.ED25519:
            return Ed25519Signer()
        raise ValueError(f"Thuật toán không được hỗ trợ: {alg}")

    @staticmethod
    def all_algorithms() -> list[Algorithm]:
        """Ba thuật toán dùng để so sánh trong báo cáo.

        Xếp theo thứ tự Ed25519, ECDSA, RSA-PSS để bảng kết quả và biểu đồ
        đi từ chữ ký nhỏ nhất tới lớn nhất.
        """
        return [Algorithm.ED25519, Algorithm.ECDSA_P256, Algorithm.RSA_PSS]
