"""Lớp miền: kiểu dữ liệu thuần, không phụ thuộc đĩa hay cơ sở dữ liệu.

Người phụ trách: Phiêu | Tuần: 3

Phải có trong tệp này:
- Algorithm (enum ba thuật toán)
- ReasonCode (enum mã lý do) kèm từ điển thông điệp tiếng Việt
- KeyPair: key_id, alg, fingerprint, created_at, expires_at, is_valid_at()
- Manifest và ManifestEntry: add_file(), canonical_bytes(), verify_contents()
- Signature, VerificationResult
- Hàm băm sha256_file() và sha256_bytes()

Lưu ý: canonical_bytes() phải ỔN ĐỊNH — cùng nội dung luôn cho cùng chuỗi
byte, bất kể thứ tự khóa trong dict hay hệ điều hành đang chạy.
"""

# TODO
