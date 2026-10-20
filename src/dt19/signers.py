"""Giao diện Signer và ba cài đặt cho ba thuật toán.

Người phụ trách: Long | Tuần: 3 và 4

Phải có trong tệp này:
- Lớp trừu tượng Signer: generate_key(), sign(), verify()
- Ed25519Signer      (tuần 3 — làm TRƯỚC vì API gọn nhất)
- EcdsaSigner        (tuần 4)
- RsaPssSigner       (tuần 4)
- SignerFactory.create(alg)

Phép thử thiết kế: thêm ECDSA và RSA ở tuần 4 mà phải sửa tầng nghiệp vụ
thì trừu tượng ở tuần 3 đã sai.

KHÔNG tự cài đặt lại thuật toán mật mã. Gọi qua thư viện cryptography.
"""

# TODO
