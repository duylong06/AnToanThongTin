# Sơ đồ lớp và kiến trúc

> Người viết: **Phiêu và Long** | Tuần: **2**

## 1. Phân tầng

Bốn tầng, phụ thuộc chỉ đi một chiều từ trên xuống. Tầng dưới không biết gì
về tầng trên.

```mermaid
flowchart TB
    CLI["Tầng giao diện — cli.py<br/>phân tích tham số, in kết quả, trả mã thoát"]
    SVC["Tầng nghiệp vụ — services.py<br/>SigningService · VerificationService<br/>RevocationService · TimestampService · BenchmarkService"]
    DOM["Tầng miền — models.py, trust.py<br/>KeyPair · Manifest · Signature · ReasonCode · TrustList"]
    INF["Tầng hạ tầng — signers.py, repository.py<br/>Signer (3 cài đặt) · Repository (SQLite)"]

    CLI --> SVC
    SVC --> DOM
    SVC --> INF
    INF --> DOM
```

Lý do tách: tầng **nghiệp vụ** phải kiểm thử được mà không cần đụng tới đĩa
hay cơ sở dữ liệu thật. Vì `SigningService` chỉ phụ thuộc vào giao diện
`Signer` chứ không phụ thuộc vào `Ed25519Signer` cụ thể, và chỉ phụ thuộc
vào `Repository` chứ không phụ thuộc vào tệp `.db` nào, nên bộ kiểm thử
thay được bằng cơ sở dữ liệu trong bộ nhớ và chạy xong không để lại rác.

Bằng chứng tầng được tách đúng: 54 ca kiểm thử chạy trong 1,6 giây và không
sinh ra tệp nào ngoài thư mục tạm của pytest.

## 2. Sơ đồ lớp

```mermaid
classDiagram
    direction TB

    class Algorithm {
        <<enumeration>>
        ED25519
        ECDSA_P256
        RSA_PSS
    }

    class ReasonCode {
        <<enumeration>>
        SUCCESS
        INVALID_SIGNATURE
        FILE_MODIFIED
        FILE_MISSING
        METADATA_MODIFIED
        KEY_NOT_TRUSTED
        KEY_REVOKED
        KEY_EXPIRED
        TIMESTAMP_INVALID
        MANIFEST_TAMPERED
    }

    class KeyPair {
        +str key_id
        +str algorithm
        +str public_key_pem
        +str private_key_path
        +str fingerprint
        +str created_at
        +str expires_at
        +str status
        +is_valid_at(moment) bool
    }

    class Manifest {
        +dict files
        +str manifest_id
        +str version
        +add_path(path) str
        +canonical_bytes() bytes
        +verify_contents(root) ReasonCode
    }

    class Signature {
        +str signature_id
        +str target_id
        +str target_kind
        +str key_id
        +str sig_path
        +int sig_size_bytes
        +datetime signed_at
        +str timestamp_token
    }

    class Signer {
        <<abstract>>
        +Algorithm alg
        +generate_key(dir, owner) KeyPair
        +sign(data, key_path) bytes
        +verify(data, sig, pub_pem) bool
        #_generate_private_key()*
        #_sign_with(key, data)*
        #_verify_with(pub, data, sig)*
    }

    class Ed25519Signer
    class EcdsaSigner
    class RsaPssSigner
    class SignerFactory {
        +create(alg)$ Signer
        +all_algorithms()$ list
    }

    class Repository {
        +save_key(key)
        +get_key(id) KeyPair
        +list_keys() list
        +save_signature(sig)
        +find_signatures_by_key(id) list
        +save_revocation(id, reason, at, n)
        +get_revocation(id) datetime
        +log_verification(...)
    }

    class TrustList {
        +int version
        +list entries
        +is_trusted(key_id, moment) bool
        +latest_in(dir)$ TrustList
    }

    class KeyRotationService {
        +int overlap_days
        +publish_initial(key_id, now)
        +rotate(old, new, now)
        +revoke_in_trust_list(key_id, at, now)
    }

    class SigningService {
        +sign_artifact(path, key_id) Signature
        +sign_manifest(manifest, key_id) Signature
    }

    class VerificationService {
        +verify_artifact(path, sig) VerificationResult
        +verify_manifest(m, sig, root) VerificationResult
        -_check_key(sig) ReasonCode
        -_log(sig, result)
    }

    class RevocationService {
        +revoke(key_id, reason, at, since) int
        +list_affected(key_id, since) list
    }

    Signer <|-- Ed25519Signer
    Signer <|-- EcdsaSigner
    Signer <|-- RsaPssSigner
    SignerFactory ..> Signer : tao ra
    Signer ..> KeyPair : sinh ra
    KeyPair --> Algorithm
    SigningService --> Repository
    SigningService ..> Signer
    SigningService ..> Signature : tao ra
    VerificationService --> Repository
    VerificationService --> TrustList
    VerificationService ..> ReasonCode
    RevocationService --> Repository
    KeyRotationService ..> TrustList
    Manifest ..> ReasonCode
```

## 3. Vì sao thiết kế như vậy

**`Signer` là lớp trừu tượng, ba thuật toán là ba lớp con.** Ba thuật toán
khác nhau hoàn toàn về toán học nhưng cùng làm ba việc: sinh khóa, ký, xác
minh. Phần khác nhau nằm ở bốn phương thức được bảo vệ; phần giống nhau
(ghi tệp khóa, đặt quyền 600, tính dấu vân tay, bắt ngoại lệ khi chữ ký
sai) viết một lần ở lớp cha.

Phép thử cho thiết kế này: thêm thuật toán thứ tư phải sửa những gì? Trả
lời: thêm một lớp con, thêm một dòng trong `SignerFactory.create`, thêm một
phần tử vào enum `Algorithm`. **Không đụng vào tầng nghiệp vụ.** Thực tế
tuần 4 thêm ECDSA và RSA-PSS vào sau Ed25519 mà `services.py` không phải
sửa dòng nào.

**`SignerFactory` là chỗ duy nhất biết tên ba lớp con.** Mọi nơi khác chỉ
cầm một đối tượng `Signer`. Nếu để `services.py` tự kiểm tra `if alg ==
"ed25519"` thì cái `if` đó sẽ nhân bản ra khắp nơi và thuật toán thứ tư
phải tìm sửa từng chỗ.

**`Repository` là giao diện, không phải SQLite.** Nhờ vậy bộ kiểm thử dùng
`Repository(db_path=":memory:")` và chạy xong không để lại tệp. Tầng nghiệp
vụ không hề biết dữ liệu nằm ở đâu.

**`TimestampService` tách riêng để bơm được thời gian giả.** Muốn kiểm tra
"khóa đã hết hạn tại thời điểm ký" mà phải chờ khóa hết hạn thật thì không
kiểm thử được. Tham số `fixed_now` làm đồng hồ đứng yên, nhờ đó ca kiểm thử
TC-10 mô phỏng được thời điểm cách hiện tại 20 ngày.

**`VerificationResult` trả về mã lý do chứ không trả `bool`.** Một hàm trả
`True`/`False` không ghi nổi nhật ký có ý nghĩa và không giúp người dùng
biết phải sửa gì. Đây là điều kiện để đạt chỉ số CS-6.

## 4. Luồng ký và luồng xác minh

```mermaid
sequenceDiagram
    autonumber
    actor Nguoi as Nguoi ky
    participant CLI as cli.py
    participant SS as SigningService
    participant Repo as Repository
    participant Sgn as Signer
    participant TS as TimestampService

    Nguoi->>CLI: dt19 sign manifest.json --key K --manifest
    CLI->>SS: sign_manifest(manifest, K)
    SS->>Repo: get_key(K)
    Repo-->>SS: KeyPair
    SS->>SS: manifest.canonical_bytes()
    SS->>Sgn: sign(data, private_key_path)
    Sgn-->>SS: chu ky (bytes)
    SS->>SS: ghi tep .sig tach roi
    SS->>TS: issue_token(sha256(data))
    TS-->>SS: token dau thoi gian
    SS->>Repo: save_signature(Signature)
    SS-->>CLI: Signature
    CLI-->>Nguoi: signature_id, kich thuoc, duong dan
```

Luồng xác minh có bốn bước kiểm tra, **thứ tự quyết định mã lý do trả về**:

```mermaid
sequenceDiagram
    autonumber
    actor Nguoi as Nguoi xac minh
    participant CLI as cli.py
    participant VS as VerificationService
    participant Repo as Repository
    participant TL as TrustList
    participant Sgn as Signer

    Nguoi->>CLI: dt19 verify manifest.json --sig S
    CLI->>VS: verify_manifest(manifest, sig, root)

    rect rgb(238, 238, 238)
        Note over VS,TL: Buoc 1-3 — khoa co dang tin tai THOI DIEM KY
        VS->>Repo: get_key(sig.key_id)
        alt khong tim thay
            VS-->>CLI: KEY_NOT_TRUSTED
        end
        VS->>Repo: get_revocation(key_id)
        alt da thu hoi truoc luc ky
            VS-->>CLI: KEY_REVOKED
        end
        VS->>TL: is_trusted(key_id, sig.signed_at)
        alt ngoai khoang hieu luc
            VS-->>CLI: KEY_EXPIRED
        end
    end

    rect rgb(238, 238, 238)
        Note over VS,Sgn: Buoc 4 — phep toan mat ma
        VS->>Sgn: verify(canonical_bytes, sig_bytes, public_pem)
        alt khong khop
            VS-->>CLI: INVALID_SIGNATURE
        end
    end

    rect rgb(238, 238, 238)
        Note over VS: Buoc 5 — dau thoi gian, roi doi chieu tung tep
        VS->>VS: check_token(timestamp_token)
        VS->>VS: manifest.verify_contents(root)
        alt tep bi sua / doi ten / bien mat
            VS-->>CLI: FILE_MODIFIED | METADATA_MODIFIED | FILE_MISSING
        end
    end

    VS->>Repo: log_verification(...)
    VS-->>CLI: SUCCESS
    CLI-->>Nguoi: [DAT] + ma ly do + thoi gian
```

**Vì sao tra trust list trước khi kiểm chữ ký.** Nếu làm ngược lại, một
khóa lạ nhưng ký đúng sẽ qua được bước mật mã rồi mới bị chặn, và thông báo
lỗi không nói được rằng vấn đề nằm ở **sự tin cậy** chứ không ở phép toán.

**Vì sao kiểm chữ ký trước dấu thời gian.** Dấu thời gian gắn với mã băm
của dữ liệu, nên mọi sửa đổi nội dung đều làm nó sai theo. Kiểm dấu thời
gian trước thì một tệp bị sửa sẽ báo `TIMESTAMP_INVALID` — đúng về mặt kỹ
thuật nhưng chỉ sai chỗ, và người dùng sẽ đi sửa nhầm thứ.
