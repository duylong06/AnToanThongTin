# Phân công và tiến độ theo tuần

> Người viết: **Long** | Tuần: **1**

## 1. Nguyên tắc chia việc

Đề bài ghi rõ: *"Cả ba phải tham gia thiết kế, thực nghiệm, phân tích và bảo
vệ; không chia tách theo kiểu một người chỉ viết báo cáo."*

Vì vậy nhóm chia theo **lát dọc**, không chia theo tầng. Mỗi người sở hữu một
nhóm chức năng từ mã nguồn, qua ca kiểm thử, đến phần lý thuyết tương ứng
trong báo cáo. Ai cũng chạm vào cả ba loại việc, nên khi bảo vệ thì ai cũng
trả lời được về phần mình.

## 2. Phân công theo người

### Nguyễn Duy Long — lõi mật mã và vòng đời khóa

Phần nhiều rủi ro kỹ thuật nhất: sai một chi tiết nhỏ là cả hệ thống mất giá
trị bảo vệ mà vẫn chạy bình thường, không báo lỗi gì.

| Hạng mục | Tệp | Tuần |
| --- | --- | --- |
| Giao diện trừu tượng `Signer` và `Ed25519Signer` | `src/dt19/signers.py` | 3 |
| `EcdsaSigner`, `RsaPssSigner`, `SignerFactory` | `src/dt19/signers.py` | 4 |
| Logic xác minh và thứ tự kiểm tra | `src/dt19/services.py` | 4–5 |
| Trust list, luân chuyển khóa có giai đoạn chồng lấn | `src/dt19/trust.py` | 5 |
| Thu hồi khóa và xử lý hậu quả | `src/dt19/services.py` | 5 |
| Dấu thời gian | `src/dt19/services.py` | 5 |
| Ca kiểm thử luân chuyển và thu hồi | `tests/test_rotation.py` | 5 |
| Mô hình đe dọa, runbook khóa bị lộ | `docs/05`, `docs/06` | 2, 5 |

**Phần lý thuyết trình bày:** mô hình chữ ký số; ECDSA và hiểm họa tái sử dụng
nonce; EdDSA và cơ chế nonce tất định; vòng đời khóa ký; **giới hạn của khái
niệm chống chối bỏ**.

### Nguyễn Quỳnh Phiêu — dữ liệu và kiểm thử âm

| Hạng mục | Tệp | Tuần |
| --- | --- | --- |
| Lớp miền, `KeyPair`, hàm băm tệp | `src/dt19/models.py` | 3 |
| Manifest và chuẩn hóa byte trước khi ký | `src/dt19/models.py` | 5 |
| Tầng lưu trữ SQLite và bản trong bộ nhớ | `src/dt19/repository.py` | 4 |
| Lược đồ cơ sở dữ liệu | `data/schema.sql` | 2 |
| Nhật ký xác minh chỉ ghi thêm | `src/dt19/services.py` | 4 |
| Toàn bộ ca kiểm thử âm | `tests/test_tamper.py` | 5 |
| Sơ đồ ERD và sơ đồ lớp | `docs/02`, `docs/03` | 2 |

**Phần lý thuyết trình bày:** tính toàn vẹn; hàm băm SHA-256; vì sao phải
chuẩn hóa byte trước khi ký; manifest và provenance.

### Trương Hồng Uyên — đo lường và hồ sơ

| Hạng mục | Tệp | Tuần |
| --- | --- | --- |
| Dựng kho mã, quy trình kiểm tra tự động | `.github/workflows/ci.yml` | 1 |
| Kế hoạch kiểm thử và baseline | `docs/04` | 2 |
| Ca kiểm thử dương | `tests/test_positive.py` | 3 |
| Giao diện dòng lệnh và ca kiểm thử dòng lệnh | `src/dt19/cli.py`, `tests/test_cli.py` | 4 |
| Bộ đo hiệu năng, xuất CSV | `src/dt19/services.py` | 5 |
| Biểu đồ và bảng kết quả | `results/`, `docs/07` | 5 |
| Bảng truy vết, sườn báo cáo, trình chiếu | `results/traceability.csv`, `docs/09` | 6 |

**Phần lý thuyết trình bày:** RSA-PSS và vai trò của đệm; tính bất đối xứng
giữa ký và xác minh; phương pháp đo và vì sao dùng trung vị thay vì trung bình.

## 3. Tiến độ 7 tuần

Cột cuối là thứ phải có mặt trong kho mã vào cuối tuần đó. Không có nghĩa là
tuần đó chưa xong.

| Tuần | Long | Phiêu | Uyên | Minh chứng cuối tuần |
| --- | --- | --- | --- | --- |
| **1** | Viết đề cương, nộp thầy duyệt | Dựng cây thư mục, `.gitignore` | Quy trình kiểm tra tự động, mời thành viên | `docs/00` có chữ ký duyệt |
| **2** | Mô hình đe dọa, chốt thứ tự kiểm tra | Sơ đồ lớp, ERD, `schema.sql` | Kế hoạch kiểm thử, baseline | `docs/02`–`docs/05` |
| **3** | `Signer` và `Ed25519Signer` | `models.py`, hàm băm | Ca kiểm thử dương cho Ed25519 | Ký rồi xác minh chạy thông |
| **4** | Thêm ECDSA và RSA-PSS | `repository.py` | `cli.py` | Ba thuật toán cùng chạy |
| **5** | Trust list, luân chuyển, thu hồi | Manifest, 6 ca kiểm thử âm | Benchmark, biểu đồ | `bench.csv`, `test_tamper.py` xanh |
| **6** | Thảo luận, giới hạn, kết luận | Phần toàn vẹn và kiểm thử | Bảng truy vết, bảng công khai AI | Báo cáo đủ 25–35 trang |
| **7** | Sửa theo góp ý | Chạy lại trên máy khác | Tập bảo vệ | Hồ sơ nộp hoàn chỉnh |

## 4. Quy ước commit

Để lịch sử commit thể hiện được đóng góp của từng người:

- Mỗi người commit bằng tài khoản GitHub của chính mình. Không ai commit hộ ai.
- Thông điệp gắn với yêu cầu: `[FR-06] Them ky artifact bang Ed25519`.
- Commit nhỏ và thường xuyên, đừng dồn cả tuần vào một commit lớn.
- Mã mới phải kèm ca kiểm thử trong cùng commit hoặc commit kế tiếp.
- Không commit khóa riêng.

## 5. Họp cuối tuần

Mỗi tuần họp ngắn, trả lời ba câu và ghi biên bản vào `docs/bien-ban/`:

1. Tuần này có minh chứng nào mới vào kho mã chưa?
2. Có ca kiểm thử nào đang trượt mà chưa ai nhận xử lý không?
3. Ai đang bị kẹt, cần ai hỗ trợ?

Biên bản cũng là bằng chứng đóng góp khi bảo vệ.
