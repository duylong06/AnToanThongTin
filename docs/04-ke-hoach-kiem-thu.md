# Kế hoạch kiểm thử

> Người viết: **Uyên** | Tuần: **2**, cập nhật khi mã hoàn thiện

## 1. Nguyên tắc

**Kết quả mong đợi phải viết TRƯỚC khi chạy.** Viết sau là tự huyễn hoặc:
nhìn thấy công cụ trả về `FILE_MODIFIED` rồi mới ghi "mong đợi
FILE_MODIFIED" thì ca kiểm thử không kiểm chứng điều gì cả, nó chỉ chép lại
hành vi hiện tại kể cả khi hành vi đó sai.

**Mỗi ca phải gọi vào `src/dt19/`.** Đây là quy ước nhóm thống nhất sau khi
rà soát giữa kỳ. Ca kiểm thử nào chỉ gán sẵn một biến rồi kiểm tra chính
biến đó thì không tính là minh chứng, vì xóa sạch mã nguồn nó vẫn xanh.

Ví dụ ca **không hợp lệ**:

```python
is_signature_valid = False
reason = ReasonCode.SUCCESS if is_signature_valid else ReasonCode.INVALID_SIGNATURE
assert reason == ReasonCode.INVALID_SIGNATURE     # luôn đúng, vô nghĩa
```

Ca **hợp lệ** cho cùng kịch bản: ký thật bằng `SigningService`, sửa tệp
thật trên đĩa, gọi `VerificationService.verify_manifest` rồi kiểm tra mã lý
do trả về.

**Ca âm quan trọng hơn ca dương.** Ca dương chứng minh công cụ chạy được
trong điều kiện thuận lợi. Ca âm chứng minh nó phát hiện được giả mạo —
đúng thứ đề tài cần trả lời. Nhưng vẫn phải có ca dương làm mốc so sánh,
nếu không thì một hệ thống hỏng hoàn toàn cũng "trượt" ở mọi ca âm và trông
như đang hoạt động đúng.

**Đồng hồ phải cố định.** Mọi ca liên quan tới hạn hiệu lực dùng
`TimestampService(fixed_now=NOW)` với `NOW = 2026-10-01 09:00`. Lấy thời
gian thật thì ca kiểm thử đổi kết quả theo ngày chạy.

**Không để lại rác.** Cơ sở dữ liệu chạy ở `:memory:`, tệp sinh ra nằm
trong `tmp_path` của pytest. Chạy xong kho mã phải sạch như trước.

## 2. Danh sách ca kiểm thử

### 2.1. Ca dương — `tests/test_positive.py` (Uyên)

| Mã | Ca | Các bước | Kết quả mong đợi |
| --- | --- | --- | --- |
| TC-01 | Ký rồi xác minh artifact, cả ba thuật toán | sinh khóa → ký `app.bin` → xác minh | `SUCCESS` |
| TC-02 | Ký rồi xác minh manifest, cả ba thuật toán | lập manifest 2 tệp → ký → xác minh | `SUCCESS` |
| TC-03 | Lập manifest bằng cách băm tệp thật | `add_path()` trên tệp trên đĩa | mã băm khớp `sha256_file`, dài 64 ký tự |
| TC-04 | Chuỗi byte chuẩn hóa ổn định | chèn hai mục theo hai thứ tự khác nhau | `canonical_bytes()` giống hệt nhau |
| TC-05 | Kích thước chữ ký đúng lý thuyết | ký bằng từng thuật toán | Ed25519 = 64 B; ECDSA 68–72 B; RSA-PSS = 256 B |
| TC-06 | Nhật ký chỉ ghi thêm | xác minh ba lần | đúng 3 dòng trong `verify_log.jsonl`, không sửa dòng cũ |

### 2.2. Ca âm — `tests/test_tamper.py` (Phiêu)

| Mã | Ca | Phá cái gì | Kết quả mong đợi |
| --- | --- | --- | --- |
| TC-07 | Mốc so sánh | không phá gì | `SUCCESS` |
| TC-08 | Sửa nội dung tệp | lật một bit trong `app.bin` | `FILE_MODIFIED`, chi tiết nêu tên tệp |
| TC-09 | Xóa tệp | chuyển tệp ra ngoài thư mục | `FILE_MISSING` |
| TC-10 | Đổi tên tệp | đổi tên, giữ nguyên nội dung | `METADATA_MODIFIED`, nêu tên mới |
| TC-11 | Thêm mục vào manifest | thêm một tệp lạ vào danh sách | `INVALID_SIGNATURE` |
| TC-12 | Bớt mục khỏi manifest | gỡ một tệp khỏi danh sách | `INVALID_SIGNATURE` |
| TC-13 | Khóa đã bị thu hồi | thu hồi với mốc trước lúc ký | `KEY_REVOKED` |
| TC-14 | Tráo tệp chữ ký | ghi đè bằng chữ ký của khóa khác | `INVALID_SIGNATURE` |
| TC-15 | Sửa token dấu thời gian | thay phần HMAC | `TIMESTAMP_INVALID` |

TC-10 và TC-09 là cặp dễ nhầm. Phân biệt được chúng là điểm đáng nói: công
cụ tìm trong thư mục xem có tệp nào cùng mã băm không, có thì kết luận bị
đổi tên chứ không phải bị mất.

### 2.3. Vòng đời khóa — `tests/test_rotation.py` (Long)

| Mã | Ca | Các bước | Kết quả mong đợi |
| --- | --- | --- | --- |
| TC-16 | Trong giai đoạn chồng lấn | ký bằng khóa cũ → luân chuyển → xác minh | `SUCCESS` |
| TC-17 | Sau giai đoạn chồng lấn | luân chuyển → ký ở ngày thứ 20 → xác minh | `KEY_EXPIRED` |
| TC-18 | Chữ ký sau mốc thu hồi | ký → thu hồi với mốc trước đó → xác minh | `KEY_REVOKED` |
| TC-19 | Đếm chữ ký bị ảnh hưởng | ký 2 bằng khóa A, 1 bằng khóa B → thu hồi A | đúng 2, trạng thái A là `REVOKED` |
| TC-20 | Khóa lạ | ký bằng khóa không có trong trust list | `KEY_NOT_TRUSTED` |
| TC-21 | Thu hồi không rõ mốc lộ | bỏ trống `suspected_since` | coi **mọi** chữ ký là đáng ngờ |
| TC-22 | Nonce tất định của Ed25519 | ký cùng dữ liệu hai lần | hai chữ ký **giống hệt**, 64 byte |
| TC-23 | Nonce ngẫu nhiên của ECDSA và RSA-PSS | ký cùng dữ liệu hai lần | hai chữ ký **khác nhau**, cả hai đều xác minh đúng |

TC-22 và TC-23 là cặp đối chứng cho phần lý thuyết về nonce. Chúng biến một
đoạn lý thuyết trong bài giảng thành thứ chạy được và nhìn thấy được.

### 2.4. Đo hiệu năng — `tests/test_benchmark.py` (Uyên)

| Mã | Ca | Kết quả mong đợi |
| --- | --- | --- |
| TC-24 | Chạy đo và trả đủ trường thống kê | có `median_sign_ms`, `p95_sign_ms` |
| TC-25 | **Số đo phải là số thật** | 20 lần đo không được giống hệt nhau, mọi giá trị > 0 |
| TC-26 | Kích thước chữ ký theo thuật toán | Ed25519 = 64 B < RSA-PSS = 256 B |
| TC-27 | Thứ tự tốc độ ký | RSA-PSS chậm hơn Ed25519 |
| TC-28 | Tính đúng của thống kê | phân vị 95 ≥ trung vị |
| TC-29 | Xuất CSV | có cả tệp tổng hợp và tệp dữ liệu thô, mỗi lần lặp một dòng |

TC-25 là chốt chặn do nhóm thêm vào sau khi phát hiện bản benchmark đầu
tiên chạy trên dữ liệu giả. Nếu ai đó thay vòng đo bằng hằng số, phương sai
bằng 0 và ca này đỏ ngay.

### 2.5. Dòng lệnh — `tests/test_cli.py` (Uyên)

| Mã | Ca | Kết quả mong đợi |
| --- | --- | --- |
| TC-30 | Phân tích tham số `keygen`, `sign` | đúng lệnh và tham số |
| TC-31 | Thuật toán lạ | bị chặn ngay ở bước phân tích tham số |
| TC-32 | Gọi trần không tham số | in hướng dẫn, mã thoát 0 |
| TC-33 | `init` | tạo được `data/sigtool.db` |
| TC-34 | `keygen` | sinh tệp khóa riêng, khóa công khai và `trust_list_v1.json` |
| TC-35 | Ký rồi xác minh qua dòng lệnh | in `[ĐẠT]`, mã thoát **0** |
| TC-36 | Sửa tệp rồi xác minh | in `[TRƯỢT]`, mã thoát **1** |
| TC-37 | Lập manifest rồi ký cả bộ | xác minh đạt |
| TC-38 | Thu hồi rồi xác minh | `KEY_REVOKED`, mã thoát 1 |
| TC-39 | `affected` | liệt kê đúng 2 chữ ký |
| TC-40 | Thu hồi không rõ mốc lộ rồi xác minh | chữ ký cũ cũng bị từ chối (ca hồi quy) |
| TC-41 | Chữ ký không tồn tại | mã thoát **2**, không phải 1 |

Ba mã thoát khác nhau để script tự động phân biệt được "xác minh trượt"
với "gọi sai lệnh". Gộp cả hai thành mã 1 thì hệ thống tích hợp liên tục
không biết nên báo hỏng hay báo phát hiện giả mạo.

### 2.6. Lớp miền và lưu trữ — `tests/test_phieu_models_repo.py` (Phiêu)

| Mã | Ca | Kết quả mong đợi |
| --- | --- | --- |
| TC-42 | Ánh xạ mã lý do | giá trị enum đúng chuỗi |
| TC-43 | Thao tác Manifest | thêm tệp, chuyển đổi qua lại với dict |
| TC-44 | Lưu trữ SQLite trong bộ nhớ | lưu và đọc lại `KeyPair`, ghi được nhật ký |

## 3. Chỉ số cần đạt

| Mã | Chỉ số | Ngưỡng | Cách kiểm | Kết quả |
| --- | --- | --- | --- | --- |
| CS-1 | Thời gian xác minh tệp 1 MB | dưới 50 ms | `results/bench.csv` | **1,87 ms** (Ed25519) — đạt |
| CS-2 | Kích thước chữ ký và khóa | ghi nhận | `results/bench.csv` | 64 / 71 / 256 byte |
| CS-3 | Số lần lặp mỗi phép đo | tối thiểu 100 | số dòng `bench_raw.csv` | **300 dòng** / 3 thuật toán — đạt |
| CS-4 | Tỷ lệ ca kiểm thử đạt | 100% | `pytest` | **54/54** — đạt |
| CS-5 | Độ phủ mã | từ 70% | `pytest --cov` | **86%** — đạt |
| CS-6 | Số loại sai lệch phân biệt được | tối thiểu 4 | `results/bang_ma_ly_do.csv` | **6 mã riêng** — đạt |
| CS-7 | Thời gian từ phát hiện tới dừng ký | dưới 15 phút | `docs/06` và bảng `revocations` | một lệnh `revoke`, dưới 1 phút — đạt |

## 4. Bảng truy vết minh chứng

Bảng đầy đủ ở `results/traceability.csv`. Nguyên tắc: mỗi yêu cầu chức năng
phải chỉ ra được ít nhất một ca kiểm thử chứng minh nó hoạt động, và mỗi ca
kiểm thử phải gắn với ít nhất một yêu cầu. Yêu cầu nào không có ca nào trỏ
tới thì hoặc là thừa, hoặc là chưa làm.

## 5. Cách chạy lại toàn bộ

```bash
pytest -q --cov=src/dt19 --cov-report=term-missing   # 54 ca, độ phủ 86%
python scripts/sinh_minh_chung.py                    # 6 kịch bản xác minh
python -m dt19 bench --iterations 100 --size 1048576 --out results/bench.csv
python -m dt19 bench --iterations 100 --size 1024    --out results/bench_1kb.csv
```
