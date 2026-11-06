# Đặc tả yêu cầu phần mềm

> Người viết: **Long và Phiêu** | Tuần: **1–2**

## 1. Mục đích và phạm vi

`sigtool` là công cụ dòng lệnh ký và xác minh artifact bằng ba cơ chế chữ ký
số, phục vụ hai mục đích của đề tài 19: **đo** khác biệt giữa ba cơ chế, và
**chứng minh** rằng mọi thay đổi trên nội dung hoặc metadata được bảo vệ đều
làm xác minh thất bại, kèm mã lý do phân biệt được nguyên nhân.

**Trong phạm vi:** sinh và quản lý vòng đời khóa thử nghiệm; lập manifest có
phiên bản; ký và xác minh cả artifact đơn lẻ lẫn manifest bằng chữ ký tách
rời; gắn và kiểm dấu thời gian; danh sách khóa tin cậy theo phiên bản; luân
chuyển khóa có giai đoạn chồng lấn; thu hồi khóa và liệt kê artifact bị ảnh
hưởng; đo hiệu năng và xuất dữ liệu thô.

**Ngoài phạm vi:** hạ tầng khóa công khai đầy đủ với CA gốc và CA trung gian
(đó là đề tài 20); giao diện đồ họa; dịch vụ dấu thời gian đạt chuẩn RFC 3161
của bên thứ ba; ký phần mềm thật bằng danh tính của bất kỳ tổ chức nào.

## 2. Tác nhân

| Tác nhân | Mô tả | Quan tâm điều gì |
| --- | --- | --- |
| **Người ký** | Giữ khóa riêng, phát hành artifact | Ký nhanh, không để lộ khóa riêng |
| **Người xác minh** | Nhận artifact qua kênh không tin cậy | Biết artifact có nguyên vẹn không, và nếu không thì **vì sao** |
| **Người vận hành khóa** | Xử lý sự cố khóa bị lộ | Dừng ký nhanh, biết artifact nào bị ảnh hưởng |
| **Kẻ tấn công** | Có quyền sửa tệp trên kênh truyền, thấy khóa công khai | Xem `docs/05` mục 2 để biết giả định năng lực |

## 3. Yêu cầu chức năng (FR-01 …)

### Quản lý khóa

| Mã | Yêu cầu | Minh chứng |
| --- | --- | --- |
| FR-01 | Sinh cặp khóa cho ba thuật toán Ed25519, ECDSA P-256, RSA-PSS 2048 | TC-01, TC-34 |
| FR-02 | Định danh khóa sinh từ chính khóa công khai (SHA-256 của PEM) | `signers._fingerprint` |
| FR-03 | Khóa riêng ghi ra đĩa với quyền 600, không lưu nội dung vào CSDL | TC-34, NFR-04 |
| FR-04 | Liệt kê khóa kèm trạng thái và chủ sở hữu | lệnh `keys` |

### Manifest và ký

| Mã | Yêu cầu | Minh chứng |
| --- | --- | --- |
| FR-05 | Lập manifest có phiên bản, định danh và mã băm từng tệp | TC-03, TC-37 |
| FR-06 | Ký artifact đơn lẻ | TC-01, TC-35 |
| FR-07 | Ký manifest bằng chuỗi byte chuẩn hóa ổn định | TC-02, TC-04 |
| FR-08 | Gắn dấu thời gian vào chữ ký | TC-15 |
| FR-09 | Chữ ký tách rời, không sửa artifact gốc | `SigningService._sign_bytes` |

### Xác minh

| Mã | Yêu cầu | Minh chứng |
| --- | --- | --- |
| FR-10 | Xác minh artifact và manifest | TC-01, TC-02 |
| FR-11 | Trả mã lý do riêng cho từng loại sai lệch | mục 5, TC-08 đến TC-15 |
| FR-12 | Phát hiện sửa nội dung, đổi tên, thêm bớt tệp | TC-08, TC-10, TC-11, TC-12 |
| FR-13 | Ghi nhật ký xác minh chỉ cho phép ghi thêm | TC-06 |
| FR-14 | Trả mã thoát phân biệt lỗi tham số với xác minh trượt | TC-35, TC-36, TC-41 |

### Vòng đời khóa

| Mã | Yêu cầu | Minh chứng |
| --- | --- | --- |
| FR-15 | Trust list có phiên bản, xét hiệu lực theo **thời điểm ký** | TC-16, TC-17 |
| FR-16 | Luân chuyển khóa có giai đoạn chồng lấn cấu hình được | TC-16, TC-17 |
| FR-17 | Thu hồi khóa, cắt hiệu lực tại mốc nghi ngờ bị lộ | TC-13, TC-18 |
| FR-18 | Liệt kê và đếm artifact bị ảnh hưởng khi khóa bị lộ | TC-19, TC-39 |
| FR-19 | Ký lại artifact bị ảnh hưởng bằng khóa mới | lệnh `resign` |

### Đo lường

| Mã | Yêu cầu | Minh chứng |
| --- | --- | --- |
| FR-20 | Đo thời gian ký và xác minh, tối thiểu 100 lần lặp | TC-24, TC-25 |
| FR-21 | Xuất dữ liệu thô từng lần đo ra CSV | TC-29 |

## 4. Yêu cầu phi chức năng (NFR-01 …)

| Mã | Yêu cầu | Ngưỡng hoặc cách kiểm |
| --- | --- | --- |
| NFR-01 | Xác minh tệp 1 MB dưới 50 ms | CS-1: đo được 1,87 ms |
| NFR-02 | Phép đo tái lập được | seed cố định, đồng hồ cố định, dữ liệu thô kèm theo |
| NFR-03 | Không tự cài đặt lại thuật toán mật mã | mọi phép toán gọi qua `cryptography` |
| NFR-04 | Khóa riêng không bao giờ vào CSDL hay nhật ký | chỉ lưu `private_key_path` |
| NFR-05 | Nhật ký xác minh chỉ ghi thêm | mở tệp chế độ `a`, bảng không có hàm sửa |
| NFR-06 | Khóa riêng không bao giờ lọt vào kho mã | `.gitignore` chặn, CI kiểm tra tự động |
| NFR-07 | Độ phủ kiểm thử từ 70% | CS-5: đạt 86% |
| NFR-08 | Mọi ca kiểm thử phải gọi vào `src/dt19/` | quy ước nhóm, xem `docs/04` mục 1 |
| NFR-09 | Chạy được trên Python 3.11 trở lên | CI chạy trên nhiều phiên bản |
| NFR-10 | Thông điệp lỗi bằng tiếng Việt, nói rõ phải làm gì | bảng `MESSAGES_VI` |
| NFR-11 | Kho mã sạch sau khi chạy kiểm thử | CSDL `:memory:`, tệp trong `tmp_path` |
| NFR-12 | Mọi tài liệu nêu rõ giới hạn, không giấu điểm yếu | `docs/05` mục 4, `docs/07` mục 6 |

## 5. Bảng mã lý do thất bại

> Chốt tại PR `feature/long-crypto-core`. Tên mã giữ đúng bảng Phiêu đã đặt
> trong `models.py`; ba mã cuối là phần Long bổ sung vì đề bài yêu cầu phân
> biệt được vòng đời khóa và dấu thời gian. **Không ai tự thêm hay đổi tên
> mã sau khi PR này merge mà không báo nhóm** — đây là hợp đồng chung giữa
> mã nguồn, kế hoạch kiểm thử và bảng nhật ký.

| Mã | Ý nghĩa | Phát hiện ở bước nào | Người dùng nên làm gì |
| --- | --- | --- | --- |
| `SUCCESS` | Xác minh đạt | — | Dùng được |
| `KEY_NOT_TRUSTED` | Khóa ký không có trong danh sách tin cậy | Tra trust list | Đặt câu hỏi ai đã ký thứ này |
| `KEY_REVOKED` | Khóa đã bị thu hồi tại thời điểm ký | Tra bảng `revocations` | Không dùng; chờ bản ký lại bằng khóa mới |
| `KEY_EXPIRED` | Khóa hết hiệu lực tại thời điểm ký, hoặc quá giai đoạn chồng lấn | Tra trust list theo `signed_at` | Cập nhật trust list phiên bản mới |
| `INVALID_SIGNATURE` | Chữ ký không khớp dữ liệu đã ký | Phép xác minh mật mã | Tải lại artifact từ nguồn gốc |
| `MANIFEST_TAMPERED` | Manifest bị can thiệp | Xác minh chữ ký manifest | Không tin bộ phát hành này |
| `FILE_MODIFIED` | Tệp còn trên đĩa nhưng nội dung đã khác | Đối chiếu mã băm | Tải lại đúng tệp đó |
| `FILE_MISSING` | Tệp ghi trong manifest không còn trên đĩa | Đối chiếu mã băm | Tải lại bộ phát hành |
| `METADATA_MODIFIED` | Nội dung nguyên vẹn nhưng tệp bị đổi tên | Tìm tệp cùng mã băm trong thư mục | Kiểm tra có bị tráo tên không |
| `TIMESTAMP_INVALID` | Chữ ký đúng nhưng dấu thời gian không kiểm chứng được | Kiểm token HMAC | Xem lại nguồn gốc dấu thời gian |
| `UNKNOWN_ERROR` | Lỗi ngoài các trường hợp trên | — | Báo nhóm phát triển |

**Thứ tự kiểm tra quyết định mã trả về.** Khi một chữ ký sai nhiều thứ cùng
lúc, công cụ trả mã của lỗi gặp đầu tiên theo thứ tự: khóa trước, chữ ký
giữa, dấu thời gian sau. Ví dụ tệp vừa bị sửa vừa ký bằng khóa đã thu hồi
thì trả `KEY_REVOKED`, vì không đáng tin về nguồn gốc là vấn đề nặng hơn.

Chỉ số CS-6 trong đề cương đặt ngưỡng tối thiểu bốn loại sai lệch phân biệt
được. Bảng này có mười mã thất bại, trong đó bảy mã đã có ca kiểm thử.

## 6. Giả định và rủi ro

**Giả định**

- Toàn bộ dữ liệu là giả lập, do nhóm tự sinh bằng script có seed cố định.
- Khóa thử nghiệm chỉ dùng cho đồ án, không ký phần mềm thật.
- Người xác minh nhận được trust list qua một kênh đáng tin. Đây là giả
  định **mạnh** và là rủi ro còn lại lớn nhất, xem bên dưới.
- Máy chạy công cụ chưa bị xâm nhập ở mức đọc được bộ nhớ tiến trình.

**Rủi ro còn lại**

| Rủi ro | Vì sao chấp nhận | Điều kiện xét lại |
| --- | --- | --- |
| Trust list không được ký | Đề tài tập trung vào cơ chế chữ ký, không dựng PKI đầy đủ | Mở rộng sang đề tài 20 thì phải có khóa gốc giữ ngoại tuyến |
| Dấu thời gian giả lập | Không có TSA chuẩn RFC 3161 trong phạm vi đồ án | Nêu rõ ở mọi kết quả liên quan |
| Khóa riêng không mã hóa bằng mật khẩu | Khóa thử nghiệm | Dùng thật thì bắt buộc mã hóa |
| Quyền tệp 600 không áp dụng trên Windows | Hạn chế hệ điều hành | Ghi chú trong README |
| Chưa chống tấn công kênh kề | Cần HSM, ngoài phạm vi | — |
