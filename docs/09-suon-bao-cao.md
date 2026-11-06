# Sườn báo cáo

> Người viết: **Uyên** | Tuần: **6**

Báo cáo 25–35 trang không tính phụ lục, trích dẫn theo chuẩn IEEE. Cột
"Nguồn" chỉ ra tài liệu hoặc tệp đã có sẵn trong kho mã — phần lớn nội dung
chỉ cần biên tập lại chứ không phải viết mới.

**Nguyên tắc chia việc:** ai viết mã phần nào thì viết lý thuyết phần đó.
Đề bài cấm kiểu một người chỉ viết báo cáo.

## Phân bổ trang và người viết

| Mục | Nội dung | Trang | Người viết | Nguồn sẵn có |
| --- | --- | ---: | --- | --- |
| **1** | **Mở đầu** | **3** | | |
| 1.1 | Bối cảnh: vì sao cần ký số cho phần mềm và tài liệu | 1 | Long | CH4 bài giảng |
| 1.2 | Ba câu hỏi nghiên cứu CH1, CH2, CH3 | 1 | Long | `docs/00` mục 2 |
| 1.3 | Phạm vi, giả định, điều nhóm không làm | 1 | Long | `docs/01` mục 1 và 6 |
| **2** | **Cơ sở lý thuyết** | **7** | | |
| 2.1 | Dịch vụ an toàn cốt lõi: bí mật, toàn vẹn, xác thực, chống chối bỏ | 1 | Phiêu | CH4 |
| 2.2 | Hàm băm SHA-256, ba tính chất an toàn, hiệu ứng tuyết lở | 1,5 | Phiêu | CH4 |
| 2.3 | Mô hình tổng quát của chữ ký số: ba thuật giải | 1 | Long | CH4 |
| 2.4 | RSA-PSS và vai trò của đệm, vì sao RSA thô không an toàn | 1,5 | Uyên | CH4 |
| 2.5 | ECDSA và hiểm họa tái sử dụng nonce `k` | 1 | Long | CH4 |
| 2.6 | EdDSA và cơ chế nonce tất định `k = H(prefix ‖ M)` | 1 | Long | CH4 |
| **3** | **Phân tích và thiết kế** | **7** | | |
| 3.1 | Đặc tả yêu cầu: 21 FR, 12 NFR | 1,5 | Long | `docs/01` |
| 3.2 | Bảng mã lý do và thứ tự kiểm tra | 1 | Long | `docs/01` mục 5 |
| 3.3 | Kiến trúc bốn tầng và lý do tách tầng | 1,5 | Phiêu | `docs/03` mục 1 và 3 |
| 3.4 | Sơ đồ lớp, giao diện `Signer` trừu tượng | 1,5 | Phiêu | `docs/03` mục 2 |
| 3.5 | Mô hình dữ liệu, sơ đồ ERD, ràng buộc toàn vẹn | 1,5 | Phiêu | `docs/02` |
| **4** | **Mô hình đe dọa** | **4** | | |
| 4.1 | Tài sản, luồng dữ liệu, hai ranh giới tin cậy | 1,5 | Long | `docs/05` mục 1 và 2 |
| 4.2 | Phân tích STRIDE và biện pháp đối ứng | 1,5 | Long | `docs/05` mục 3 |
| 4.3 | **Điều công cụ không bảo vệ được** | 1 | Long | `docs/05` mục 4 |
| **5** | **Triển khai** | **4** | | |
| 5.1 | Vòng ký và vòng xác minh, biểu đồ trình tự | 1,5 | Long | `docs/03` mục 4 |
| 5.2 | Vòng đời khóa: luân chuyển, chồng lấn, thu hồi | 1,5 | Long | `trust.py`, `docs/06` |
| 5.3 | Giao diện dòng lệnh và ba mã thoát | 1 | Uyên | `cli.py`, `docs/04` 2.5 |
| **6** | **Thực nghiệm và đánh giá** | **7** | | |
| 6.1 | Phương pháp đo, vì sao trung vị thay vì trung bình | 1 | Uyên | `docs/07` mục 1 |
| 6.2 | Kết quả đo ba thuật toán, biểu đồ | 2 | Uyên | `docs/07` mục 2 |
| 6.3 | Phân tích: bất đối xứng của RSA, chi phí băm tách riêng | 2 | Uyên | `docs/07` mục 3 |
| 6.4 | Kết quả kiểm thử âm, sáu mã lý do phân biệt được | 1,5 | Phiêu | `docs/07` mục 5 |
| 6.5 | Đối chiếu bảy chỉ số CS-1 đến CS-7 | 0,5 | Uyên | `docs/07` mục 4 |
| **7** | **Thảo luận** | **3** | | |
| 7.1 | Nên chọn thuật toán nào trong tình huống nào | 1 | Uyên | `docs/07` mục 3 |
| 7.2 | **Giới hạn của khái niệm chống chối bỏ** | 1 | Long | `docs/05` mục 4 |
| 7.3 | Rủi ro còn lại và hướng mở rộng sang PKI | 1 | Long | `docs/01` mục 6 |
| **8** | **Kết luận** | **1** | Cả ba | |
| | **Tài liệu tham khảo** (IEEE) | 1 | Uyên | |
| | **Tổng** | **~36** | | |

Nếu vượt 35 trang thì cắt ở mục 2 trước, vì phần lý thuyết dễ trùng với bài
giảng nhất. Không cắt mục 4.3 và 7.2 — đó là hai mục ăn điểm nhất.

## Phụ lục

| Phụ lục | Nội dung | Nguồn |
| --- | --- | --- |
| A | Bộ artifact gốc và bản bị sửa | `artifacts/` |
| B | Khóa thử nghiệm và dấu vân tay công khai | `keys/*/*.public.pem` |
| C | Nhật ký xác minh đầy đủ | `results/verify_log.jsonl` |
| D | Dữ liệu đo thô, 300 dòng mỗi kích thước | `results/bench_raw.csv` |
| E | Bảng truy vết minh chứng | `results/traceability.csv` |
| F | Runbook xử lý khóa bị lộ | `docs/06` |
| G | **Bảng công khai sử dụng công cụ AI** | README |

## Ba điều cần tránh khi viết

**Đừng chép lại bài giảng.** Mục 2 phải nối lý thuyết với mã nguồn của
nhóm. Ví dụ không viết chung chung "EdDSA dùng nonce tất định", mà viết:
"EdDSA dùng nonce tất định, và điều này quan sát được trực tiếp — ca kiểm
thử TC-22 ký cùng một dữ liệu hai lần bằng Ed25519 và nhận về hai chữ ký
giống hệt nhau, trong khi TC-23 làm điều tương tự với ECDSA và nhận hai chữ
ký khác nhau."

**Đừng giấu điểm yếu.** Mục 4.3 và 7.2 nói thẳng công cụ không bảo vệ được
gì. Nêu rõ giới hạn thì được điểm, giấu đi mà thầy hỏi ra thì mất.

**Mỗi con số phải chỉ được ra nguồn.** Viết "1,87 ms" thì phải nói ngay là
lấy từ `results/bench.csv`, đo trên máy nào, lặp bao nhiêu lần. Con số
không có nguồn là con số không kiểm chứng được.
