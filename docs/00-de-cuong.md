# Phiếu đề cương đồ án — nộp tuần 1

> Người viết: **Long** | Tuần: **1**

**Học phần:** An toàn thông tin (123033) — TS. Lê Quốc Tuấn
**Đề tài 19:** Đánh giá chữ ký số cho phần mềm và tài liệu điện tử
**Bám sát mục:** 4.5, 4.7, 4.8 và 4.9.3 — **Mức độ:** Khá — **Thời lượng:** 7 tuần
**Kho mã:** https://github.com/duylong06/AnToanThongTin

## 1. Thành viên và phân công

| | Họ và tên | MSSV | Vai trò | Phần chịu trách nhiệm |
| --- | --- | --- | --- | --- |
| 1 | **Nguyễn Duy Long** | 060206005525 | Nhóm trưởng, phụ trách kỹ thuật | Lõi mật mã, logic xác minh, vòng đời khóa |
| 2 | Nguyễn Quỳnh Phiêu | *(điền)* | Thành viên | Lớp miền, manifest, lưu trữ, kiểm thử âm |
| 3 | Trương Hồng Uyên | *(điền)* | Thành viên | Dòng lệnh, đo lường, biểu đồ, hồ sơ báo cáo |

Cả ba cùng tham gia thiết kế, thực nghiệm, phân tích và bảo vệ. Nhóm chia việc
theo lát dọc: mỗi người sở hữu một nhóm chức năng từ mã nguồn, qua kiểm thử,
đến phần lý thuyết tương ứng trong báo cáo. Chi tiết theo tuần ở
`docs/08-phan-cong-va-tien-do.md`.

## 2. Câu hỏi nghiên cứu

Nhóm đặt ba câu hỏi. Mỗi câu phải trả lời được bằng số liệu đo hoặc bằng ca
kiểm thử, không trả lời bằng nhận định suông.

**CH1. Ba thuật toán RSA-PSS, ECDSA và Ed25519 khác nhau thế nào về kích thước
chữ ký, tốc độ ký, tốc độ xác minh và yêu cầu nonce?**
Trả lời bằng phép đo lặp tối thiểu 100 lần, thực hiện ở hai kích thước dữ liệu
khác nhau để tách chi phí băm khỏi chi phí mật mã.

**CH2. Mọi thay đổi trên nội dung hoặc metadata được bảo vệ có thực sự làm xác
minh thất bại không, và công cụ có phân biệt được nguyên nhân không?**
Trả lời bằng bộ ca kiểm thử âm, mỗi loại sai lệch trả về một mã lý do riêng
chứ không gộp chung thành "sai".

**CH3. Khi khóa ký bị lộ thì xử lý ra sao, và quy trình đó đo được bằng chỉ số
nào?**
Trả lời bằng kịch bản mô phỏng thu hồi khóa và một runbook có chỉ số thời gian.

## 3. Phạm vi

**Nhóm làm:**

- Sinh, lưu trữ và quản lý vòng đời khóa thử nghiệm cho ba thuật toán.
- Tạo manifest có phiên bản và định danh khóa ký.
- Ký và xác minh cả artifact đơn lẻ lẫn manifest, dùng chữ ký tách rời.
- Gắn và kiểm tra dấu thời gian.
- Danh sách khóa tin cậy theo phiên bản; luân chuyển khóa có giai đoạn chồng lấn.
- Thu hồi khóa, liệt kê artifact bị ảnh hưởng, ký lại.
- Đo hiệu năng và xuất dữ liệu thô dạng CSV.

**Nhóm không làm:**

- Hạ tầng khóa công khai đầy đủ với CA gốc và CA trung gian — đó là đề tài 20.
- Giao diện đồ họa. Công cụ chạy bằng dòng lệnh.
- Dịch vụ dấu thời gian đạt chuẩn RFC 3161 của bên thứ ba. Nhóm mô phỏng cục
  bộ và nêu rõ đây là giả lập, không có giá trị trước bên thứ ba.
- Ký phần mềm thật bằng danh tính hoặc chứng thư của bất kỳ tổ chức nào.

## 4. Kiến trúc

Công cụ dòng lệnh viết bằng Python, chia ba tầng, phụ thuộc chỉ đi một chiều
từ trên xuống:

| Tầng | Thành phần | Trách nhiệm |
| --- | --- | --- |
| Giao diện | `cli.py` | Phân tích tham số, in kết quả, trả mã thoát |
| Nghiệp vụ | `services.py` | Ký, xác minh, thu hồi, đo hiệu năng |
| Miền | `models.py`, `trust.py` | Kiểu dữ liệu thuần, không biết đĩa |
| Hạ tầng | `signers.py`, `repository.py` | Thư viện mật mã, lưu trữ SQLite |

Điểm thiết kế chính: **`Signer` là một giao diện trừu tượng, ba thuật toán là
ba cài đặt của nó**. Nhờ vậy tầng nghiệp vụ và bộ đo hiệu năng chạy được trên
cả ba mà không cần biết bên trong chúng khác nhau ra sao, và thêm thuật toán
thứ tư chỉ cần thêm một lớp con.

Tầng lưu trữ cũng là giao diện, có hai cài đặt: SQLite để chạy thật và bản
trong bộ nhớ để kiểm thử chạy nhanh, không để lại tệp rác.

## 5. Dữ liệu và môi trường

| Hạng mục | Lựa chọn |
| --- | --- |
| Dữ liệu | Hoàn toàn giả lập: một tệp nhị phân sinh ngẫu nhiên, một tài liệu văn bản, một manifest. Không dùng dữ liệu thật của bất kỳ tổ chức nào |
| Khóa | Khóa thử nghiệm sinh tại chỗ, chỉ dùng cho đồ án; khóa riêng không commit lên kho mã |
| Ngôn ngữ | Python 3.11 trở lên |
| Thư viện mật mã | `cryptography` — nhóm không tự cài đặt lại thuật toán mật mã |
| Lưu trữ | SQLite, một tệp `data/sigtool.db`, nộp kèm được |
| Môi trường chạy | Máy cá nhân của từng thành viên, trong môi trường ảo Python riêng |
| Kho mã | GitHub, cả ba thành viên commit bằng tài khoản của chính mình |

## 6. Chỉ số đánh giá

| Mã | Chỉ số | Ngưỡng đặt ra | Nguồn kiểm chứng |
| --- | --- | --- | --- |
| CS-1 | Thời gian ký và xác minh, trung vị và phân vị 95 | Xác minh tệp 1 MB dưới 50 ms | `results/bench.csv` |
| CS-2 | Kích thước chữ ký và kích thước khóa | Ghi nhận, không đặt ngưỡng | `results/bench.csv` |
| CS-3 | Số lần lặp mỗi phép đo | Tối thiểu 100 | Số dòng trong CSV |
| CS-4 | Tỷ lệ ca kiểm thử đạt | 100%, hoặc giải thích rõ ca trượt | `pytest` |
| CS-5 | Độ phủ kiểm thử | Từ 70% trở lên | `pytest --cov` |
| CS-6 | Số loại sai lệch phân biệt được bằng mã lý do riêng | Tối thiểu 4 | `results/verify_log.jsonl` |
| CS-7 | Thời gian từ phát hiện khóa lộ đến dừng ký | Dưới 15 phút | Runbook và bảng `revocation` |

Nhóm dùng **trung vị** thay cho trung bình, vì một lần đo chậm bất thường do
hệ điều hành chen ngang sẽ kéo lệch trung bình nhưng gần như không ảnh hưởng
trung vị. Phân vị 95 báo kèm để thấy phần đuôi.

## 7. Điều kiện an toàn và đạo đức

- Khóa thử nghiệm **chỉ dùng cho đồ án**. Tuyệt đối không ký phần mềm thật
  bằng danh tính hoặc chứng thư của tổ chức nào.
- Khóa riêng không bao giờ được commit. Tệp `.gitignore` chặn sẵn, và quy
  trình kiểm tra tự động trên GitHub sẽ báo hỏng nếu phát hiện.
- Mọi phép thử chạy trên dữ liệu giả lập do nhóm tự tạo, trong môi trường
  nhóm kiểm soát.
- Nhóm không tấn công, dò quét hay thử nghiệm trên bất kỳ hệ thống nào khác.
- Phiên bản Python và phiên bản thư viện ghi đầy đủ trong README để người khác
  tái lập được kết quả.

## 8. Sản phẩm cam kết nộp

Báo cáo 25–35 trang không tính phụ lục, trích dẫn theo chuẩn IEEE. Kho mã
nguồn có README ghi rõ lệnh cài đặt, lệnh chạy, phiên bản công cụ và quy trình
hoàn nguyên. Công cụ ký và xác minh artifact ở mức nguyên mẫu. Bảng so sánh
định lượng giữa ba cơ chế. Manifest có phiên bản và định danh khóa ký. Runbook
xử lý khóa ký bị lộ kèm bằng chứng kiểm thử.

Minh chứng kèm theo: bộ artifact gốc và bản bị sửa; khóa thử nghiệm và dấu vân
tay công khai; chữ ký cùng log xác minh; tệp benchmark; sơ đồ vòng đời khóa
ký; bảng truy vết minh chứng; **bảng công khai việc sử dụng công cụ AI**.

## 9. Tiến độ dự kiến

| Tuần | Giai đoạn | Kết quả phải có |
| --- | --- | --- |
| 1 | Đề cương | Phiếu này được duyệt; kho mã dựng xong |
| 2 | Thiết kế | Mô hình đe dọa, sơ đồ lớp, ERD, kế hoạch kiểm thử, baseline |
| 3 | Triển khai | Ed25519 ký và xác minh chạy thông |
| 4 | Triển khai | Đủ ba thuật toán, tầng lưu trữ, dòng lệnh |
| 5 | Đánh giá | Kiểm thử âm, luân chuyển và thu hồi khóa, benchmark |
| 6 | Bàn giao | Báo cáo, bảng truy vết, tập bảo vệ |
| 7 | Dự phòng | Sửa theo góp ý, kiểm chứng khả năng tái lập |

---

**Ý kiến của giảng viên:**

&nbsp;

&nbsp;

&nbsp;

☐ Đồng ý phê duyệt &nbsp;&nbsp; ☐ Yêu cầu chỉnh sửa &nbsp;&nbsp; ☐ Không đồng ý

Ngày ..... tháng ..... năm 2026
