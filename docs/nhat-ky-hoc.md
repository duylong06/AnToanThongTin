# Nhật ký học

> Mỗi lần hiểu ra điều gì, ghi một hai câu vào đây rồi commit cùng code.
> Đến tuần 6 viết báo cáo sẽ có sẵn nguyên liệu bằng chính lời mình.

**Đây là tệp duy nhất không ai viết hộ được.** Mục 2 và mục 7 của báo cáo
cần giọng của từng người; chép lại tài liệu thì ra một bài trơn tru nhưng
rỗng, và khi thầy hỏi lại thì không trả lời được.

Mỗi người ghi dưới mục của mình. Không cần dài, hai ba câu một lần là đủ.
Viết sai cũng không sao — ghi lại chỗ mình từng hiểu sai và sau đó hiểu
đúng là phần có giá trị nhất.

---

## Long — lõi mật mã và vòng đời khóa

Gợi ý những câu đáng trả lời bằng lời của mình:

- Vì sao `Signer` phải là lớp trừu tượng? Mình đã nghĩ gì trước khi hiểu ra?
- Lần đầu đọc về nonce `k` của ECDSA, điều gì làm mình thấy đáng sợ?
- Vì sao Ed25519 ký cùng một dữ liệu hai lần lại ra chữ ký giống hệt, còn
  ECDSA thì không? Mình kiểm chứng điều đó bằng cách nào?
- Thứ tự kiểm tra trong `verify_signature` — mình đã từng xếp sai chưa, và
  hậu quả là gì?
- Khác nhau giữa `revoked_at` và `suspected_since`: vì sao lúc đầu mình thấy
  hai cái giống nhau?

### Tuần 2

### Tuần 3

### Tuần 4

### Tuần 5

---

## Phiêu — dữ liệu, manifest và kiểm thử âm

Gợi ý:

- Vì sao phải chuẩn hóa byte trước khi ký? Nếu không chuẩn hóa thì hỏng ở đâu?
- Lúc đầu mình viết ca kiểm thử kiểu gán sẵn biến rồi kiểm tra chính biến đó.
  Vì sao cách đó không chứng minh được gì? Mình nhận ra lúc nào?
- `FILE_MISSING` và `METADATA_MODIFIED` khác nhau thế nào, và vì sao đáng
  công phân biệt?
- Vì sao chỉ lưu đường dẫn khóa riêng mà không lưu nội dung vào cơ sở dữ liệu?
- Hiệu ứng tuyết lở của SHA-256: lật một bit trong tệp 4096 byte mà vẫn bị
  bắt — mình giải thích chuyện đó ra sao?

### Tuần 2

### Tuần 3

### Tuần 4

### Tuần 5

---

## Uyên — dòng lệnh, đo lường và hồ sơ

Gợi ý:

- Vì sao dùng trung vị thay vì trung bình? Mình từng nghĩ hai cái gần giống
  nhau không?
- Vì sao phải đo ở **hai** kích thước dữ liệu? Nếu chỉ đo ở 1 MB thì kết luận
  về RSA sẽ sai lệch thế nào?
- RSA-PSS ký chậm hơn xác minh 428 lần — mình giải thích con số đó bằng toán
  học nào?
- Lúc đầu bản benchmark chạy trên dữ liệu giả `[1.5, 1.5, ...]`. Vì sao ca
  kiểm thử cũ vẫn xanh, và mình đã thêm ca nào để chuyện đó không lặp lại?
- Vì sao dòng lệnh cần ba mã thoát khác nhau chứ không chỉ 0 và 1?

### Tuần 2

### Tuần 3

### Tuần 4

### Tuần 5

---

## Ghi chung của nhóm

### Điều nhóm làm sai và đã sửa

Phần này đáng giá khi bảo vệ. Vài chuyện đã xảy ra, mỗi người tự viết lại
bằng lời mình:

- Tuần 2: bảng mã lý do trong `docs/01` để trống, nên mỗi người tự đặt tên mã
  khác nhau. Hậu quả và cách nhóm xử lý.
- Tuần 4: thu hồi khóa mà không rõ mốc lộ — lệnh `affected` báo có chữ ký bị
  ảnh hưởng nhưng `verify` vẫn trả ĐẠT cho đúng những chữ ký đó. Hai câu trả
  lời mâu thuẫn cho cùng một câu hỏi. Ca kiểm thử nào bắt được?
- Tuần 4: một số ca kiểm thử không gọi vào mã thật nên luôn xanh. Quy ước
  nhóm đặt ra sau đó là gì?
