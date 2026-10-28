# Mô hình đe dọa

> Người viết: **Long** | Tuần: **2**

Tài liệu này trả lời câu hỏi: công cụ `sigtool` bảo vệ cái gì, trước ai, và
quan trọng nhất là **không** bảo vệ được cái gì. Phương pháp theo mục 2.3 và
chương 6 của bài giảng: xác định tài sản, vẽ luồng dữ liệu, phân định ranh
giới tin cậy, rồi áp khung STRIDE lên từng thành phần.

## 1. Tài sản cần bảo vệ

Xếp theo hậu quả nếu mất, không theo thứ tự xuất hiện trong mã nguồn.

| Mã | Tài sản | Mất thì sao | Thuộc tính cần giữ |
| --- | --- | --- | --- |
| TS-1 | **Khóa riêng ký** | Kẻ tấn công ký được mọi thứ dưới danh nghĩa nhóm. Toàn bộ chữ ký đã phát hành mất giá trị | Bí mật, quyền kiểm soát |
| TS-2 | **Trust list** | Thêm được khóa lạ vào đây là thắng, không cần phá mật mã | Toàn vẹn, xác thực nguồn |
| TS-3 | **Artifact và manifest** | Người dùng cài phải bản đã bị sửa | Toàn vẹn |
| TS-4 | **Chữ ký tách rời** | Xóa chữ ký thì không ai xác minh được; đổi chữ ký thì xác minh trượt | Toàn vẹn, sẵn sàng |
| TS-5 | **Nhật ký xác minh** | Không dựng lại được chuyện gì đã xảy ra khi có sự cố | Toàn vẹn, chỉ ghi thêm |
| TS-6 | **Bản ghi thu hồi** | Chữ ký của khóa đã lộ vẫn được chấp nhận | Toàn vẹn |

TS-1 và TS-2 đứng đầu vì chúng là **gốc của niềm tin**. Mọi thứ còn lại chỉ
đáng tin trong chừng mực hai thứ này còn nguyên vẹn.

## 2. Luồng dữ liệu và ranh giới tin cậy

Bài giảng nhấn mạnh: sơ đồ chỉ có tên thành phần mà thiếu luồng dữ liệu và
ranh giới tin cậy thì chưa đủ điều kiện để mô hình hóa đe dọa.

```
   [Người ký]                    │ RGTC-1 │              [Người xác minh]
       │                                                        │
       ▼                                                        ▼
  sign artifact ──► chữ ký (.sig) ──────────────────────► verify artifact
       │                                                        ▲
       ▼                                                        │
  khóa riêng (keys/, quyền 600)        trust list (JSON có phiên bản)
       │                                                        ▲
       │ RGTC-2                                                 │
       ▼                                                        │
  cơ sở dữ liệu SQLite ◄──── bản ghi thu hồi ────────────────────┘
```

**RGTC-1 — giữa người ký và người xác minh.** Artifact, chữ ký và trust list
đi qua một kênh không tin cậy (mạng, USB, kho phát hành). Giả định: mọi thứ
đi qua đây đều có thể bị đọc, sửa, thay thế hoặc chặn lại.

**RGTC-2 — giữa tiến trình và nơi lưu trữ.** Khóa riêng nằm trên đĩa, cơ sở
dữ liệu nằm trên đĩa. Ai đọc được đĩa thì đọc được chúng.

Ranh giới quan trọng nhất là RGTC-1, vì toàn bộ giá trị của chữ ký số nằm ở
chỗ nó vẫn kiểm chứng được sau khi đi qua một kênh không ai kiểm soát.

## 3. Đe dọa và biện pháp theo STRIDE

| Chữ | Đe dọa cụ thể trong `sigtool` | Biện pháp | Nằm ở đâu |
| --- | --- | --- | --- |
| **S** Giả mạo | Kẻ tấn công ký bằng khóa của mình rồi phát hành như thể là của nhóm | Trust list có phiên bản; xác minh tra trust list **trước** khi kiểm chữ ký | `trust.py`, `VerificationService._check_key` |
| **T** Sửa đổi | Sửa một byte trong artifact; đổi tên tệp; thêm hoặc bớt tệp khỏi bộ phát hành | Băm SHA-256 từng tệp; ký manifest chuẩn hóa byte nên thêm bớt đều bị phát hiện | `models.py`, `verify_manifest` |
| **T** Sửa đổi | Sửa trust list để thêm khóa của kẻ tấn công | Trust list không sửa tại chỗ, mỗi thay đổi là một phiên bản mới; số phiên bản ghi vào nhật ký xác minh | `trust.py` |
| **R** Chối bỏ | Người ký phủ nhận đã ký một artifact | Chữ ký bằng khóa riêng chỉ một người giữ; nhật ký xác minh chỉ ghi thêm | `signers.py`, `_log` |
| **I** Lộ thông tin | Khóa riêng lọt vào Git, vào nhật ký, hoặc vào bản sao lưu cơ sở dữ liệu | Chỉ lưu **đường dẫn** khóa riêng, không lưu nội dung; `.gitignore` chặn `keys/`; CI báo hỏng nếu phát hiện khóa riêng được commit | `models.KeyPair`, `.gitignore`, CI |
| **D** Từ chối dịch vụ | Xóa tệp chữ ký khiến artifact không xác minh được | Ngoài phạm vi công cụ. Giải quyết bằng sao lưu và phân phối nhiều nơi | — |
| **E** Nâng quyền | Người dùng khác trên cùng máy đọc tệp khóa riêng | Đặt quyền 600 khi ghi khóa riêng | `Signer.generate_key` |

Hai dòng đáng nói thêm:

**Về chữ S.** Thứ tự kiểm tra trong `VerificationService` chính là biện pháp
chống giả mạo. Nếu kiểm chữ ký trước rồi mới tra trust list, một khóa lạ ký
đúng sẽ qua được bước mật mã, và thông báo lỗi sau đó không nói được rằng
vấn đề nằm ở **sự tin cậy** chứ không ở phép toán.

**Về chữ E.** Quyền 600 không áp dụng được trên Windows theo kiểu POSIX. Mã
nguồn bắt ngoại lệ và đi tiếp thay vì dừng, nhưng đây là một hạn chế thật,
đã ghi ở mục 4.

## 4. Điều công cụ KHÔNG bảo vệ được

Mục này quan trọng hơn ba mục trên. Một công cụ an toàn mà người dùng hiểu
sai phạm vi bảo vệ thì nguy hiểm hơn là không có công cụ.

**Không bảo vệ bí mật nội dung.** Chữ ký số chỉ chứng minh nội dung không
bị sửa và biết ai ký. Artifact vẫn đọc được bình thường. Muốn giấu nội dung
phải mã hóa, đó là cơ chế khác.

**Không phát hiện được artifact độc hại được ký hợp lệ.** Nếu chính người
giữ khóa ký một tệp có mã độc, `sigtool` sẽ báo `OK` — và báo đúng. Chữ ký
trả lời câu "có phải người này ký không", không trả lời câu "thứ này có an
toàn không".

**Không bảo vệ được sau khi khóa riêng bị lộ.** Mọi chữ ký tạo bằng khóa đã
lộ đều xác minh đúng về mặt toán học. Đây là lý do cần cơ chế thu hồi và
runbook ở `docs/06`, chứ không phải lý do để dùng thuật toán mạnh hơn.

**Chống chối bỏ ở đây là chống chối bỏ kỹ thuật, không phải pháp lý.** Công
cụ chứng minh được rằng một chữ ký khớp với một khóa công khai. Nó không
chứng minh được rằng khóa riêng tương ứng thuộc về một con người cụ thể —
việc đó cần quy trình định danh và chứng thư của một CA, tức là phạm vi của
đề tài 20 chứ không phải đề tài này. Người ký vẫn có thể nói "khóa của tôi
bị người khác dùng".

**Dấu thời gian là giả lập, không có giá trị trước bên thứ ba.** Nhóm tự giữ
khóa HMAC ký dấu, nên nhóm tạo được dấu thời gian bất kỳ. Một TSA thật có
giá trị chính vì nó độc lập với người ký. Token trong công cụ này chỉ dùng
để kiểm thử logic, không dùng làm bằng chứng.

**Không bảo vệ được trust list trên đường truyền.** Trust list là tệp JSON
không được ký. Nếu kẻ tấn công thay được tệp này trên máy người xác minh thì
mọi biện pháp chống giả mạo ở trên đều vô hiệu. Hệ thống thật giải quyết
bằng cách ký trust list bằng một khóa gốc giữ ngoại tuyến; nhóm ghi nhận đây
là rủi ro còn lại và nêu rõ trong phần giới hạn của báo cáo.

**Không chống được tấn công kênh kề và không bảo vệ bộ nhớ tiến trình.**
Khóa riêng được nạp vào RAM lúc ký. Người có quyền đọc bộ nhớ tiến trình thì
lấy được khóa. Bảo vệ ở mức đó cần HSM, nằm ngoài phạm vi đồ án.

## 5. Rủi ro còn lại được chấp nhận

| Rủi ro | Vì sao chấp nhận | Điều kiện xét lại |
| --- | --- | --- |
| Trust list không được ký | Đề tài tập trung vào cơ chế chữ ký, không dựng PKI đầy đủ | Nếu mở rộng sang đề tài 20 thì phải bổ sung khóa gốc |
| Dấu thời gian giả lập | Không có TSA chuẩn RFC 3161 để dùng trong phạm vi đồ án | Nêu rõ trong mọi kết quả liên quan tới dấu thời gian |
| Khóa riêng không mã hóa bằng mật khẩu | Khóa thử nghiệm, chỉ dùng cho đồ án | Nếu dùng thật thì bắt buộc mã hóa khóa riêng |
| Quyền tệp không áp dụng trên Windows | Hạn chế của hệ điều hành | Ghi chú trong README và trong báo cáo |

## 6. Liên hệ tới phần còn lại của đồ án

Mỗi đe dọa ở mục 3 có ít nhất một ca kiểm thử tương ứng: chữ S kiểm bằng ca
khóa lạ trả `KEY_NOT_TRUSTED`; chữ T kiểm bằng bộ ca kiểm thử âm trong
`test_tamper.py`; vòng đời khóa và thu hồi kiểm bằng `test_rotation.py`. Mô
hình đe dọa không nằm riêng một chỗ mà là nguồn gốc của kế hoạch kiểm thử.
