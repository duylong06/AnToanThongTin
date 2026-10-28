# Đặc tả yêu cầu phần mềm

> Người viết: **Long và Phiêu** | Tuần: **1–2**

## 1. Mục đích và phạm vi

## 2. Tác nhân

## 3. Yêu cầu chức năng (FR-01 …)

## 4. Yêu cầu phi chức năng (NFR-01 …)

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
