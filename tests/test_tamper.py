"""Ca kiểm thử âm — quan trọng hơn ca dương.

Người phụ trách: Phiếu | Tuần: 5

Các ca cần viết:
Mỗi ca một MÃ LÝ DO RIÊNG, không gộp chung thành “sai”:
- TC-03 Sửa một byte nội dung        → CONTENT_MODIFIED
- TC-04 Đổi tên tệp, giữ nội dung    → METADATA_MODIFIED
- TC-05 Sửa manifest đã ký           → SIG_INVALID
- TC-06 Thay chữ ký bằng rác         → SIG_INVALID
- TC-07 Khóa không trong trust list  → KEY_UNKNOWN
- TC-08 Nhật ký chỉ ghi thêm, không sửa dòng cũ
"""

# TODO
