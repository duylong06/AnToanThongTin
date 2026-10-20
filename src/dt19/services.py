"""Tầng nghiệp vụ: ký, xác minh, thu hồi, đo hiệu năng.

Người phụ trách: Long (ký, xác minh, thu hồi) và Uyên (benchmark) | Tuần: 3 đến 5

Phải có trong tệp này:
- TimestampService: now(), issue_token(), check_token()
- SigningService: sign_artifact(), sign_manifest()
- VerificationService: verify_artifact(), verify_manifest(), ghi nhật ký
- RevocationService: revoke(), list_affected()
- BenchmarkRunner: run(), export_csv(), summarize()

THỨ TỰ KIỂM TRA trong VerificationService — quyết định mã lý do trả về:
  1. Khóa có trong trust list tại thời điểm ký không?
  2. Khóa đã bị thu hồi chưa?
  3. Chữ ký có khớp không?
  4. Dấu thời gian có đúng không?
Làm sai thứ tự này là mã lý do trả về sai chỗ.
"""

# TODO
