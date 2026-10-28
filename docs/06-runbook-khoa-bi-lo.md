# Runbook: xử lý khi khóa ký bị lộ

> Người viết: **Long** | Tuần: **5**

Tài liệu vận hành, viết ở dạng các bước làm được ngay, không phải tài liệu
giải thích. Người đọc là người đang xử lý sự cố lúc nửa đêm, nên mỗi bước có
lệnh cụ thể và tiêu chí biết là đã xong.

Đây là một trong bốn kết quả thực nghiệm đề tài yêu cầu, và là câu trả lời
cho câu hỏi nghiên cứu CH3 trong đề cương.

> Các lệnh `python -m dt19 ...` có từ tuần 4, khi `cli.py` hoàn thành. Trước
> đó dùng trực tiếp `RevocationService` và `KeyRotationService` trong Python.

## Điều kiện kích hoạt

Kích hoạt khi **nghi ngờ** hoặc **xác nhận** khóa riêng đã ra ngoài tầm
kiểm soát:

- Máy giữ khóa bị xâm nhập.
- Tệp khóa riêng bị sao chép, gửi nhầm, hoặc lỡ commit lên Git.
- Người từng có quyền truy cập khóa rời nhóm mà khóa chưa luân chuyển.
- Phát hiện chữ ký hợp lệ trên artifact mà không ai trong nhóm nhận đã ký.

**Nghi ngờ là đủ để kích hoạt.** Chờ tới khi chắc chắn thì khoảng thời gian
thiệt hại đã dài thêm.

## Giờ đầu tiên

**1. Dừng ký.** Chuyển trạng thái khóa sang `revoked`. Mọi lệnh ký bằng khóa
này phải thất bại ngay.

```bash
python -m dt19 revoke --key <key_id> --reason "khoa bi lo"
```

*Xong khi:* `python -m dt19 keys` hiển thị khóa ở trạng thái `revoked`.

**2. Ghi lại thời điểm NGHI NGỜ BỊ LỘ, không phải thời điểm phát hiện.**

Đây là bước dễ làm sai nhất và hậu quả nặng nhất. Hai mốc này thường cách
nhau hàng tuần. Mốc nghi ngờ mới là mốc dùng để phân loại chữ ký nào còn
đáng tin. Lấy mốc phát hiện là bỏ sót đúng những chữ ký nguy hiểm nhất —
những chữ ký kẻ tấn công tạo ra trong khoảng chưa ai biết.

Nếu **không xác định được** mốc nghi ngờ, để trống. Công cụ sẽ coi mọi chữ
ký của khóa này là đáng ngờ. Đừng điền đại một mốc gần đây cho đẹp báo cáo:
con số nhỏ sẽ tạo cảm giác an toàn sai.

**3. Đừng xóa gì cả.** Nhật ký, chữ ký cũ, trust list cũ đều là bằng chứng.
Xóa đi là mất khả năng dựng lại chuyện đã xảy ra.

**4. Thông báo nội bộ.** Báo cả nhóm và người phụ trách. Chưa thông báo ra
ngoài khi chưa xác định xong thiệt hại ở bước sau.

## Xác định thiệt hại

**5. Liệt kê toàn bộ artifact đã ký bằng khóa đó.**

```bash
python -m dt19 affected --key <key_id>
python -m dt19 affected --key <key_id> --since 2026-10-15T08:00
```

**6. Chia làm hai nhóm theo mốc ở bước 2.**

| Nhóm | Điều kiện | Xử lý |
| --- | --- | --- |
| A | Ký **trước** mốc nghi ngờ bị lộ | Nhiều khả năng vẫn hợp lệ, **nếu** có dấu thời gian kiểm chứng được bởi bên thứ ba. Với công cụ này dấu thời gian là giả lập nên không đủ căn cứ, phải ký lại |
| B | Ký **từ** mốc nghi ngờ trở đi | Coi như không đáng tin, bất kể xác minh có đạt hay không |

Chữ ký nhóm B vẫn xác minh **đúng** về mặt toán học. Đó chính là lý do phải
có cơ chế thu hồi: mật mã không tự biết khóa đã lọt ra ngoài.

**7. Ghi số lượng mỗi nhóm** vào bảng `revocation`, cột `affected_signatures`.
Con số này vào báo cáo và vào chỉ số CS-7.

## Khôi phục

**8. Sinh khóa mới.** Cùng thuật toán hay khác đều được, nhưng phải là cặp
khóa hoàn toàn mới. Không tái dùng bất cứ phần nào của khóa cũ.

```bash
python -m dt19 keygen --alg ed25519 --owner "<ten>"
```

Sinh khóa mới trên **máy sạch**. Sinh trên chính máy vừa bị xâm nhập là lặp
lại sự cố ngay lập tức.

**9. Phát hành trust list phiên bản mới.** Thêm khóa mới, cắt hiệu lực khóa
cũ **tại thời điểm nghi ngờ bị lộ**, không phải hôm nay.

```bash
python -m dt19 revoke --key <key_id_cu> --since <moc_nghi_ngo>
```

Khác với luân chuyển khóa thông thường, ở đây **không có giai đoạn chồng
lấn**. Chồng lấn tồn tại để người dùng kịp chuyển đổi êm thấm; thu hồi là
tình huống khẩn cấp, kéo dài hiệu lực thêm một ngày nào cũng là kéo dài
thiệt hại.

**10. Ký lại artifact nhóm B** (và nhóm A, theo ghi chú ở bước 6).

```bash
python -m dt19 resign --old <key_id_cu> --new <key_id_moi>
```

**11. Công bố trust list mới** kèm **dấu vân tay** khóa mới qua một kênh
khác với kênh phát hành artifact, để người dùng đối chiếu. Nếu công bố khóa
mới trên chính kênh đã bị kiểm soát thì kẻ tấn công công bố khóa của họ cũng
được.

*Xong khi:* người xác minh chạy `verify` trên artifact mới nhận `OK`, và
chạy trên artifact cũ của nhóm B nhận `KEY_REVOKED`.

## Sau sự cố

**12. Dựng lại dòng thời gian** từ nhật ký xác minh và bản ghi thu hồi:
khóa lộ lúc nào, phát hiện lúc nào, dừng ký lúc nào, công bố lúc nào.

**13. Tìm nguyên nhân gốc.** Câu hỏi không phải "khóa lộ bằng cách nào" mà
"vì sao cách đó khả thi". Khóa commit nhầm lên Git thì nguyên nhân gốc là
`.gitignore` thiếu hoặc không có bước kiểm tra tự động, chứ không phải người
commit bất cẩn.

**14. Rút ngắn chu kỳ luân chuyển** nếu thời gian từ lúc lộ tới lúc phát
hiện quá dài. Luân chuyển định kỳ giới hạn được lượng chữ ký phơi nhiễm
dưới cùng một khóa.

**15. Cập nhật mô hình đe dọa** `docs/05` nếu sự cố cho thấy một đường tấn
công chưa có trong bảng STRIDE.

## Chỉ số đo được của quy trình

Quy trình không đo được thì không cải tiến được. Bốn chỉ số, đo từ nhật ký
và bản ghi thu hồi chứ không từ trí nhớ:

| Mã | Chỉ số | Cách đo | Ngưỡng nhóm đặt ra |
| --- | --- | --- | --- |
| CS-7 | Thời gian từ **phát hiện** tới **dừng ký** | `revocation.revoked_at` trừ thời điểm ghi nhận sự cố | Dưới 15 phút |
| RB-2 | Thời gian từ phát hiện tới **công bố trust list mới** | Thời điểm tạo `trust_list_v<n>.json` trừ thời điểm phát hiện | Dưới 4 giờ |
| RB-3 | Số chữ ký bị ảnh hưởng | `revocation.affected_signatures` | Ghi nhận, không đặt ngưỡng |
| RB-4 | Khoảng từ lúc **nghi ngờ bị lộ** tới lúc **phát hiện** | Hai mốc ở bước 2 | Ghi nhận; đây là chỉ số nói lên chất lượng giám sát |

RB-4 là chỉ số đáng chú ý nhất. CS-7 đo tốc độ phản ứng, còn RB-4 đo thời
gian hệ thống bị phơi nhiễm mà không ai biết. Phản ứng nhanh không bù được
cho việc phát hiện muộn.

## Kiểm chứng runbook này

Runbook chưa diễn tập thì chưa biết có chạy được không. Các bước trên được
kiểm chứng bằng ba ca trong `tests/test_rotation.py`:

- **TC-11** — chữ ký tạo sau mốc thu hồi trả về `KEY_REVOKED` (bước 9).
- **TC-12** — đếm đúng số chữ ký bị ảnh hưởng, không đếm lẫn chữ ký của khóa
  khác (bước 5 và 6).
- **Ca bổ sung** — bỏ trống mốc nghi ngờ thì mọi chữ ký bị coi là đáng ngờ,
  không trả về 0 (bước 2).
