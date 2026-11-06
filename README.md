# sigtool — Đánh giá chữ ký số cho phần mềm và tài liệu điện tử

Đồ án môn **An toàn thông tin (123033)** — Đề tài 19
Trường Đại học Giao thông Vận tải TP. Hồ Chí Minh
Giảng viên hướng dẫn: TS. Lê Quốc Tuấn

> **Khóa trong kho này là khóa thử nghiệm, chỉ dùng cho đồ án.**
> Không ký phần mềm thật bằng danh tính hoặc chứng thư của bất kỳ tổ chức nào.
> Mọi phép thử chạy trên dữ liệu giả lập, trong môi trường do nhóm kiểm soát.

## Nhóm 19

| | Họ và tên | MSSV | Phần chịu trách nhiệm |
| --- | --- | --- | --- |
| 1 | Nguyễn Duy Long | 060206005525 | Lõi mật mã, xác minh, vòng đời khóa |
| 2 | Nguyễn Quỳnh Phiêu | 051206008523 | Lớp miền, manifest, lưu trữ, kiểm thử âm |
| 3 | Trương Hồng Uyên | 051306002000 | Dòng lệnh, đo lường, biểu đồ, báo cáo |

## Đề tài làm gì

Xây dựng công cụ dòng lệnh ký và xác minh artifact bằng ba thuật toán chữ ký
số, rồi **đo** sự khác biệt giữa chúng và **chứng minh** rằng mọi thay đổi
trên nội dung hoặc metadata đều làm xác minh thất bại.

Ba câu hỏi nghiên cứu:

1. RSA-PSS, ECDSA và Ed25519 khác nhau thế nào về kích thước chữ ký, tốc độ
   ký, tốc độ xác minh và yêu cầu nonce?
2. Mọi thay đổi có thực sự bị phát hiện không, và công cụ có phân biệt được
   nguyên nhân không?
3. Khi khóa ký bị lộ thì xử lý ra sao, đo bằng chỉ số nào?

## Cấu trúc kho mã

```
├── docs/            Tài liệu: đề cương, đặc tả, ERD, sơ đồ lớp, kiểm thử,
│                    mô hình đe dọa, runbook, kết quả, phân công, sườn báo cáo
├── src/dt19/        Mã nguồn
│   ├── models.py        Lớp miền: KeyPair, Manifest, ReasonCode
│   ├── signers.py       Giao diện Signer và ba cài đặt
│   ├── repository.py    Tầng lưu trữ SQLite
│   ├── trust.py         Trust list, luân chuyển khóa
│   ├── services.py      Ký, xác minh, thu hồi, benchmark
│   └── cli.py           Giao diện dòng lệnh
├── tests/           Ca kiểm thử dương, âm, luân chuyển, dòng lệnh
├── data/            schema.sql và cơ sở dữ liệu sinh ra khi chạy
├── artifacts/       Tệp mẫu để ký
├── keys/            Khóa thử nghiệm và trust list (khóa riêng KHÔNG commit)
└── results/         Số liệu đo, nhật ký xác minh, biểu đồ, bảng truy vết
```

Mỗi tệp mã nguồn và tài liệu đều có ghi chú ở đầu nói rõ **ai viết, tuần nào,
phải có những gì**.

## Cài đặt

```bash
git clone <đường dẫn repo của nhóm>
cd <tên thư mục>
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export PYTHONPATH=src            # Windows: set PYTHONPATH=src
```

Kiểm tra môi trường chạy được:

```bash
python -c "import cryptography; print(cryptography.__version__)"
pytest -q
```

## Trạng thái

| | |
| --- | --- |
| Ca kiểm thử | **54/54 đạt** |
| Độ phủ mã | **86%** (ngưỡng nhóm đặt: 70%) |
| Xác minh tệp 1 MB | **1,87 ms** (ngưỡng: dưới 50 ms) |
| Loại sai lệch phân biệt được | **6** mã lý do riêng |

## Dùng thử trong năm phút

```bash
python -m dt19 init
python -m dt19 keygen --alg ed25519 --owner "Nhom 19"
python -m dt19 keys                      # xem key_id vừa sinh

python -m dt19 manifest --dir artifacts --out artifacts/manifest.json
python -m dt19 sign artifacts/manifest.json --key <key_id> --manifest
python -m dt19 verify artifacts/manifest.json --sig <signature_id> --root artifacts
#   -> [ĐẠT]  SUCCESS

# Thử phá: lật một bit rồi xác minh lại
python -c "p='artifacts/app.bin';d=bytearray(open(p,'rb').read());d[0]^=1;open(p,'wb').write(d)"
python -m dt19 verify artifacts/manifest.json --sig <signature_id> --root artifacts
#   -> [TRƯỢT] FILE_MODIFIED, mã thoát 1
```

Các lệnh còn lại:

```bash
python -m dt19 rotate   --old <key_cu> --new <key_moi> --overlap-days 14
python -m dt19 revoke   --key <key_id> --reason "khoa bi lo" [--since 2026-10-15T08:00]
python -m dt19 affected --key <key_id>
python -m dt19 resign   --old <key_cu> --new <key_moi> --dir artifacts
python -m dt19 bench    --iterations 100 --size 1048576 --out results/bench.csv
```

**Mã thoát:** `0` thành công · `1` xác minh trượt · `2` sai tham số.
Ba mã khác nhau để script tự động phân biệt "phát hiện giả mạo" với "gọi
sai lệnh".

## Sinh lại toàn bộ minh chứng

```bash
python scripts/sinh_minh_chung.py                                       # 6 kịch bản xác minh
python -m dt19 bench --iterations 100 --size 1048576 --out results/bench.csv
python -m dt19 bench --iterations 100 --size 1024    --out results/bench_1kb.csv
```

## Kiểm thử

```bash
pytest -q --cov=src/dt19 --cov-report=term-missing
```

Ngưỡng nhóm đặt ra: độ phủ từ **70%** trở lên, toàn bộ ca kiểm thử đạt hoặc
giải thích rõ ca trượt.

**Quy ước:** mọi ca kiểm thử phải gọi vào `src/dt19/`. Ca nào chỉ gán sẵn
một biến rồi kiểm tra chính biến đó thì không tính là minh chứng, vì xóa
sạch mã nguồn nó vẫn xanh. Xem `docs/04` mục 1.

## Tiến độ

- [x] **Tuần 1** — Đề cương, repo dựng xong, CI chạy
- [x] **Tuần 2** — Mô hình đe dọa, sơ đồ lớp, ERD, kế hoạch kiểm thử, baseline
- [x] **Tuần 3** — Ed25519 ký và xác minh chạy thông
- [x] **Tuần 4** — Đủ ba thuật toán, tầng lưu trữ, dòng lệnh
- [x] **Tuần 5** — Kiểm thử âm, luân chuyển khóa, thu hồi, benchmark
- [ ] **Tuần 6** — Báo cáo 25–35 trang, tập bảo vệ *(sườn đã có ở `docs/09`)*
- [ ] **Tuần 7** — Dự phòng, sửa theo góp ý

Chi tiết từng tuần: [docs/08-phan-cong-va-tien-do.md](docs/08-phan-cong-va-tien-do.md)

## Môi trường

| Thành phần | Phiên bản |
| --- | --- |
| Python | 3.11 trở lên (đã chạy trên 3.13.16) |
| cryptography | 43.0.1 trở lên (đã chạy trên 50.0.1) |
| pytest | 8.3 trở lên |
| Hệ điều hành | Linux x86-64; Windows chạy được, xem lưu ý bên dưới |

> Số liệu trong `docs/07` đo trên cấu hình ở hàng "đã chạy trên". Mỗi thành
> viên ghi thêm phiên bản máy mình bằng `python -V` và `pip freeze`.

**Lưu ý Windows:** quyền tệp 600 cho khóa riêng không áp dụng được theo kiểu
POSIX. Mã nguồn bỏ qua lỗi này và chạy tiếp, nhưng tệp khóa riêng trên
Windows không được hệ điều hành bảo vệ ở mức tương đương.

## Quy ước commit

- Mỗi người commit bằng tài khoản GitHub của chính mình, không ai commit hộ ai.
- Thông điệp gắn với yêu cầu: `[FR-06] Thêm ký artifact bằng Ed25519`.
- Mã mới đi kèm ca kiểm thử.
- Không commit khóa riêng. CI có bước kiểm tra tự động.

## Hoàn nguyên

```bash
rm -f data/sigtool.db results/verify_log.jsonl
rm -rf keys/*/ signatures/*
python -m dt19 init
```

## Công khai sử dụng AI

| Công cụ | Nội dung hỗ trợ | Phần nhóm tự thực hiện và chịu trách nhiệm |
| --- | --- | --- |
| Claude (Anthropic) | Soạn bản nháp mã nguồn cho `signers.py`, `services.py`, `trust.py`, `repository.py`, `cli.py`; soạn bản nháp bộ kiểm thử; soạn bản nháp tài liệu `docs/01`–`docs/09`; soạn kịch bản CI; giải thích lý thuyết chương 4 và chương 6 khi nhóm hỏi | Chọn phạm vi và ba câu hỏi nghiên cứu; chốt bảng mã lý do và thứ tự kiểm tra; đọc hiểu và rà từng tệp trước khi commit; chạy lại toàn bộ 54 ca kiểm thử và script sinh minh chứng; đối chiếu số liệu với bài giảng chương 4; tự trả lời phần lý thuyết khi bảo vệ |
| CrypTool 2 | Đối chiếu kết quả băm SHA-256 và minh họa RSA, ECDSA trong buổi học | Tự chạy lại và so với đầu ra của `sigtool` |

**Nhóm đã tự kiểm chứng những gì:**

| Việc | Người làm | Bằng chứng |
| --- | --- | --- |
| Chạy lại 54/54 ca kiểm thử, độ phủ 86% | | CI trên GitHub Actions, 3 phiên bản Python |
| Chạy lại `scripts/sinh_minh_chung.py`, 6/6 kịch bản đúng mã lý do | | `results/bang_ma_ly_do.csv` |
| Đo lại hiệu năng bằng lệnh `bench` | | `results/bench_raw.csv`, 100 lần lặp |
| Đọc và giải thích được từng tệp mình commit | | Mục hỏi đáp khi bảo vệ |

> **Bảng này bắt buộc có trong hồ sơ nộp.** Cột "Người làm" ở bảng thứ hai để
> trống cho từng thành viên tự điền tên mình vào đúng dòng mình đã thực sự
> làm — không điền hộ nhau. Đề bài yêu cầu cả ba thành viên tham gia thiết kế,
> thực nghiệm, phân tích và **bảo vệ**.
