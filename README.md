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
| 2 | Nguyễn Quỳnh Phiêu | | Lớp miền, manifest, lưu trữ, kiểm thử âm |
| 3 | Trương Hồng Uyên | | Dòng lệnh, đo lường, biểu đồ, báo cáo |

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

## Cách dùng

> Phần này điền dần khi các lệnh được hiện thực. Mỗi tuần thêm lệnh nào thì
> bổ sung ví dụ chạy thật của lệnh đó vào đây.

```bash
python -m dt19 init
python -m dt19 keygen --alg ed25519 --owner "<tên>"
python -m dt19 manifest --dir artifacts --out artifacts/manifest.json
python -m dt19 sign artifacts/manifest.json --key <key_id> --manifest
python -m dt19 verify artifacts/manifest.json --sig <signature_id>
python -m dt19 bench --iterations 100 --size 1048576
```

## Kiểm thử

```bash
pytest -q --cov=src/dt19 --cov-report=term-missing
```

Ngưỡng nhóm đặt ra: độ phủ từ **70%** trở lên, toàn bộ ca kiểm thử đạt hoặc
giải thích rõ ca trượt.

## Tiến độ

- [ ] **Tuần 1** — Đề cương được duyệt, repo dựng xong, CI chạy
- [ ] **Tuần 2** — Mô hình đe dọa, sơ đồ lớp, ERD, kế hoạch kiểm thử, baseline
- [ ] **Tuần 3** — Ed25519 ký và xác minh chạy thông
- [ ] **Tuần 4** — Đủ ba thuật toán, tầng lưu trữ, dòng lệnh
- [ ] **Tuần 5** — Kiểm thử âm, luân chuyển khóa, thu hồi, benchmark
- [ ] **Tuần 6** — Báo cáo, bảng truy vết, tập bảo vệ
- [ ] **Tuần 7** — Dự phòng, sửa theo góp ý

Chi tiết từng tuần: [docs/08-phan-cong-va-tien-do.md](docs/08-phan-cong-va-tien-do.md)

## Môi trường

| Thành phần | Phiên bản |
| --- | --- |
| Python | |
| cryptography | |
| pytest | |
| Hệ điều hành | |

> Điền bằng kết quả `python -V` và `pip freeze` trên máy thật của nhóm.
> Đề bài yêu cầu ghi rõ phiên bản công cụ để người khác tái lập được.

## Quy ước commit

- Mỗi người commit bằng tài khoản GitHub của chính mình, không ai commit hộ ai.
- Thông điệp gắn với yêu cầu: `[FR-06] Thêm ký artifact bằng Ed25519`.
- Mã mới đi kèm ca kiểm thử.
- Không commit khóa riêng. CI có bước kiểm tra tự động.

## Hoàn nguyên

```bash
rm -f data/sigtool.db results/verify_log.jsonl
rm -rf keys/*/ signatures/
python -m dt19 init
```

## Công khai sử dụng AI

| Công cụ | Nội dung hỗ trợ | Phần nhóm tự thực hiện và chịu trách nhiệm |
| --- | --- | --- |
| | | |

> Đề bài yêu cầu bảng này trong hồ sơ nộp. Điền đúng thực tế: công cụ nào,
> hỗ trợ việc gì, và nhóm đã tự kiểm chứng những gì.
