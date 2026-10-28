"""
Tác giả: Trương Hồng Uyên
Mô tả: Giao diện dòng lệnh (CLI) cho hệ thống sigtool
"""
import argparse

def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Công cụ ký và xác minh chữ ký số (sigtool)")
    subparsers = parser.add_subparsers(dest="command", help="Các lệnh hỗ trợ")

    # Lệnh sinh khóa
    subparsers.add_parser("keygen", help="Sinh cặp khóa mới")
    
    # Lệnh ký tệp
    sign_parser = subparsers.add_parser("sign", help="Ký tệp tin")
    sign_parser.add_argument("file", type=str, help="Đường dẫn tệp cần ký")
    sign_parser.add_argument("--key", type=str, required=True, help="ID của khóa ký")

    # Lệnh xác minh
    verify_parser = subparsers.add_parser("verify", help="Xác minh chữ ký")
    verify_parser.add_argument("file", type=str, help="Đường dẫn tệp cần xác minh")
    verify_parser.add_argument("--sig", type=str, required=True, help="ID của chữ ký")

    # Lệnh đo hiệu năng
    subparsers.add_parser("bench", help="Đo lường hiệu năng các thuật toán")

    return parser

def main():
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 0
    
    print(f"Đang thực thi lệnh: {args.command}")
    return 0

if __name__ == "__main__":
    exit(main())