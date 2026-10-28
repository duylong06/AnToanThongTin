"""
Tác giả: Trương Hồng Uyên
Mô tả: Ca kiểm thử cho Giao diện dòng lệnh (CLI)
"""
import pytest
from dt19.cli import create_parser

def test_cli_parser_creation():
    """Kiểm tra parser được tạo thành công"""
    parser = create_parser()
    assert parser is not None

def test_cli_parse_keygen():
    """Kiểm tra phân tích tham số lệnh sinh khóa"""
    parser = create_parser()
    args = parser.parse_args(["keygen"])
    assert args.command == "keygen"

def test_cli_parse_sign():
    """Kiểm tra phân tích tham số lệnh ký tệp"""
    parser = create_parser()
    args = parser.parse_args(["sign", "docs/test.txt", "--key", "key-123"])
    assert args.command == "sign"
    assert args.file == "docs/test.txt"
    assert args.key == "key-123"