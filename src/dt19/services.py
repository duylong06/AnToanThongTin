"""
Tác giả: Nguyễn Quỳnh Phiếu
Mô tả: Dịch vụ tạo Manifest và kiểm tra toàn vẹn cho thư mục artifacts
"""

import os
import json
import hashlib
from dt19.models import Manifest


def create_manifest(artifacts_dir: str, output_manifest_path: str) -> Manifest:
    """Quét thư mục artifacts_dir, tính SHA-256 cho từng file và xuất ra manifest.json"""
    manifest = Manifest(files={})

    if not os.path.exists(artifacts_dir):
        raise FileNotFoundError(f"Thư mục không tồn tại: {artifacts_dir}")

    for root, _, files in os.walk(artifacts_dir):
        for file in files:
            # Bỏ qua chính file manifest.json nếu nó nằm cùng thư mục
            if file == "manifest.json":
                continue

            full_path = os.path.join(root, file)
            # Lấy đường dẫn tương đối để đảm bảo tính độc lập môi trường
            rel_path = os.path.relpath(full_path, artifacts_dir).replace("\\", "/")

            # Tính SHA-256
            hasher = hashlib.sha256()
            with open(full_path, "rb") as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)

            manifest.add_file(rel_path, hasher.hexdigest())

    # Ghi cấu trúc Manifest ra file JSON
    os.makedirs(os.path.dirname(output_manifest_path), exist_ok=True)
    with open(output_manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest.to_dict(), f, indent=2, ensure_ascii=False)

    return manifest