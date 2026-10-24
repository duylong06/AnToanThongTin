-- Bảng lưu trữ thông tin các cặp khóa (KeyPair)
CREATE TABLE IF NOT EXISTS keys (
    key_id TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    owner TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT DEFAULT 'ACTIVE',
    revoked_at TEXT
);

-- Bảng lưu trữ Nhật ký xác minh chỉ ghi thêm (Append-only Verification Logs)
CREATE TABLE IF NOT EXISTS verify_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sig_id TEXT NOT NULL,
    status TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    verified_at TEXT NOT NULL,
    details TEXT
);