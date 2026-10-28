-- Lược đồ cơ sở dữ liệu SQLite
-- Tác giả: Nguyễn Quỳnh Phiếu (bảng keys, verify_logs)
--          Nguyễn Duy Long (bảng signatures, revocations, trust_list_entry)
-- Chạy:  sqlite3 data/sigtool.db < data/schema.sql

PRAGMA foreign_keys = ON;

-- Bảng lưu trữ thông tin các cặp khóa (KeyPair)
-- Long bổ sung ba cột cuối: đường dẫn khóa riêng, hạn dùng, dấu vân tay.
-- Khóa riêng chỉ lưu ĐƯỜNG DẪN, không bao giờ lưu nội dung (NFR-04).
CREATE TABLE IF NOT EXISTS keys (
    key_id TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    owner TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT DEFAULT 'ACTIVE',
    revoked_at TEXT,
    private_key_path TEXT,
    expires_at TEXT,
    fingerprint TEXT
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

-- ===========================================================================
-- Long bổ sung
-- ===========================================================================

-- Chữ ký tách rời. Cần bảng riêng vì một artifact có thể mang nhiều chữ ký
-- của nhiều khóa, và khi thu hồi một khóa phải tra ngược được ra toàn bộ
-- chữ ký của khóa đó (FR-18).
CREATE TABLE IF NOT EXISTS signatures (
    signature_id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL,
    target_kind TEXT NOT NULL,          -- artifact | manifest
    key_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    sig_path TEXT NOT NULL,
    sig_size_bytes INTEGER NOT NULL,
    signed_at TEXT NOT NULL,
    timestamp_token TEXT,
    FOREIGN KEY (key_id) REFERENCES keys(key_id)
);

CREATE INDEX IF NOT EXISTS idx_signatures_key ON signatures(key_id);

-- Bản ghi thu hồi khóa. revoked_at là mốc CẮT HIỆU LỰC, lấy theo thời điểm
-- nghi ngờ bị lộ chứ không phải thời điểm phát hiện (xem docs/06).
CREATE TABLE IF NOT EXISTS revocations (
    key_id TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    revoked_at TEXT NOT NULL,
    affected_signatures INTEGER DEFAULT 0,
    FOREIGN KEY (key_id) REFERENCES keys(key_id)
);

-- Danh sách khóa tin cậy theo phiên bản. Trust list bản chính nằm ở tệp JSON
-- trong keys/ để phân phối được; bảng này để truy vấn và báo cáo.
CREATE TABLE IF NOT EXISTS trust_list_entry (
    version INTEGER NOT NULL,
    key_id TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_to TEXT,
    PRIMARY KEY (version, key_id)
);
