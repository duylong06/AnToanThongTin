-- Lược đồ cơ sở dữ liệu SQLite
-- Người viết: Phiêu | Tuần: 2
-- Chạy:  sqlite3 data/sigtool.db < data/schema.sql
--
-- Các bảng cần có: key_pair, trust_list, trust_list_entry, artifact,
-- manifest, manifest_entry, signature, verification_log, revocation,
-- benchmark_run

PRAGMA foreign_keys = ON;

-- TODO
