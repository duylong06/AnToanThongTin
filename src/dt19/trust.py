"""Trust list có phiên bản và luân chuyển khóa (FR-15, FR-16).

Người phụ trách: Long | Tuần: 5

Trust list là thứ quyết định khóa nào được tin. Nó quan trọng ngang khóa
riêng: ai thêm được khóa vào đây thì người đó thắng, không cần phá mật mã.
Vì thế trust list có PHIÊN BẢN và không bao giờ sửa tại chỗ — mỗi lần thay
đổi là một tệp mới, tệp cũ giữ nguyên để truy vết được.

ĐIỂM MẤU CHỐT của cả tệp này: is_trusted xét THỜI ĐIỂM KÝ, không xét hiện
tại. Một chữ ký tạo hôm qua bằng khóa hôm nay đã hết hiệu lực vẫn phải hợp
lệ — lúc ký nó hoàn toàn đúng. Nếu xét theo hiện tại thì mọi chữ ký cũ sẽ
hỏng hết mỗi lần luân chuyển khóa.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

# Định dạng thời gian cố định, có cả micro giây. Dùng một định dạng duy nhất
# cho cả ghi và đọc để không bao giờ lệch nhau.
ISO = "%Y-%m-%dT%H:%M:%S.%f"


def _dt(v: str | None) -> datetime | None:
    return datetime.strptime(v, ISO) if v else None


def _s(v: datetime | None) -> str | None:
    return v.strftime(ISO) if v else None


@dataclass
class TrustEntry:
    """Một khóa được tin, kèm khoảng thời gian hiệu lực.

    ``valid_to`` để None nghĩa là chưa có hạn kết thúc, tức khóa đang hoạt
    động. Hạn kết thúc chỉ được đặt khi luân chuyển hoặc khi thu hồi.
    """

    key_id: str
    valid_from: datetime
    valid_to: datetime | None = None

    def covers(self, moment: datetime) -> bool:
        """Khoảng hiệu lực có bao trùm thời điểm ``moment`` không."""
        if moment < self.valid_from:
            return False
        if self.valid_to is not None and moment > self.valid_to:
            return False
        return True


@dataclass
class TrustList:
    """Danh sách khóa tin cậy tại một phiên bản cụ thể."""

    version: int
    created_at: datetime
    entries: list[TrustEntry] = field(default_factory=list)
    note: str = ""

    def is_trusted(self, key_id: str, moment: datetime) -> bool:
        """Khóa có được tin tại thời điểm ``moment`` không.

        Đây là chỗ giai đoạn chồng lấn phát huy tác dụng: trong khoảng chồng
        lấn, cả khóa cũ lẫn khóa mới đều trả True, nên máy chưa kịp cập nhật
        trust list vẫn xác minh được chữ ký cũ.
        """
        return any(e.key_id == key_id and e.covers(moment) for e in self.entries)

    def add(self, entry: TrustEntry) -> None:
        """Thêm hoặc thay một mục. Trùng ``key_id`` thì ghi đè mục cũ."""
        for i, e in enumerate(self.entries):
            if e.key_id == entry.key_id:
                self.entries[i] = entry
                return
        self.entries.append(entry)

    def to_dict(self) -> dict:
        """Sắp xếp mục theo key_id để hai lần ghi cùng nội dung cho cùng tệp."""
        return {
            "version": self.version,
            "created_at": _s(self.created_at),
            "note": self.note,
            "entries": [
                {
                    "key_id": e.key_id,
                    "valid_from": _s(e.valid_from),
                    "valid_to": _s(e.valid_to),
                }
                for e in sorted(self.entries, key=lambda x: x.key_id)
            ],
        }

    def save(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
        )

    @staticmethod
    def load(path: str | Path) -> "TrustList":
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        return TrustList(
            version=d["version"],
            created_at=_dt(d["created_at"]),
            note=d.get("note", ""),
            entries=[
                TrustEntry(
                    key_id=e["key_id"],
                    valid_from=_dt(e["valid_from"]),
                    valid_to=_dt(e["valid_to"]),
                )
                for e in d["entries"]
            ],
        )

    @staticmethod
    def latest_in(dir_path: str | Path) -> "TrustList | None":
        """Đọc trust list có số phiên bản cao nhất trong thư mục.

        So theo SỐ phiên bản chứ không theo tên tệp: sắp xếp chuỗi sẽ đặt
        v10 trước v2, và từ phiên bản thứ mười trở đi hệ thống sẽ âm thầm
        dùng nhầm trust list cũ.
        """
        files = list(Path(dir_path).glob("trust_list_v*.json"))
        if not files:
            return None
        return TrustList.load(max(files, key=lambda p: int(p.stem.split("v")[-1])))


class KeyRotationService:
    """Luân chuyển khóa với giai đoạn chồng lấn (FR-16).

    Mặc định 14 ngày. Giai đoạn này tồn tại vì không phải máy nào cũng cập
    nhật trust list ngay lúc luân chuyển. Cắt khóa cũ lập tức sẽ làm mọi chữ
    ký cũ bị từ chối oan trong khi chúng hoàn toàn hợp lệ, và người dùng sẽ
    học được thói quen bỏ qua cảnh báo xác minh — tệ hơn nhiều so với rủi ro
    mà việc cắt sớm định ngăn chặn.
    """

    def __init__(self, keys_dir: str | Path = "keys", overlap_days: int = 14) -> None:
        self.keys_dir = Path(keys_dir)
        self.overlap_days = overlap_days

    def publish_initial(self, key_id: str, now: datetime, note: str = "") -> TrustList:
        """Phát hành trust list phiên bản 1 với một khóa duy nhất."""
        tl = TrustList(
            version=1,
            created_at=now,
            entries=[TrustEntry(key_id=key_id, valid_from=now)],
            note=note or "Phat hanh lan dau",
        )
        tl.save(self.keys_dir / "trust_list_v1.json")
        return tl

    def rotate(self, old_key_id: str, new_key_id: str, now: datetime) -> TrustList:
        """Phát hành trust list phiên bản mới khi luân chuyển khóa.

        Khóa cũ giữ hiệu lực thêm ``overlap_days`` ngày; khóa mới hiệu lực
        ngay. Quá giai đoạn chồng lấn, chữ ký bằng khóa cũ trả KEY_EXPIRED.

        Lưu ý về mã lý do: khóa cũ vẫn NẰM TRONG danh sách, chỉ là ngoài
        khoảng hiệu lực. Nhờ vậy VerificationService phân biệt được "hết hạn"
        với "chưa bao giờ được tin" — hai tình huống có cách xử lý khác nhau.
        """
        current = TrustList.latest_in(self.keys_dir)
        version = (current.version + 1) if current else 1
        entries: list[TrustEntry] = []

        if current:
            for e in current.entries:
                if e.key_id == old_key_id:
                    entries.append(
                        TrustEntry(
                            key_id=e.key_id,
                            valid_from=e.valid_from,
                            valid_to=now + timedelta(days=self.overlap_days),
                        )
                    )
                else:
                    entries.append(e)

        entries.append(TrustEntry(key_id=new_key_id, valid_from=now))

        tl = TrustList(
            version=version,
            created_at=now,
            entries=entries,
            note=(
                f"Luan chuyen tu {old_key_id} sang {new_key_id}, "
                f"chong lan {self.overlap_days} ngay"
            ),
        )
        tl.save(self.keys_dir / f"trust_list_v{version}.json")
        return tl

    def revoke_in_trust_list(
        self, key_id: str, revoked_at: datetime, now: datetime
    ) -> TrustList:
        """Phát hành trust list mới, cắt hiệu lực khóa bị thu hồi.

        Cắt tại thời điểm NGHI NGỜ BỊ LỘ, không phải hôm nay. Khoảng giữa
        lúc khóa bị lộ và lúc phát hiện ra thường dài hàng tuần, và mọi chữ
        ký tạo trong khoảng đó đều không đáng tin dù lúc ấy chưa ai biết.

        Khác với ``rotate``: ở đây không có giai đoạn chồng lấn. Chồng lấn
        là để người dùng kịp chuyển đổi êm thấm; thu hồi là tình huống khẩn
        cấp, kéo dài hiệu lực thêm một ngày nào cũng là kéo dài thiệt hại.
        """
        current = TrustList.latest_in(self.keys_dir)
        version = (current.version + 1) if current else 1
        entries: list[TrustEntry] = []
        if current:
            for e in current.entries:
                if e.key_id == key_id:
                    entries.append(
                        TrustEntry(
                            key_id=e.key_id,
                            valid_from=e.valid_from,
                            valid_to=revoked_at,
                        )
                    )
                else:
                    entries.append(e)
        tl = TrustList(
            version=version,
            created_at=now,
            entries=entries,
            note=f"Thu hoi khoa {key_id} tu {_s(revoked_at)}",
        )
        tl.save(self.keys_dir / f"trust_list_v{version}.json")
        return tl
