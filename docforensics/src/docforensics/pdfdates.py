"""PDF / XMP date parsing and dialect classification."""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from typing import Any

_PDF_DATE = re.compile(
    r"^(?P<prefix>D:)?(?P<y>\d{4})(?P<mo>\d{2})?(?P<d>\d{2})?(?P<h>\d{2})?(?P<mi>\d{2})?(?P<s>\d{2})?"
    r"(?P<tz>Z|[+-]\d{2}(?:'\d{2}'?)?)?\s*$"
)


@dataclass
class DateDialect:
    literal: str
    has_d_prefix: bool
    has_seconds: bool
    tz_form: str        # none | Z | +HH'mm' | +HH'mm | +HH
    parsed: bool

    @property
    def key(self) -> str:
        return f"{'D' if self.has_d_prefix else '-'}|{'s' if self.has_seconds else '-'}|{self.tz_form}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["key"] = self.key
        return d


def classify_pdf_date(s: str) -> DateDialect:
    m = _PDF_DATE.match(s.strip())
    if not m:
        return DateDialect(s, s.startswith("D:"), False, "unparsed", False)
    tz = m.group("tz") or ""
    if tz == "":
        form = "none"
    elif tz == "Z":
        form = "Z"
    elif re.fullmatch(r"[+-]\d{2}'\d{2}'", tz):
        form = "+HH'mm'"
    elif re.fullmatch(r"[+-]\d{2}'\d{2}", tz):
        form = "+HH'mm"
    else:
        form = "+HH"
    return DateDialect(s, bool(m.group("prefix")), m.group("s") is not None, form, True)


def parse_pdf_date(s: str) -> datetime | None:
    m = _PDF_DATE.match(s.strip())
    if not m:
        return None
    try:
        dt = datetime(int(m.group("y")), int(m.group("mo") or 1), int(m.group("d") or 1),
                      int(m.group("h") or 0), int(m.group("mi") or 0), int(m.group("s") or 0))
    except ValueError:
        return None
    tz = m.group("tz")
    if not tz or tz == "Z":
        return dt.replace(tzinfo=timezone.utc)
    sign = 1 if tz[0] == "+" else -1
    hh = int(tz[1:3])
    mm = int(tz[4:6]) if len(tz) >= 6 else 0
    return (dt - sign * timedelta(hours=hh, minutes=mm)).replace(tzinfo=timezone.utc)


def parse_xmp_date(s: str) -> datetime | None:
    s = s.strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
    except ValueError:
        # date-only or partial forms
        for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d", "%Y-%m", "%Y"):
            try:
                dt = datetime.strptime(s, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def same_instant(a: datetime | None, b: datetime | None, tolerance_s: int = 1) -> bool | None:
    if a is None or b is None:
        return None
    return abs((a - b).total_seconds()) <= tolerance_s
