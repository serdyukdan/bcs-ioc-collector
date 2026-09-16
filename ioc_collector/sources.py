"""Three datasets; multiple feeds of one dataset count as one source."""

from dataclasses import dataclass
import os
from urllib.parse import quote


@dataclass(frozen=True)
class Feed:
    name: str
    url: str
    kind: str
    demo_file: str
    auth_env: str | None = None
    auth_required: bool = False
    data: bytes | None = None
    content_type: str | None = None

    def request_parameters(self) -> tuple[str, dict[str, str], bytes | None]:
        """Read credentials at request time; never put their values in errors."""
        key = os.environ.get(self.auth_env, "").strip() if self.auth_env else ""
        if self.auth_required and not key:
            raise ValueError(f"Set {self.auth_env} to your free abuse.ch Auth-Key; "
                             "see README. Use --demo for an offline run.")
        if any(ord(c) < 33 or ord(c) > 126 for c in key):
            raise ValueError(f"Invalid characters in {self.auth_env}")
        url = self.url
        headers = {}
        if "{auth_key}" in url:
            url = url.replace("{auth_key}", quote(key, safe=""))
        elif "{optional_key}" in url:
            url = url.replace("{optional_key}", quote(key, safe="") + "/" if key else "")
        elif key:
            headers["Auth-Key"] = key
        if self.content_type:
            headers["Content-Type"] = self.content_type
        return url, headers, self.data


@dataclass(frozen=True)
class Source:
    id: str
    name: str
    feeds: tuple[Feed, ...]


SOURCES = (
    Source("phishtank", "PhishTank", (
        Feed("online-valid", "https://data.phishtank.com/data/{optional_key}online-valid.csv",
             "phishtank", "phishtank.csv", auth_env="PHISHTANK_APP_KEY"),
    )),
    Source("threatfox", "ThreatFox", (
        Feed("recent-7-days", "https://threatfox-api.abuse.ch/api/v1/",
             "threatfox", "threatfox.json", auth_env="ABUSECH_AUTH_KEY", auth_required=True,
             data=b'{"query":"get_iocs","days":7}', content_type="application/json"),
    )),
    Source("malwarebazaar", "MalwareBazaar", (
        Feed("recent-48-hours", "https://mb-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv",
             "malwarebazaar", "malwarebazaar.csv", auth_env="ABUSECH_AUTH_KEY", auth_required=True),
    )),
)
