"""Three datasets; multiple feeds of one dataset count as one source."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Feed:
    name: str
    url: str
    kind: str
    demo_file: str


@dataclass(frozen=True)
class Source:
    id: str
    name: str
    feeds: tuple[Feed, ...]


SOURCES = (
    Source("phishtank", "PhishTank", (
        Feed("online-valid", "https://data.phishtank.com/data/online-valid.csv",
             "phishtank", "phishtank.csv"),
    )),
    Source("threatview", "ThreatView", (
        Feed("ip", "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt",
             "ip", "threatview_ip.txt"),
        Feed("domain", "https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt",
             "domain", "threatview_domain.txt"),
        Feed("md5", "https://threatview.io/Downloads/MD5-HASH-ALL.txt",
             "md5", "threatview_md5.txt"),
    )),
    Source("blocklist_de", "Blocklist.de", (
        Feed("all", "https://lists.blocklist.de/lists/all.txt",
             "ip", "blocklist_de.txt"),
    )),
)
