"""A provider is one source even if it publishes several feeds."""

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
    Source("blocklist_de", "Blocklist.de", (
        Feed("all", "https://lists.blocklist.de/lists/all.txt", "ip", "blocklist_de.txt"),
    )),
    Source("cins_army", "CINS Army", (
        Feed("ip", "https://cinsscore.com/list/ci-badguys.txt", "ip", "cins_army.txt"),
    )),
    Source("threatview", "ThreatView", (
        Feed("ip", "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt",
             "ip", "threatview_ip.txt"),
        Feed("domain", "https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt",
             "domain", "threatview_domain.txt"),
    )),
)
