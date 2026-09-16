"""Conservative normalization: compare the pair (type, value), never substrings."""

from dataclasses import dataclass
import ipaddress
import re


@dataclass(frozen=True, order=True)
class Indicator:
    type: str
    value: str


def normalize(raw: str, expected: str = "auto") -> Indicator:
    """Support the IP/domain types supplied by the configured feeds.

    Validate syntax only; do not resolve domains or contact indicator addresses.
    The built-in IDNA codec uses IDNA 2003 (see README for limitations).
    """
    if expected not in {"auto", "ip", "domain"}:
        raise ValueError(f"Unsupported feed type: {expected}")
    value = raw.strip().replace("[.]", ".").replace("(.)", ".")
    if not value or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Empty value or whitespace/control character inside IoC")
    ip_candidate = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    try:
        if "%" in ip_candidate:
            raise ValueError("Scoped IPv6 is not a public IoC")
        address = ipaddress.ip_address(ip_candidate)
    except ValueError:
        if expected == "ip":
            raise ValueError("Invalid IP address") from None
    else:
        if expected == "domain":
            raise ValueError("An IP address is not a domain")
        return Indicator(f"ipv{address.version}", address.compressed.lower())

    try:
        domain = value.encode("idna").decode("ascii").lower().removesuffix(".")
    except UnicodeError:
        raise ValueError("Invalid IDNA name") from None
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or labels[-1].isdigit():
        raise ValueError("Invalid domain length, TLD or number of labels")
    for label in labels:
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
            raise ValueError("Invalid domain label")
        if label.startswith("xn--"):
            try:
                label.encode("ascii").decode("idna")
            except UnicodeError:
                raise ValueError("Invalid punycode label") from None
    return Indicator("domain", domain)
