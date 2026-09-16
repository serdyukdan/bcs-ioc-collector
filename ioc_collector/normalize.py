"""Conservative normalization: compare the pair (type, value), never substrings."""

from dataclasses import dataclass
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}


@dataclass(frozen=True, order=True)
class Indicator:
    type: str
    value: str


def normalize(raw: str, expected: str = "auto") -> Indicator:
    """Normalize explicitly typed indicators without widening their scope.

    Validate syntax only; do not resolve domains or contact indicator addresses.
    The built-in IDNA codec uses IDNA 2003 (see README for limitations).
    """
    if not isinstance(raw, str):
        raise ValueError("IoC must be a string")
    if expected not in {"auto", "ip", "domain", "url", "ip_port", *HASH_LENGTHS}:
        raise ValueError(f"Unsupported feed type: {expected}")
    value = raw.strip().replace("[.]", ".").replace("(.)", ".")
    if not value or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Empty value or whitespace/control character inside IoC")
    if expected in HASH_LENGTHS:
        if not re.fullmatch(r"[0-9a-fA-F]{%d}" % HASH_LENGTHS[expected], value):
            raise ValueError(f"Invalid {expected} hash")
        return Indicator(expected, value.lower())
    if expected == "ip_port":
        host, separator, port = value.rpartition(":")
        if not separator or not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError("Invalid IP:port")
        if ":" in host and not (host.startswith("[") and host.endswith("]")):
            raise ValueError("IPv6 endpoints must use [address]:port")
        address = normalize(host, "ip")
        host = f"[{address.value}]" if address.type == "ipv6" else address.value
        return Indicator("ip_port", f"{host}:{int(port)}")
    if expected == "url":
        value = re.sub(r"^hxxps:", "https:", value, flags=re.I)
        value = re.sub(r"^hxxp:", "http:", value, flags=re.I)
        try:
            parts = urlsplit(value)
            if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
                raise ValueError("Only absolute HTTP(S) URLs are supported")
            if "\\" in parts.netloc or parts.netloc.endswith(":"):
                raise ValueError("Invalid URL authority")
            host = normalize(parts.hostname)
            authority = f"[{host.value}]" if host.type == "ipv6" else host.value
            port = parts.port
            if port is not None and not 1 <= port <= 65535:
                raise ValueError("Invalid URL port")
            if port is not None and (parts.scheme.lower(), port) not in {("http", 80), ("https", 443)}:
                authority += f":{port}"
            # Userinfo, path case, query order, escapes and fragments can matter.
            if "@" in parts.netloc:
                authority = parts.netloc.rpartition("@")[0] + "@" + authority
            normalized = urlunsplit((parts.scheme.lower(), authority, parts.path or "/",
                                    parts.query, parts.fragment))
            # Preserve explicit empty query/fragment delimiters as well.
            if "?" in value.split("#", 1)[0] and not parts.query:
                base, marker, fragment = normalized.partition("#")
                normalized = base + "?" + (marker + fragment if marker else "")
            if value.endswith("#") and not parts.fragment:
                normalized += "#"
            return Indicator("url", normalized)
        except (ValueError, UnicodeError):
            raise ValueError("Invalid HTTP(S) URL") from None
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
