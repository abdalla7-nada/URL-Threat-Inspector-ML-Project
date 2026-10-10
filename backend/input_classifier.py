"""
Upfront Input Classification Gateway for URL Threat Assessment API.

Performs syntactic and semantic gateway validation on raw user input before
LightGBM inference or domain allowlist matching.
Catches plain-text search queries, executable/dangerous schemes, and internal loopback targets.
"""

from enum import Enum
import ipaddress
import re
from typing import Any, Dict, Optional, Union
import urllib.parse

import tldextract


class InputCategory(str, Enum):
    """Classification taxonomy for incoming inspection targets."""
    PLAIN_TEXT = "PLAIN_TEXT"
    DANGEROUS_SCHEME = "DANGEROUS_SCHEME"
    INTERNAL_HOST = "INTERNAL_HOST"
    VALID_URL = "VALID_URL"


# Dangerous or executable URI schemes that represent injection/XSS vectors
DANGEROUS_SCHEMES = (
    "javascript:",
    "data:",
    "file:",
    "blob:",
    "vbscript:",
    "about:",
)

# Standard schemes for routable web protocols
STANDARD_SCHEMES = ("http://", "https://")

# Common loopback and non-routable hostnames
INTERNAL_HOSTNAMES = {
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "ip6-localhost",
    "ip6-loopback",
}

# Credential harvesting / phishing lures that distinguish malicious router attacks
LURE_WORDS = (
    "login",
    "signin",
    "verify",
    "account",
    "password",
    "secure",
    "update",
    "banking",
    "confirm",
    "wallet",
)

# Canonical set of public URL redirection and shortening services
KNOWN_SHORTENERS = frozenset({
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "cutt.ly",
    "is.gd",
    "ow.ly",
    "rb.gy",
    "shorturl.at",
    "bl.ink",
})

# Initialize offline TLD extractor instance
_TLD_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=(),
    include_psl_private_domains=True,
)


def canonicalize_ip_host(host_str: str) -> Optional[str]:
    """
    Normalizes standard IPv4, bracketed IPv6, and alternative IP representations
    (dword integer, hex, octal, dotted-hex/octal) into standard dotted-decimal notation.
    Returns None if the host string is not an IP address.
    """
    if not host_str:
        return None
    clean = host_str.strip().strip("[]")
    candidate = clean
    if ":" in clean and not clean.startswith("0x"):
        if clean.count(":") == 1:
            candidate = clean.split(":")[0]

    # 1. Standard ipaddress parser (IPv4 and IPv6)
    try:
        ip = ipaddress.ip_address(candidate)
        return str(ip)
    except ValueError:
        pass

    # 2. Integer dword (e.g. 2130706433 -> 127.0.0.1)
    # Range 16777216 (1.0.0.0) to 4294967295 (255.255.255.255) ensures small numbers like '12345'
    # are not misclassified as IP addresses.
    if candidate.isdigit():
        try:
            val = int(candidate, 10)
            if 16777216 <= val <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(val))
        except (ValueError, OverflowError):
            pass

    # 3. Hexadecimal integer (e.g. 0x7f000001 -> 127.0.0.1)
    if candidate.lower().startswith("0x"):
        try:
            val = int(candidate, 16)
            if 16777216 <= val <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(val))
        except (ValueError, OverflowError):
            pass

    # 4. Octal single number (e.g. 017700000001 -> 127.0.0.1)
    if candidate.startswith("0") and len(candidate) > 1 and all(c in "01234567" for c in candidate):
        try:
            val = int(candidate, 8)
            if 16777216 <= val <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(val))
        except (ValueError, OverflowError):
            pass

    # 5. Dotted format with hex or octal octets (e.g. 0x7f.0.0.1, 0177.0.0.1)
    parts = candidate.split(".")
    if len(parts) == 4:
        try:
            octets = []
            for p in parts:
                if p.lower().startswith("0x"):
                    octets.append(int(p, 16))
                elif p.startswith("0") and len(p) > 1 and all(c in "01234567" for c in p):
                    octets.append(int(p, 8))
                elif p.isdigit():
                    octets.append(int(p, 10))
                else:
                    return None
            if all(0 <= o <= 255 for o in octets):
                return str(ipaddress.IPv4Address(bytes(octets)))
        except (ValueError, OverflowError):
            pass

    return None


def parse_ip_address(host_str: str) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
    """Parse string into IPv4 or IPv6 address, safely handling bracketed IPv6, ports, and alt formats."""
    canon = canonicalize_ip_host(host_str)
    if canon:
        try:
            return ipaddress.ip_address(canon)
        except ValueError:
            pass
    return None


def _is_ip_internal(host_str: str) -> bool:
    """Check if host string is a valid private, loopback, link-local, or reserved IP."""
    ip = parse_ip_address(host_str)
    if not ip:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified


def classify_input_string(raw_input: Optional[str]) -> Dict[str, Any]:
    """
    Evaluates and classifies raw input string into one of four taxonomic categories:
    - PLAIN_TEXT: Non-URL text, search queries, single alphanumeric tokens without TLD.
    - DANGEROUS_SCHEME: Executable or local scheme (javascript:, data:, file:, etc.).
    - INTERNAL_HOST: Loopback, localhost, link-local, or private RFC1918 infrastructure.
    - VALID_URL: Routable web target with valid domain, public suffix, or IP address.

    :param raw_input: Raw input string from client payload.
    :return: Dictionary containing 'category' (InputCategory), 'normalized_url' (str), and 'message' (str).
    """
    if raw_input is None:
        raw_clean = ""
    elif isinstance(raw_input, str):
        raw_clean = raw_input.strip()
    else:
        raw_clean = str(raw_input).strip()

    if not raw_clean:
        return {
            "category": InputCategory.PLAIN_TEXT,
            "normalized_url": "",
            "message": "Input string is empty or whitespace-only.",
            "is_shortener": False,
        }

    lower_input = raw_clean.lower()

    # 1. Dangerous & Executable URI Schemes
    for ds in DANGEROUS_SCHEMES:
        if lower_input.startswith(ds):
            return {
                "category": InputCategory.DANGEROUS_SCHEME,
                "normalized_url": raw_clean,
                "message": (
                    f"High-risk executable or local resource URI scheme detected ('{ds}'). "
                    "Potential script injection or browser exploit vector."
                ),
                "is_shortener": False,
            }

    # 2. Plain-Text Detection: Spaces without standard web protocol
    if " " in raw_clean:
        # Check if the string lacks http:// or https://
        if not (lower_input.startswith("http://") or lower_input.startswith("https://")):
            return {
                "category": InputCategory.PLAIN_TEXT,
                "normalized_url": raw_clean,
                "message": "Input contains whitespace characters without a resolvable web protocol.",
                "is_shortener": False,
            }
        # If it has http:// or https://, check if hostname itself contains spaces
        try:
            parts = urllib.parse.urlsplit(raw_clean)
            if not parts.hostname or " " in parts.hostname:
                return {
                    "category": InputCategory.PLAIN_TEXT,
                    "normalized_url": raw_clean,
                    "message": "Host segment contains spaces, violating RFC 3986 URL specification.",
                    "is_shortener": False,
                }
        except Exception:
            return {
                "category": InputCategory.PLAIN_TEXT,
                "normalized_url": raw_clean,
                "message": "Input could not be parsed as a valid URI structure.",
                "is_shortener": False,
            }

    # 3. Host and Path Parsing
    parse_target = raw_clean
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", parse_target) and not parse_target.startswith("//"):
        parse_target = "//" + parse_target

    try:
        parsed = urllib.parse.urlsplit(parse_target)
        host = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
    except Exception:
        # Resilient fallback for malformed URLs (e.g. unclosed IPv6 bracket like http://[2001:db8::1/path)
        if "//" in parse_target:
            remainder = parse_target.split("//", 1)[1]
        else:
            remainder = parse_target
        parts = remainder.split("/", 1)
        host = parts[0].split("?", 1)[0].split("#", 1)[0]
        path = "/" + parts[1] if len(parts) > 1 else ""
        query = ""

    host_lower = host.lower()

    # 4. Internal Infrastructure & Loopback Target Detection
    is_named_internal = (
        host_lower in INTERNAL_HOSTNAMES
        or host_lower.endswith((".local", ".internal", ".localhost", ".lan"))
    )

    if is_named_internal:
        norm_scheme = "http://" if not lower_input.startswith(STANDARD_SCHEMES) else ""
        norm_url = f"{norm_scheme}{raw_clean}" if norm_scheme else raw_clean
        return {
            "category": InputCategory.INTERNAL_HOST,
            "normalized_url": norm_url,
            "message": (
                f"Target resolves to internal or loopback host ('{host_lower}'). "
                "Not a publicly routable internet domain."
            ),
            "is_shortener": False,
        }

    if _is_ip_internal(host_lower):
        # Differentiate pure internal targets (e.g. localhost/bare router) from active credential lure attacks
        has_phishing_lures = any(w in lower_input for w in LURE_WORDS)
        if has_phishing_lures:
            # Active attack vector targeting network management credentials -> evaluate via ML pipeline
            pass
        else:
            norm_scheme = "http://" if not lower_input.startswith(STANDARD_SCHEMES) else ""
            norm_url = f"{norm_scheme}{raw_clean}" if norm_scheme else raw_clean
            return {
                "category": InputCategory.INTERNAL_HOST,
                "normalized_url": norm_url,
                "message": (
                    f"Target resolves to private/loopback RFC1918 address ('{host_lower}'). "
                    "Not a publicly routable internet endpoint."
                ),
                "is_shortener": False,
            }

    # 5. Public Suffix (TLD) and Domain Integrity Verification
    if not host and not raw_clean.startswith(("/", "?", "#")):
        return {
            "category": InputCategory.PLAIN_TEXT,
            "normalized_url": raw_clean,
            "message": (
                "Incomplete URL: Missing or invalid top-level domain suffix (e.g., .com, .org). "
                "Please specify a complete domain target."
            ),
            "is_shortener": False,
        }

    if host:
        is_ip = bool(parse_ip_address(host_lower))
        if not is_ip:
            tld_info = _TLD_EXTRACTOR(host_lower)
            has_invalid_dots = (
                ".." in host_lower
                or host_lower.endswith(".")
                or host_lower.startswith(".")
            )
            # Enforce strict public suffix presence (rejects https://www.wikipedia, https://google., test..com)
            if not tld_info.suffix or not tld_info.domain or has_invalid_dots:
                return {
                    "category": InputCategory.PLAIN_TEXT,
                    "normalized_url": raw_clean,
                    "message": (
                        "Incomplete URL: Missing or invalid top-level domain suffix (e.g., .com, .org). "
                        "Please specify a complete domain target."
                    ),
                    "is_shortener": False,
                }

    # 6. URL Shortener Service Detection Heuristic
    is_shortener = False
    if host:
        tld_info_shortener = _TLD_EXTRACTOR(host_lower)
        reg_domain = (
            f"{tld_info_shortener.domain}.{tld_info_shortener.suffix}".lower()
            if tld_info_shortener.domain and tld_info_shortener.suffix
            else host_lower
        )
        if (
            host_lower in KNOWN_SHORTENERS
            or reg_domain in KNOWN_SHORTENERS
            or any(host_lower.endswith("." + s) for s in KNOWN_SHORTENERS)
        ):
            is_shortener = True

    # 7. Valid Web Target Normalization
    if raw_clean.startswith("//"):
        normalized = "https:" + raw_clean
    elif not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_clean):
        if raw_clean.startswith("/") or raw_clean.startswith("?"):
            normalized = raw_clean
        else:
            normalized = "https://" + raw_clean
    else:
        normalized = raw_clean

    return {
        "category": InputCategory.VALID_URL,
        "normalized_url": normalized,
        "message": "Well-formed web target ready for lexical forensic inspection.",
        "is_shortener": is_shortener,
    }
