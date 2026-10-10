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

# Initialize offline TLD extractor instance
_TLD_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=(),
    include_psl_private_domains=True,
)


def parse_ip_address(host_str: str) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
    """Parse string into IPv4 or IPv6 address, safely handling bracketed IPv6 and ports."""
    if not host_str:
        return None
    clean = host_str.strip().strip("[]")
    try:
        return ipaddress.ip_address(clean)
    except ValueError:
        pass

    # Check IPv4 with port (e.g. 192.168.1.1:8080)
    if ":" in clean:
        parts = clean.split(":")
        if len(parts) == 2:
            try:
                return ipaddress.ip_address(parts[0])
            except ValueError:
                pass
        # Check IPv6 with port (e.g. [2001:db8::1]:8080)
        candidate, _, _ = clean.rpartition(":")
        candidate_clean = candidate.strip("[]")
        try:
            return ipaddress.ip_address(candidate_clean)
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
            }

    # 2. Plain-Text Detection: Spaces without standard web protocol
    if " " in raw_clean:
        # Check if the string lacks http:// or https://
        if not (lower_input.startswith("http://") or lower_input.startswith("https://")):
            return {
                "category": InputCategory.PLAIN_TEXT,
                "normalized_url": raw_clean,
                "message": "Input contains whitespace characters without a resolvable web protocol.",
            }
        # If it has http:// or https://, check if hostname itself contains spaces
        try:
            parts = urllib.parse.urlsplit(raw_clean)
            if not parts.hostname or " " in parts.hostname:
                return {
                    "category": InputCategory.PLAIN_TEXT,
                    "normalized_url": raw_clean,
                    "message": "Host segment contains spaces, violating RFC 3986 URL specification.",
                }
        except Exception:
            return {
                "category": InputCategory.PLAIN_TEXT,
                "normalized_url": raw_clean,
                "message": "Input could not be parsed as a valid URI structure.",
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
            }

    # 5. Single alphanumeric word or number check (e.g. '12345', 'paypal', 'facebook')
    if not host and not raw_clean.startswith(("/", "?", "#", "http://", "https://", "//")):
        return {
            "category": InputCategory.PLAIN_TEXT,
            "normalized_url": raw_clean,
            "message": "Input is a single word or token without an internet domain suffix or path.",
        }

    if host:
        tld_info = _TLD_EXTRACTOR(host_lower)
        is_ip = bool(parse_ip_address(host_lower))

        if not tld_info.suffix and not is_ip:
            # Host has no registered public suffix and is not an IP address (e.g. '12345', 'justaword')
            if not raw_clean.startswith(("/", "?", "#", "//", "http://", "https://")):
                return {
                    "category": InputCategory.PLAIN_TEXT,
                    "normalized_url": raw_clean,
                    "message": f"Host '{host}' does not have a recognized Top-Level Domain (TLD).",
                }

    # 6. Valid Web Target Normalization
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
    }
