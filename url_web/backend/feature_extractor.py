"""
URL Feature Extractor for Phishing URL Detection.

Extracts lexical, structural, statistical, and domain-based features from raw URLs.
Hardened for malformed and adversarial URLs.
Protocol-recording features ('scheme_known', 'has_https') are intentionally excluded
to eliminate protocol-recording bias.
"""

from collections import Counter
from functools import lru_cache
import ipaddress
import math
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Union
from urllib.parse import urlsplit

import pandas as pd
import tldextract

# Lure words commonly found in phishing campaigns
SUSPICIOUS_LURES = (
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

# Standard URL scheme pattern
SCHEME_REGEX = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

# Special characters considered in lexical analysis
SPECIAL_CHARS = set(".-/@?=&%_:+~#")


def compute_shannon_entropy(text: str) -> float:
    """
    Compute Shannon entropy of characters in a string in bits: -sum(p * log2(p)).

    Returns 0.0 for empty or single-character strings.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)


class URLFeatureExtractor:
    """
    Extracts 29 numerical and categorical features from raw URLs.
    Hardened against malformed, unparseable, or adversarial input strings.
    """

    def __init__(self, top_tlds: Optional[Iterable[str]] = None) -> None:
        """
        Initialize the feature extractor.

        :param top_tlds: Optional iterable of top frequent TLDs. If provided,
                         extracted TLDs not in this collection are mapped to 'other'.
        """
        self.top_tlds: Optional[Set[str]] = (
            {tld.lower().strip() for tld in top_tlds if tld}
            if top_tlds is not None
            else None
        )
        self._tld_extractor = tldextract.TLDExtract(
            suffix_list_urls=(),
            include_psl_private_domains=True,
        )
        # Bounded in-memory cache for fast repeated host extraction
        self._host_tld_cache: Dict[str, Any] = {}

    def _get_tld_info(self, host: str):
        """Extract and cache suffix/subdomain details for a hostname."""
        if not host:
            return None
        cached = self._host_tld_cache.get(host)
        if cached is None:
            # Keep cache bounded to avoid memory leaks in long-running services
            if len(self._host_tld_cache) > 200_000:
                self._host_tld_cache.clear()
            cached = self._tld_extractor(host)
            self._host_tld_cache[host] = cached
        return cached

    def extract(self, url: str) -> Dict[str, Union[int, float, str]]:
        """
        Extract features from a single raw URL.

        Guaranteed not to raise an unhandled exception on any malformed input.
        """
        # 1. Input sanitization
        if url is None:
            raw_url = ""
        elif isinstance(url, str):
            raw_url = url.strip()
        else:
            raw_url = str(url).strip()

        # 2. Scheme normalization for safe hostname parsing
        parse_target = raw_url
        if not SCHEME_REGEX.match(parse_target) and not parse_target.startswith("//"):
            parse_target = "//" + parse_target

        try:
            parsed = urlsplit(parse_target)
            host = parsed.hostname or ""
            path = parsed.path or ""
            query = parsed.query or ""
        except Exception:
            # Fallback for malformed URLs (e.g. unclosed IPv6 brackets)
            host = ""
            path = ""
            query = ""
            if "//" in parse_target:
                remainder = parse_target.split("//", 1)[1]
            else:
                remainder = parse_target
            parts = remainder.split("/", 1)
            host = parts[0].split("?", 1)[0].split("#", 1)[0]
            if len(parts) > 1:
                path_query = parts[1].split("?", 1)
                path = "/" + path_query[0]
                if len(path_query) > 1:
                    query = path_query[1].split("#", 1)[0]

        # 3. Protocol stripping for raw URL lexical measurements
        text = SCHEME_REGEX.sub("", raw_url)
        if text.startswith("//"):
            text = text[2:]
        text_len = len(text)

        # 4. Lexical character counts
        digits = 0
        special_count = 0
        for char in text:
            if char.isdigit():
                digits += 1
            if char in SPECIAL_CHARS:
                special_count += 1

        dot_count = text.count(".")
        hyphen_count = text.count("-")
        at_count = text.count("@")
        slash_count = text.count("/")
        question_count = text.count("?")
        equal_count = text.count("=")
        amp_count = text.count("&")
        percent_count = text.count("%")
        underscore_count = text.count("_")

        # 5. Domain and host metrics
        host_lower = host.lower()
        tld_info = self._get_tld_info(host_lower)

        raw_suffix = (
            tld_info.suffix.lower() if tld_info and tld_info.suffix else ""
        )
        subdomain = tld_info.subdomain if tld_info and tld_info.subdomain else ""

        # Map TLD against top_tlds or fallback to 'other'
        if self.top_tlds is not None:
            tld = raw_suffix if raw_suffix in self.top_tlds else "other"
        else:
            tld = raw_suffix if raw_suffix else "other"

        tld_length = len(raw_suffix)
        subdomain_count = len(subdomain.split(".")) if subdomain else 0

        host_digit_count = sum(1 for c in host if c.isdigit())
        host_hyphen_count = host.count("-")
        host_entropy = compute_shannon_entropy(host)

        # 6. Suspicious lures count in total, host, and path
        text_lower = text.lower()
        path_lower = path.lower()

        suspicious_count = sum(1 for word in SUSPICIOUS_LURES if word in text_lower)
        host_suspicious_count = sum(
            1 for word in SUSPICIOUS_LURES if word in host_lower
        )
        path_suspicious_count = sum(
            1 for word in SUSPICIOUS_LURES if word in path_lower
        )

        # 7. Structural metrics
        path_depth = sum(1 for segment in path.split("/") if segment)
        param_count = sum(1 for param in query.split("&") if param)
        digit_ratio = (digits / text_len) if text_len > 0 else 0.0

        # IP address check (handles IPv4 and IPv6)
        is_ip = 0
        clean_host = host.strip("[]")
        if clean_host:
            try:
                ipaddress.ip_address(clean_host)
                is_ip = 1
            except ValueError:
                is_ip = 0

        # Punycode check
        has_punycode = 1 if "xn--" in host_lower else 0

        # Note: 'scheme_known' and 'has_https' are STRICTLY EXCLUDED
        return {
            "url_length": text_len,
            "domain_length": len(host),
            "path_length": len(path),
            "query_length": len(query),
            "dot_count": dot_count,
            "digit_count": digits,
            "hyphen_count": hyphen_count,
            "at_count": at_count,
            "slash_count": slash_count,
            "question_count": question_count,
            "equal_count": equal_count,
            "amp_count": amp_count,
            "percent_count": percent_count,
            "underscore_count": underscore_count,
            "special_count": special_count,
            "subdomain_count": subdomain_count,
            "host_digit_count": host_digit_count,
            "host_hyphen_count": host_hyphen_count,
            "digit_ratio": float(digit_ratio),
            "path_depth": path_depth,
            "param_count": param_count,
            "has_ip": is_ip,
            "has_punycode": has_punycode,
            "suspicious_count": suspicious_count,
            "host_suspicious_count": host_suspicious_count,
            "path_suspicious_count": path_suspicious_count,
            "host_entropy": host_entropy,
            "tld": tld,
            "tld_length": tld_length,
        }

    def extract_many(self, urls: Iterable[str]) -> List[Dict[str, Any]]:
        """Extract features for an iterable of URLs."""
        return [self.extract(url) for url in urls]

    def to_dataframe(
        self,
        urls_or_features: Union[Iterable[str], List[Dict[str, Any]]],
        categories: Optional[List[str]] = None,
    ) -> pd.DataFrame:
        """
        Convert URLs or extracted feature dicts into a pandas DataFrame ready for LightGBM.
        Properly formats the 'tld' column as categorical if categories are provided.
        """
        if not urls_or_features:
            return pd.DataFrame()

        first = next(iter(urls_or_features))
        if isinstance(first, dict):
            df = pd.DataFrame(urls_or_features)
        else:
            df = pd.DataFrame([self.extract(u) for u in urls_or_features])

        if categories is not None and "tld" in df.columns:
            df["tld"] = pd.Categorical(df["tld"], categories=categories)
        elif self.top_tlds is not None and "tld" in df.columns:
            cat_list = sorted(list(self.top_tlds)) + ["other"]
            df["tld"] = pd.Categorical(df["tld"], categories=cat_list)

        return df
