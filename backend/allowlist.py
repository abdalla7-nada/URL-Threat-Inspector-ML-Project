"""
Enterprise Trust Tier - High-Reputation Domain Allowlist.

Provides deterministic, sub-millisecond reputation verification for verified global
root domains (e.g. Wikipedia, Google, Microsoft, Apple, GitHub, Amazon, Cloudflare).
Prevents zero-length path False Positives on top-tier root domains while strictly
blocking adversary subdomains and homograph spoofing attempts.
"""

from typing import FrozenSet, Optional


# Canonical set of verified global enterprise root domains
ENTERPRISE_TRUSTED_DOMAINS: FrozenSet[str] = frozenset({
    # Global Knowledge & Non-profit (Wikipedia & Wikimedia)
    "wikipedia.org",
    "wikipedia.com",
    "wikipedia.net",
    "m.wikipedia.org",
    "wikimedia.org",
    "wiktionary.org",
    "wikidata.org",
    "archive.org",
    "arxiv.org",
    "nih.gov",
    "cdc.gov",
    "who.int",

    # Search & Cloud Providers (Google)
    "google.com",
    "google.net",
    "google.org",
    "google.co.uk",
    "google.com.eg",
    "googleapis.com",
    "googlevideo.com",
    "gstatic.com",
    "youtube.com",
    "gmail.com",

    # Microsoft
    "microsoft.com",
    "microsoft.net",
    "microsoft.org",
    "microsoftonline.com",
    "office.com",
    "live.com",
    "azure.com",
    "bing.com",
    "windows.com",
    "visualstudio.com",

    # Apple
    "apple.com",
    "icloud.com",

    # Amazon
    "amazon.com",
    "aws.amazon.com",
    "amazon.eg",
    "cloudflare.com",

    # Developer & Open-Source Platforms
    "github.com",
    "pages.github.com",
    "gitlab.com",
    "bitbucket.org",
    "stackoverflow.com",
    "stackexchange.com",
    "docker.com",
    "pypi.org",
    "python.org",
    "npmjs.com",
    "mozilla.org",
    "w3.org",

    # Enterprise SaaS & Business Systems
    "salesforce.com",
    "slack.com",
    "zoom.us",
    "atlassian.com",
    "dropbox.com",
    "notion.so",
    "figma.com",
    "stripe.com",
    "paypal.com",
    "oracle.com",
    "ibm.com",
    "cisco.com",
    "intel.com",
    "nvidia.com",

    # Media & Social Platforms
    "linkedin.com",
    "twitter.com",
    "x.com",
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "meta.com",
    "reddit.com",
    "netflix.com",
    "spotify.com",
    "nytimes.com",
    "cnn.com",
    "bbc.com",
    "bbc.co.uk",
    "unsplash.com",
})

# Multi-tenant cloud hosting root domains where users or adversaries can deploy unvetted content.
# These MUST NEVER be allowlisted at root or subdomain level.
SHARED_MULTI_TENANT_DOMAINS: FrozenSet[str] = frozenset({
    "github.io",
    "vercel.app",
    "firebaseapp.com",
    "web.app",
    "pages.dev",
    "workers.dev",
    "netlify.app",
    "herokuapp.com",
    "azurewebsites.net",
    "amazonaws.com",
    "s3.amazonaws.com",
    "googleusercontent.com",
    "glitch.me",
    "surge.sh",
    "ngrok-free.app",
    "ngrok.io",
})


def is_allowlisted_domain(registered_domain: Optional[str]) -> bool:
    """
    Check if a normalized registered root domain or host is present in the enterprise allowlist.
    Enforces strict isolation of shared multi-tenant hosting platforms.

    :param registered_domain: Normalized root domain or host (e.g. 'wikipedia.org', 'google.com').
    :return: True if the domain is verified in the enterprise trust tier, False otherwise.
    """
    if not registered_domain:
        return False
    domain_clean = registered_domain.lower().strip()

    # Strictly reject shared multi-tenant domains and their subdomains
    if domain_clean in SHARED_MULTI_TENANT_DOMAINS or any(
        domain_clean.endswith("." + mtd) for mtd in SHARED_MULTI_TENANT_DOMAINS
    ):
        return False

    return domain_clean in ENTERPRISE_TRUSTED_DOMAINS
