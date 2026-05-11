"""
whois_lookup.py
---------------
Retrieves domain registration and ownership information via WHOIS.

WHY WHOIS MATTERS IN RECON:
- Reveals registrar and registration/expiry dates
- May expose registrant contact info if not privacy-protected
- Expiry date near? Domain might be hijackable soon
- Creation date reveals domain age → older = more trusted, newer = suspicious
- Name servers here vs DNS records can reveal discrepancies
- Organization name can link to other domains owned by the same entity
"""

import whois
from typing import Dict, Any
from datetime import datetime


def get_whois_info(domain: str) -> Dict[str, Any]:
    """
    Perform WHOIS lookup and extract structured registration data.

    Args:
        domain: Target domain string

    Returns:
        Dictionary with registrar, dates, name servers, and org info
    """
    result: Dict[str, Any] = {
        "registrar": "Unknown",
        "org": "Unknown",
        "country": "Unknown",
        "creation_date": "Unknown",
        "expiry_date": "Unknown",
        "updated_date": "Unknown",
        "name_servers": [],
        "status": [],
        "emails": [],
        "dnssec": "Unknown",
        "error": None,
    }

    try:
        w = whois.whois(domain)

        result["registrar"] = _safe_str(w.registrar)
        result["org"] = _safe_str(w.org)
        result["country"] = _safe_str(w.country)
        result["dnssec"] = _safe_str(w.dnssec)

        # Handle dates (can be list or single datetime)
        result["creation_date"] = _format_date(w.creation_date)
        result["expiry_date"] = _format_date(w.expiration_date)
        result["updated_date"] = _format_date(w.updated_date)

        # Name servers
        ns = w.name_servers
        if ns:
            if isinstance(ns, list):
                result["name_servers"] = [str(n).lower() for n in ns]
            else:
                result["name_servers"] = [str(ns).lower()]

        # Status
        status = w.status
        if status:
            if isinstance(status, list):
                result["status"] = [str(s).split(" ")[0] for s in status]
            else:
                result["status"] = [str(status).split(" ")[0]]

        # Emails
        emails = w.emails
        if emails:
            if isinstance(emails, list):
                result["emails"] = list(set(emails))[:5]
            else:
                result["emails"] = [str(emails)]

    except Exception as e:
        result["error"] = f"WHOIS lookup failed: {str(e)}"

    return result


def _safe_str(value: Any) -> str:
    """Safely convert a WHOIS field to string."""
    if value is None:
        return "Not disclosed"
    if isinstance(value, list):
        return str(value[0]) if value else "Not disclosed"
    return str(value)


def _format_date(value: Any) -> str:
    """Format a WHOIS date field (handles list or datetime)."""
    if value is None:
        return "Not disclosed"
    if isinstance(value, list):
        value = value[0]
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(value)