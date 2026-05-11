"""
dns_lookup.py
-------------
Performs DNS enumeration for A, MX, NS, TXT, and CNAME records.

WHY DNS MATTERS IN RECON:
- A records reveal the real IP behind a domain (even if CDN-protected sometimes)
- MX records expose mail infrastructure, often less hardened than web servers
- NS records show which DNS provider is used — misconfigs here = zone transfer attacks
- TXT records often leak SPF, DKIM, DMARC configs and sometimes API keys
- CNAME records can reveal internal subdomains or third-party services
"""

import dns.resolver
from typing import Dict, List


def get_dns_records(domain: str) -> Dict[str, List[str]]:
    """
    Query multiple DNS record types for a given domain.

    Args:
        domain: Target domain string (e.g., 'example.com')

    Returns:
        Dictionary mapping record type -> list of record values
    """
    record_types = ["A", "MX", "NS", "TXT", "CNAME"]
    results: Dict[str, List[str]] = {}

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=5)
            records = []
            for rdata in answers:
                if record_type == "MX":
                    records.append(f"{rdata.preference} {rdata.exchange}")
                else:
                    records.append(str(rdata))
            results[record_type] = records
        except dns.resolver.NoAnswer:
            results[record_type] = []
        except dns.resolver.NXDOMAIN:
            results[record_type] = ["[NXDOMAIN - Domain does not exist]"]
        except dns.resolver.Timeout:
            results[record_type] = ["[Timeout - DNS server did not respond]"]
        except dns.exception.DNSException as e:
            results[record_type] = [f"[Error: {str(e)}]"]

    return results


def get_reverse_dns(ip: str) -> str:
    """
    Perform reverse DNS lookup (PTR record) for an IP address.

    Args:
        ip: IPv4 address string

    Returns:
        Hostname string or error message
    """
    try:
        reversed_ip = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        answers = dns.resolver.resolve(reversed_ip, "PTR", lifetime=5)
        return str(answers[0])
    except Exception:
        return "No PTR record found"