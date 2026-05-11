"""
ssl_checker.py
--------------
Inspects SSL/TLS certificates for validity, expiry, and issuer details.

HOW SSL WORKS (why this matters in recon):
- SSL certs are cryptographically signed by a Certificate Authority (CA)
- They contain the domain, issuer, validity window, and Subject Alternative Names (SANs)
- SANs often reveal OTHER domains/subdomains on the same cert → free subdomain enumeration!
- An expired cert = the org is negligent about security hygiene
- Self-signed certs on production = red flag, possible MITM vector
- The CN/issuer can reveal internal naming conventions
"""

import ssl
import socket
from datetime import datetime
from typing import Dict, Any


def get_ssl_info(domain: str, port: int = 443) -> Dict[str, Any]:
    """
    Retrieve and parse SSL certificate information for a domain.

    Args:
        domain: Target domain (e.g., 'example.com')
        port:   Port to connect to (default: 443)

    Returns:
        Dictionary with cert details, validity status, and SANs
    """
    result: Dict[str, Any] = {
        "valid": False,
        "issuer": "Unknown",
        "subject": "Unknown",
        "issued_on": "Unknown",
        "expires_on": "Unknown",
        "days_remaining": None,
        "san": [],
        "tls_version": "Unknown",
        "error": None,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result["tls_version"] = ssock.version()

                # Parse issuer
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                result["issuer"] = issuer_dict.get("organizationName", "Unknown")

                # Parse subject
                subject_dict = dict(x[0] for x in cert.get("subject", []))
                result["subject"] = subject_dict.get("commonName", domain)

                # Parse validity dates
                not_before = cert.get("notBefore", "")
                not_after = cert.get("notAfter", "")

                if not_before:
                    result["issued_on"] = datetime.strptime(
                        not_before, "%b %d %H:%M:%S %Y %Z"
                    ).strftime("%Y-%m-%d")

                if not_after:
                    expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    result["expires_on"] = expiry_dt.strftime("%Y-%m-%d")
                    delta = expiry_dt - datetime.utcnow()
                    result["days_remaining"] = delta.days
                    result["valid"] = delta.days > 0

                # Extract Subject Alternative Names
                san_list = []
                for san_type, san_value in cert.get("subjectAltName", []):
                    san_list.append(f"{san_type}: {san_value}")
                result["san"] = san_list[:15]  # Limit to first 15

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Certificate verification failed: {str(e)}"
        result["valid"] = False
    except ssl.SSLError as e:
        result["error"] = f"SSL error: {str(e)}"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = "Connection refused on port 443"
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"

    return result