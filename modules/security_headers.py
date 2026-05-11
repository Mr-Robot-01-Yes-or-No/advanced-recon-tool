"""
security_headers.py
--------------------
Analyzes HTTP response headers for the presence/absence of security controls.

WHY SECURITY HEADERS MATTER:
- Content-Security-Policy (CSP): Prevents XSS by whitelisting allowed content sources
- Strict-Transport-Security (HSTS): Forces HTTPS, prevents SSL stripping attacks
- X-Frame-Options: Blocks clickjacking attacks by preventing iframe embedding
- X-Content-Type-Options: Prevents MIME-type sniffing attacks
- Referrer-Policy: Controls what info leaks via the Referer header
- Permissions-Policy: Restricts browser features (camera, mic, geolocation)
- X-XSS-Protection: Legacy XSS filter (mostly deprecated but still checked)

MISSING HEADERS = Attack surface for bug bounty findings
Analysts check these to estimate the security maturity of a target.
"""

import requests
from typing import Dict, Any

# Security headers to check with explanations
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Prevents XSS attacks by defining trusted content sources",
        "severity": "HIGH",
    },
    "Strict-Transport-Security": {
        "description": "Forces HTTPS connections (prevents SSL stripping)",
        "severity": "HIGH",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking via iframe embedding",
        "severity": "MEDIUM",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing attacks",
        "severity": "MEDIUM",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information leakage",
        "severity": "LOW",
    },
    "Permissions-Policy": {
        "description": "Restricts browser feature access (camera, mic, etc.)",
        "severity": "MEDIUM",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (deprecated but still informative)",
        "severity": "LOW",
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Isolates browsing context against cross-origin attacks",
        "severity": "MEDIUM",
    },
    "Cross-Origin-Embedder-Policy": {
        "description": "Controls cross-origin resource embedding",
        "severity": "LOW",
    },
}

# Headers that should NOT be present (information disclosure)
LEAKY_HEADERS = [
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "Server",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Varnish",
]


def analyze_headers(domain: str) -> Dict[str, Any]:
    """
    Fetch HTTP headers and analyze security posture.

    Args:
        domain: Target domain string

    Returns:
        Dictionary with present/missing security headers and server info
    """
    result: Dict[str, Any] = {
        "url": "",
        "status_code": None,
        "server": "Unknown",
        "content_type": "Unknown",
        "present_headers": {},
        "missing_headers": {},
        "leaky_headers": {},
        "all_headers": {},
        "security_score": 0,
        "error": None,
    }

    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}"
        try:
            response = requests.get(
                url,
                timeout=10,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Security-Scanner/1.0)"},
                verify=False,  # We still want data even with SSL issues
            )

            result["url"] = response.url
            result["status_code"] = response.status_code
            result["server"] = response.headers.get("Server", "Not disclosed")
            result["content_type"] = response.headers.get("Content-Type", "Unknown")
            result["all_headers"] = dict(response.headers)

            # Analyze security headers
            present = {}
            missing = {}

            for header, meta in SECURITY_HEADERS.items():
                if header.lower() in {k.lower(): v for k, v in response.headers.items()}:
                    # Find actual value (case-insensitive)
                    value = next(
                        (v for k, v in response.headers.items() if k.lower() == header.lower()),
                        "present"
                    )
                    present[header] = {
                        "value": value[:120] + "..." if len(value) > 120 else value,
                        "description": meta["description"],
                        "severity": meta["severity"],
                    }
                else:
                    missing[header] = {
                        "description": meta["description"],
                        "severity": meta["severity"],
                    }

            result["present_headers"] = present
            result["missing_headers"] = missing

            # Check for information-leaking headers
            for header in LEAKY_HEADERS:
                if header.lower() in {k.lower() for k in response.headers.keys()}:
                    value = next(
                        (v for k, v in response.headers.items() if k.lower() == header.lower()),
                        ""
                    )
                    result["leaky_headers"][header] = value

            # Calculate security score (out of 100)
            high_weight = 25
            med_weight = 15
            low_weight = 10

            score = 0
            for h, meta in present.items():
                if meta["severity"] == "HIGH":
                    score += high_weight
                elif meta["severity"] == "MEDIUM":
                    score += med_weight
                else:
                    score += low_weight

            max_score = sum(
                high_weight if m["severity"] == "HIGH"
                else med_weight if m["severity"] == "MEDIUM"
                else low_weight
                for m in SECURITY_HEADERS.values()
            )
            result["security_score"] = min(100, int((score / max_score) * 100))
            break  # Success, stop trying

        except requests.exceptions.SSLError:
            continue  # Try http fallback
        except requests.exceptions.ConnectionError as e:
            result["error"] = f"Connection failed: {str(e)}"
            break
        except requests.exceptions.Timeout:
            result["error"] = "Request timed out"
            break
        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
            break

    return result