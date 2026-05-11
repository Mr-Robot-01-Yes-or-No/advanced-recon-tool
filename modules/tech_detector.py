"""
tech_detector.py
----------------
Fingerprints web technologies by analyzing response headers, cookies,
HTML meta tags, script tags, and body content patterns.

HOW TECH FINGERPRINTING WORKS:
- HTTP headers like 'X-Powered-By: PHP/8.1' directly reveal server tech
- Cookie names (e.g., 'PHPSESSID' = PHP, 'JSESSIONID' = Java)
- HTML meta tags: <meta name="generator" content="WordPress 6.x">
- Script src patterns: /wp-content/ → WordPress, /sites/all/ → Drupal
- Body text patterns: specific class names, comments, file paths
- Response timing and error page formats

WHY IT MATTERS:
- Knowing the CMS → look up known CVEs for that version
- Knowing the framework → understand attack surface
- Knowing CDN/WAF → adjust attack vectors
- Every technology = potential vulnerability entry point
"""

import requests
import re
from typing import Dict, List, Any

# Signature patterns: (pattern_type, pattern, technology_name, category)
SIGNATURES = [
    # ── Web Servers ──────────────────────────────────────────────────
    ("header", "server", r"nginx", "Nginx", "Web Server"),
    ("header", "server", r"apache", "Apache", "Web Server"),
    ("header", "server", r"IIS", "Microsoft IIS", "Web Server"),
    ("header", "server", r"LiteSpeed", "LiteSpeed", "Web Server"),
    ("header", "server", r"cloudflare", "Cloudflare", "CDN / WAF"),
    ("header", "server", r"openresty", "OpenResty", "Web Server"),

    # ── Frameworks / Languages ────────────────────────────────────────
    ("header", "x-powered-by", r"PHP", "PHP", "Language"),
    ("header", "x-powered-by", r"ASP\.NET", "ASP.NET", "Framework"),
    ("header", "x-powered-by", r"Express", "Express.js", "Framework"),
    ("header", "x-powered-by", r"Next\.js", "Next.js", "Framework"),

    # ── CMS ───────────────────────────────────────────────────────────
    ("body", None, r"/wp-content/", "WordPress", "CMS"),
    ("body", None, r"/wp-includes/", "WordPress", "CMS"),
    ("body", None, r'content="WordPress', "WordPress", "CMS"),
    ("body", None, r"/sites/default/files/", "Drupal", "CMS"),
    ("body", None, r'Drupal\.settings', "Drupal", "CMS"),
    ("body", None, r'content="Joomla', "Joomla", "CMS"),
    ("body", None, r'/media/jui/', "Joomla", "CMS"),
    ("body", None, r'Shopify\.theme', "Shopify", "E-Commerce"),
    ("body", None, r'cdn\.shopify\.com', "Shopify", "E-Commerce"),
    ("body", None, r'static\.wixstatic\.com', "Wix", "Website Builder"),
    ("body", None, r'squarespace\.com', "Squarespace", "Website Builder"),
    ("body", None, r'ghost\.io|content\.ghost\.org', "Ghost", "CMS"),

    # ── JavaScript Frameworks ─────────────────────────────────────────
    ("body", None, r'react(?:\.min)?\.js|__REACT|data-reactroot', "React", "JS Framework"),
    ("body", None, r'angular(?:\.min)?\.js|ng-version|ng-app', "Angular", "JS Framework"),
    ("body", None, r'vue(?:\.min)?\.js|__vue__|data-v-', "Vue.js", "JS Framework"),
    ("body", None, r'jquery[.-][\d.]+(?:\.min)?\.js', "jQuery", "JS Library"),
    ("body", None, r'bootstrap(?:\.min)?\.(?:js|css)', "Bootstrap", "CSS Framework"),
    ("body", None, r'tailwind(?:css)?', "Tailwind CSS", "CSS Framework"),
    ("body", None, r'next/static|__NEXT_DATA__', "Next.js", "JS Framework"),
    ("body", None, r'__nuxt__|_nuxt/', "Nuxt.js", "JS Framework"),
    ("body", None, r'gatsby-|/gatsby-', "Gatsby", "Static Site Generator"),

    # ── Analytics / Marketing ─────────────────────────────────────────
    ("body", None, r'google-analytics\.com|gtag\(|GoogleAnalyticsObject', "Google Analytics", "Analytics"),
    ("body", None, r'googletagmanager\.com', "Google Tag Manager", "Analytics"),
    ("body", None, r'hotjar\.com', "Hotjar", "Analytics"),
    ("body", None, r'segment\.com|analytics\.js', "Segment", "Analytics"),
    ("body", None, r'cdn\.mxpnl\.com|mixpanel', "Mixpanel", "Analytics"),

    # ── CDN / Infrastructure ──────────────────────────────────────────
    ("header", "cf-ray", None, "Cloudflare", "CDN / WAF"),
    ("header", "x-amz-cf-id", None, "Amazon CloudFront", "CDN"),
    ("header", "x-azure-ref", None, "Azure CDN", "CDN"),
    ("header", "x-fastly-request-id", None, "Fastly", "CDN"),
    ("header", "x-varnish", None, "Varnish Cache", "Cache"),
    ("header", "x-cache", r"HIT|MISS", "Caching Layer", "Cache"),

    # ── Cookie Patterns ───────────────────────────────────────────────
    ("cookie", None, r"PHPSESSID", "PHP", "Language"),
    ("cookie", None, r"JSESSIONID", "Java (Servlet)", "Language"),
    ("cookie", None, r"ASP\.NET_SessionId", "ASP.NET", "Framework"),
    ("cookie", None, r"laravel_session", "Laravel", "Framework"),
    ("cookie", None, r"_rails", "Ruby on Rails", "Framework"),
    ("cookie", None, r"django", "Django", "Framework"),
    ("cookie", None, r"wp-settings", "WordPress", "CMS"),
]


def detect_technologies(domain: str) -> Dict[str, Any]:
    """
    Fingerprint technologies used by a web application.

    Args:
        domain: Target domain string

    Returns:
        Dictionary with detected technologies grouped by category
    """
    result: Dict[str, Any] = {
        "technologies": {},   # category -> list of tech names
        "raw_signals": [],    # debug: what triggered each detection
        "generator": None,
        "error": None,
    }

    for scheme in ["https", "http"]:
        try:
            response = requests.get(
                f"{scheme}://{domain}",
                timeout=12,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                verify=False,
            )

            headers = {k.lower(): v for k, v in response.headers.items()}
            body = response.text[:50000]  # First 50KB is enough
            cookies = "; ".join([f"{c.name}={c.value}" for c in response.cookies])

            detected = {}  # tech_name -> category

            # Check <meta name="generator"> tag
            gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body, re.I)
            if gen_match:
                result["generator"] = gen_match.group(1)

            for sig in SIGNATURES:
                sig_type, header_name, pattern, tech, category = sig

                matched = False

                if sig_type == "header" and header_name in headers:
                    if pattern is None:
                        matched = True
                    else:
                        matched = bool(re.search(pattern, headers[header_name], re.I))

                elif sig_type == "body":
                    if pattern and re.search(pattern, body, re.I):
                        matched = True

                elif sig_type == "cookie":
                    if pattern and re.search(pattern, cookies, re.I):
                        matched = True

                if matched and tech not in detected:
                    detected[tech] = category
                    result["raw_signals"].append(f"{sig_type.upper()} → {tech}")

            # Group by category
            grouped: Dict[str, List[str]] = {}
            for tech, cat in detected.items():
                grouped.setdefault(cat, [])
                if tech not in grouped[cat]:
                    grouped[cat].append(tech)

            result["technologies"] = grouped
            break

        except requests.exceptions.ConnectionError:
            continue
        except Exception as e:
            result["error"] = f"Detection failed: {str(e)}"
            break

    return result