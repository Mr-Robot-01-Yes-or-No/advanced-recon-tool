"""
report_generator.py
--------------------
Saves recon results to JSON and/or TXT report files.
"""

import json
import os
from datetime import datetime
from typing import Dict, Any


def generate_reports(domain: str, data: Dict[str, Any], output_dir: str = "reports") -> Dict[str, str]:
    """
    Generate both JSON and TXT reports from collected recon data.

    Args:
        domain:     Target domain
        data:       Full results dictionary
        output_dir: Directory to save reports

    Returns:
        Dictionary with paths to generated files
    """
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_domain = domain.replace(".", "_").replace("/", "_")
    base_name = f"{safe_domain}_{timestamp}"

    paths = {}

    # ── JSON Report ───────────────────────────────────────────────────
    json_path = os.path.join(output_dir, f"{base_name}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    paths["json"] = json_path

    # ── TXT Report ────────────────────────────────────────────────────
    txt_path = os.path.join(output_dir, f"{base_name}.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        _write_txt_report(f, domain, data, timestamp)
    paths["txt"] = txt_path

    return paths


def _write_txt_report(f, domain: str, data: Dict[str, Any], timestamp: str):
    """Write a human-readable TXT report."""

    sep = "=" * 70
    thin = "-" * 70

    f.write(f"{sep}\n")
    f.write(f"  ADVANCED RECON TOOL — RECONNAISSANCE REPORT\n")
    f.write(f"{sep}\n")
    f.write(f"  Target  : {domain}\n")
    f.write(f"  Date    : {timestamp}\n")
    f.write(f"  Tool    : Advanced Recon & Tech Fingerprinting Tool v1.0\n")
    f.write(f"{sep}\n\n")

    # IP Info
    ip_data = data.get("ip_info", {})
    f.write(f"[1] IP INFORMATION\n{thin}\n")
    f.write(f"  IPv4 Address : {ip_data.get('ipv4', 'N/A')}\n")
    f.write(f"  Hostname     : {ip_data.get('hostname', 'N/A')}\n\n")

    # HTTP Headers
    hdr = data.get("headers", {})
    f.write(f"[2] SERVER INFORMATION\n{thin}\n")
    f.write(f"  URL         : {hdr.get('url', 'N/A')}\n")
    f.write(f"  Status Code : {hdr.get('status_code', 'N/A')}\n")
    f.write(f"  Server      : {hdr.get('server', 'N/A')}\n")
    f.write(f"  Content-Type: {hdr.get('content_type', 'N/A')}\n\n")

    # Security Headers
    f.write(f"[3] SECURITY HEADERS (Score: {hdr.get('security_score', 0)}/100)\n{thin}\n")
    f.write("  PRESENT:\n")
    for h in hdr.get("present_headers", {}):
        f.write(f"    ✓ {h}\n")
    f.write("  MISSING:\n")
    for h in hdr.get("missing_headers", {}):
        f.write(f"    ✗ {h}\n")
    f.write("\n")

    # SSL
    ssl_data = data.get("ssl", {})
    f.write(f"[4] SSL/TLS INFORMATION\n{thin}\n")
    f.write(f"  Valid       : {ssl_data.get('valid', False)}\n")
    f.write(f"  Issuer      : {ssl_data.get('issuer', 'N/A')}\n")
    f.write(f"  Issued On   : {ssl_data.get('issued_on', 'N/A')}\n")
    f.write(f"  Expires On  : {ssl_data.get('expires_on', 'N/A')}\n")
    f.write(f"  Days Left   : {ssl_data.get('days_remaining', 'N/A')}\n")
    f.write(f"  TLS Version : {ssl_data.get('tls_version', 'N/A')}\n\n")

    # DNS
    dns_data = data.get("dns", {})
    f.write(f"[5] DNS RECORDS\n{thin}\n")
    for rtype, records in dns_data.items():
        f.write(f"  {rtype}:\n")
        for r in records:
            f.write(f"    → {r}\n")
    f.write("\n")

    # WHOIS
    who = data.get("whois", {})
    f.write(f"[6] WHOIS INFORMATION\n{thin}\n")
    f.write(f"  Registrar    : {who.get('registrar', 'N/A')}\n")
    f.write(f"  Organization : {who.get('org', 'N/A')}\n")
    f.write(f"  Created      : {who.get('creation_date', 'N/A')}\n")
    f.write(f"  Expires      : {who.get('expiry_date', 'N/A')}\n")
    f.write(f"  Updated      : {who.get('updated_date', 'N/A')}\n\n")

    # Technologies
    tech = data.get("tech", {}).get("technologies", {})
    f.write(f"[7] TECHNOLOGY FINGERPRINTING\n{thin}\n")
    if tech:
        for category, items in tech.items():
            f.write(f"  {category}: {', '.join(items)}\n")
    else:
        f.write("  No technologies detected\n")
    f.write("\n")

    # Ports
    ports = data.get("ports", {})
    open_ports = ports.get("open", [])
    f.write(f"[8] PORT SCAN RESULTS\n{thin}\n")
    if open_ports:
        for p in open_ports:
            f.write(f"  OPEN  {p['port']:>5}/tcp  {p['service']:<15}  {p['risk']}\n")
    else:
        f.write("  No open ports found from scanned list\n")
    f.write("\n")

    # Disclaimer
    f.write(f"{sep}\n")
    f.write("  DISCLAIMER\n")
    f.write(f"{thin}\n")
    f.write("  This tool is developed for educational and authorized security\n")
    f.write("  testing purposes only. Unauthorized use against systems you do\n")
    f.write("  not own or have explicit permission to test is illegal.\n")
    f.write(f"{sep}\n")