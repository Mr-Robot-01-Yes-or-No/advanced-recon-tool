"""
main.py
-------
Advanced Website Recon & Tech Fingerprinting Tool
Entry point — orchestrates all modules with a professional Rich UI.

Author : You
Version: 1.0.0
Purpose: Educational / Authorized Security Testing Only
"""

import socket
import sys
import time
import warnings
from datetime import datetime
from typing import Dict, Any

# Suppress InsecureRequestWarning from requests
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
)
from rich.text import Text
from rich.columns import Columns
from rich import box
from rich.rule import Rule
from rich.align import Align

# ── Module imports ─────────────────────────────────────────────────────────────
from modules.dns_lookup import get_dns_records
from modules.ssl_checker import get_ssl_info
from modules.whois_lookup import get_whois_info
from modules.security_headers import analyze_headers
from modules.tech_detector import detect_technologies
from modules.port_scanner import run_port_scan
from modules.report_generator import generate_reports

console = Console()

# ══════════════════════════════════════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════════════════════════════════════

BANNER = r"""
 █████╗ ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗ ██████╗███████╗██████╗ 
██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║██╔════╝██╔════╝██╔══██╗
███████║██║  ██║██║   ██║███████║██╔██╗ ██║██║     █████╗  ██║  ██║
██╔══██║██║  ██║╚██╗ ██╔╝██╔══██║██║╚██╗██║██║     ██╔══╝  ██║  ██║
██║  ██║██████╔╝ ╚████╔╝ ██║  ██║██║ ╚████║╚██████╗███████╗██████╔╝
╚═╝  ╚═╝╚═════╝   ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═════╝ 
        ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
        ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
        ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
        ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
        ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
        ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
"""


def print_banner():
    console.print(BANNER, style="bold cyan")
    console.print(
        Align.center(
            "[bold white]Advanced Website Recon & Tech Fingerprinting Tool[/bold white]\n"
            "[dim]v1.0.0  |  Educational & Authorized Testing Only[/dim]\n"
            "[dim]Author: Mr-Robot-01-Yes-or-No[/dim]"
        )
    )
    console.print()


# ══════════════════════════════════════════════════════════════════════════════
#  INPUT VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

def get_target_domain() -> str:
    """Prompt user for target domain and validate it."""
    console.print(
        Panel(
            "[bold yellow]Enter the target domain[/bold yellow]\n"
            "[dim]Examples: example.com  |  google.com  |  github.com[/dim]\n"
            "[red]⚠  Only scan domains you own or have explicit permission to test.[/red]",
            title="[bold white]🎯 TARGET[/bold white]",
            border_style="yellow",
        )
    )

    while True:
        domain = console.input("[bold green]➜ Domain: [/bold green]").strip()
        # Strip protocols if pasted
        domain = domain.replace("https://", "").replace("http://", "").rstrip("/")

        if not domain:
            console.print("[red]Domain cannot be empty. Try again.[/red]")
            continue

        if "." not in domain:
            console.print("[red]That doesn't look like a valid domain. Try again.[/red]")
            continue

        return domain


def resolve_ip(domain: str) -> Dict[str, str]:
    """Resolve IPv4 and hostname for a domain."""
    result = {"ipv4": "Unknown", "hostname": "Unknown"}
    try:
        ipv4 = socket.gethostbyname(domain)
        result["ipv4"] = ipv4
        try:
            result["hostname"] = socket.gethostbyaddr(ipv4)[0]
        except Exception:
            result["hostname"] = "No reverse DNS"
    except socket.gaierror as e:
        result["ipv4"] = f"Resolution failed: {e}"
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  DISPLAY FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def display_ip_info(domain: str, ip_data: Dict):
    table = Table(
        title="🌐 IP & Host Information",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Field", style="bold cyan", width=20)
    table.add_column("Value", style="white")

    table.add_row("Target Domain", f"[bold green]{domain}[/bold green]")
    table.add_row("IPv4 Address", ip_data.get("ipv4", "N/A"))
    table.add_row("Hostname (PTR)", ip_data.get("hostname", "N/A"))
    table.add_row("Scan Time", datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"))

    console.print(table)
    console.print()


def display_server_info(hdr_data: Dict):
    table = Table(
        title="🖥  Server Information",
        box=box.ROUNDED,
        border_style="blue",
        header_style="bold magenta",
    )
    table.add_column("Field", style="bold cyan", width=20)
    table.add_column("Value", style="white")

    status = hdr_data.get("status_code")
    status_color = "green" if status and 200 <= status < 300 else "yellow" if status and 300 <= status < 400 else "red"

    table.add_row("Final URL", str(hdr_data.get("url", "N/A")))
    table.add_row("HTTP Status", f"[{status_color}]{status}[/{status_color}]")
    table.add_row("Server", hdr_data.get("server", "N/A"))
    table.add_row("Content-Type", hdr_data.get("content_type", "N/A"))

    if hdr_data.get("leaky_headers"):
        leaky = ", ".join(hdr_data["leaky_headers"].keys())
        table.add_row("⚠ Info Leakage", f"[yellow]{leaky}[/yellow]")

    console.print(table)
    console.print()


def display_security_headers(hdr_data: Dict):
    score = hdr_data.get("security_score", 0)
    score_color = "green" if score >= 70 else "yellow" if score >= 40 else "red"
    score_label = "GOOD" if score >= 70 else "MODERATE" if score >= 40 else "POOR"

    console.print(
        Panel(
            f"Security Header Score: [{score_color}][bold]{score}/100 — {score_label}[/bold][/{score_color}]",
            title="🔒 Security Headers Analysis",
            border_style=score_color,
        )
    )

    table = Table(box=box.SIMPLE_HEAVY, header_style="bold magenta", show_lines=True)
    table.add_column("Header", style="bold white", width=35)
    table.add_column("Status", width=10, justify="center")
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Description", style="dim white")

    present = hdr_data.get("present_headers", {})
    missing = hdr_data.get("missing_headers", {})

    sev_colors = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "blue"}

    for header, meta in present.items():
        sev = meta.get("severity", "LOW")
        table.add_row(
            header,
            "[bold green]✓ PRESENT[/bold green]",
            f"[{sev_colors.get(sev, 'white')}]{sev}[/{sev_colors.get(sev, 'white')}]",
            meta.get("description", ""),
        )

    for header, meta in missing.items():
        sev = meta.get("severity", "LOW")
        table.add_row(
            header,
            "[bold red]✗ MISSING[/bold red]",
            f"[{sev_colors.get(sev, 'white')}]{sev}[/{sev_colors.get(sev, 'white')}]",
            meta.get("description", ""),
        )

    console.print(table)
    console.print()


def display_ssl_info(ssl_data: Dict):
    days = ssl_data.get("days_remaining")
    valid = ssl_data.get("valid", False)

    if days is not None:
        if days > 60:
            days_color = "green"
        elif days > 14:
            days_color = "yellow"
        else:
            days_color = "red"
        days_str = f"[{days_color}]{days} days[/{days_color}]"
    else:
        days_str = "N/A"

    table = Table(
        title="🔐 SSL / TLS Certificate",
        box=box.ROUNDED,
        border_style="green" if valid else "red",
        header_style="bold magenta",
    )
    table.add_column("Field", style="bold cyan", width=20)
    table.add_column("Value", style="white")

    validity_text = "[bold green]✓ Valid[/bold green]" if valid else "[bold red]✗ Invalid / Expired[/bold red]"
    table.add_row("SSL Status", validity_text)
    table.add_row("TLS Version", ssl_data.get("tls_version", "N/A"))
    table.add_row("Issuer (CA)", ssl_data.get("issuer", "N/A"))
    table.add_row("Subject (CN)", ssl_data.get("subject", "N/A"))
    table.add_row("Issued On", ssl_data.get("issued_on", "N/A"))
    table.add_row("Expires On", ssl_data.get("expires_on", "N/A"))
    table.add_row("Days Remaining", days_str)

    if ssl_data.get("error"):
        table.add_row("Error", f"[red]{ssl_data['error']}[/red]")

    console.print(table)

    # SANs
    san_list = ssl_data.get("san", [])
    if san_list:
        san_text = "\n".join(f"  • {s}" for s in san_list[:10])
        console.print(
            Panel(san_text, title="📋 Subject Alternative Names (SANs)", border_style="dim cyan")
        )
    console.print()


def display_dns_records(dns_data: Dict):
    table = Table(
        title="🗂  DNS Records",
        box=box.ROUNDED,
        border_style="yellow",
        header_style="bold magenta",
    )
    table.add_column("Record Type", style="bold cyan", width=15, justify="center")
    table.add_column("Values", style="white")

    type_colors = {
        "A": "green",
        "MX": "yellow",
        "NS": "blue",
        "TXT": "magenta",
        "CNAME": "cyan",
    }

    for rtype, records in dns_data.items():
        color = type_colors.get(rtype, "white")
        if records:
            value_text = "\n".join(records)
        else:
            value_text = "[dim]No records found[/dim]"
        table.add_row(f"[{color}]{rtype}[/{color}]", value_text)

    console.print(table)
    console.print()


def display_whois(whois_data: Dict):
    table = Table(
        title="📋 WHOIS Information",
        box=box.ROUNDED,
        border_style="magenta",
        header_style="bold magenta",
    )
    table.add_column("Field", style="bold cyan", width=22)
    table.add_column("Value", style="white")

    table.add_row("Registrar", whois_data.get("registrar", "N/A"))
    table.add_row("Organization", whois_data.get("org", "N/A"))
    table.add_row("Country", whois_data.get("country", "N/A"))
    table.add_row("Created", whois_data.get("creation_date", "N/A"))
    table.add_row("Expires", whois_data.get("expiry_date", "N/A"))
    table.add_row("Last Updated", whois_data.get("updated_date", "N/A"))
    table.add_row("DNSSEC", whois_data.get("dnssec", "N/A"))

    ns_list = whois_data.get("name_servers", [])
    if ns_list:
        table.add_row("Name Servers", "\n".join(ns_list[:4]))

    status_list = whois_data.get("status", [])
    if status_list:
        table.add_row("Domain Status", "\n".join(status_list[:3]))

    if whois_data.get("error"):
        table.add_row("Error", f"[red]{whois_data['error']}[/red]")

    console.print(table)
    console.print()


def display_technologies(tech_data: Dict):
    technologies = tech_data.get("technologies", {})
    generator = tech_data.get("generator")

    category_icons = {
        "Web Server": "🌐",
        "CDN / WAF": "🛡",
        "Language": "💻",
        "Framework": "⚙️",
        "CMS": "📰",
        "E-Commerce": "🛒",
        "Website Builder": "🏗",
        "JS Framework": "⚡",
        "JS Library": "📦",
        "CSS Framework": "🎨",
        "Analytics": "📊",
        "CDN": "☁️",
        "Cache": "⚡",
        "Static Site Generator": "📄",
    }

    if not technologies and not generator:
        console.print(
            Panel(
                "[yellow]No technologies detected from response patterns.[/yellow]",
                title="🔍 Technology Fingerprinting",
                border_style="yellow",
            )
        )
        console.print()
        return

    table = Table(
        title="🔍 Technology Fingerprinting",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold magenta",
    )
    table.add_column("Category", style="bold cyan", width=22)
    table.add_column("Detected Technologies", style="white")

    if generator:
        table.add_row("🏷  Generator Tag", f"[bold yellow]{generator}[/bold yellow]")

    for category, items in sorted(technologies.items()):
        icon = category_icons.get(category, "•")
        tech_str = "  ".join(f"[bold green]{t}[/bold green]" for t in items)
        table.add_row(f"{icon}  {category}", tech_str)

    console.print(table)
    console.print()


def display_port_scan(port_data: Dict):
    open_ports = port_data.get("open", [])
    closed_ports = port_data.get("closed", [])

    summary = (
        f"[bold green]{len(open_ports)} open[/bold green]  |  "
        f"[bold red]{len(closed_ports)} closed[/bold red]  "
        f"[dim](from {len(open_ports) + len(closed_ports)} scanned)[/dim]"
    )

    console.print(
        Panel(summary, title="🔌 Port Scan Results", border_style="red" if open_ports else "green")
    )

    if open_ports:
        table = Table(box=box.SIMPLE_HEAVY, header_style="bold magenta", show_lines=True)
        table.add_column("Port", style="bold green", width=8, justify="right")
        table.add_column("Protocol", width=6, justify="center")
        table.add_column("Service", style="bold white", width=18)
        table.add_column("Risk Note", style="yellow")

        for p in open_ports:
            table.add_row(
                str(p["port"]),
                "TCP",
                p["service"],
                p["risk"],
            )
        console.print(table)
    else:
        console.print("[dim]  No open ports detected from scanned list.[/dim]")

    console.print()


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN EXECUTION
# ══════════════════════════════════════════════════════════════════════════════

def run_recon(domain: str) -> Dict[str, Any]:
    """Run all recon modules with a rich progress UI."""

    all_data: Dict[str, Any] = {
        "target": domain,
        "scan_time": datetime.now().isoformat(),
        "ip_info": {},
        "headers": {},
        "ssl": {},
        "dns": {},
        "whois": {},
        "tech": {},
        "ports": {},
    }

    tasks = [
        ("ip_info",  "Resolving IP address...",          lambda: resolve_ip(domain)),
        ("headers",  "Fetching HTTP headers...",          lambda: analyze_headers(domain)),
        ("ssl",      "Inspecting SSL certificate...",     lambda: get_ssl_info(domain)),
        ("dns",      "Enumerating DNS records...",        lambda: get_dns_records(domain)),
        ("whois",    "Performing WHOIS lookup...",        lambda: get_whois_info(domain)),
        ("tech",     "Fingerprinting technologies...",    lambda: detect_technologies(domain)),
        ("ports",    "Scanning common ports...",
            lambda: run_port_scan(all_data["ip_info"].get("ipv4", domain))),
    ]

    console.print(Rule("[bold cyan]🚀 Starting Reconnaissance[/bold cyan]"))
    console.print()

    with Progress(
        SpinnerColumn(spinner_name="dots", style="bold cyan"),
        TextColumn("[bold white]{task.description}"),
        BarColumn(bar_width=30, style="cyan", complete_style="green"),
        TextColumn("[dim]{task.percentage:>3.0f}%[/dim]"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        main_task = progress.add_task("[cyan]Overall Progress", total=len(tasks))

        for key, description, fn in tasks:
            task_id = progress.add_task(description, total=1)
            try:
                all_data[key] = fn()
            except Exception as e:
                all_data[key] = {"error": str(e)}
            progress.update(task_id, completed=1, description=f"[green]✓[/green] {description}")
            progress.update(main_task, advance=1)

    console.print()
    console.print(Rule("[bold green]📊 Reconnaissance Complete — Displaying Results[/bold green]"))
    console.print()

    return all_data


def display_all_results(domain: str, data: Dict[str, Any]):
    """Display all results sections sequentially."""

    console.print(Rule("[bold cyan]① IP & Host Information[/bold cyan]"))
    display_ip_info(domain, data.get("ip_info", {}))

    console.print(Rule("[bold blue]② Server Information[/bold blue]"))
    display_server_info(data.get("headers", {}))

    console.print(Rule("[bold yellow]③ Security Headers[/bold yellow]"))
    display_security_headers(data.get("headers", {}))

    console.print(Rule("[bold green]④ SSL / TLS Certificate[/bold green]"))
    display_ssl_info(data.get("ssl", {}))

    console.print(Rule("[bold yellow]⑤ DNS Enumeration[/bold yellow]"))
    display_dns_records(data.get("dns", {}))

    console.print(Rule("[bold magenta]⑥ WHOIS Information[/bold magenta]"))
    display_whois(data.get("whois", {}))

    console.print(Rule("[bold cyan]⑦ Technology Fingerprinting[/bold cyan]"))
    display_technologies(data.get("tech", {}))

    console.print(Rule("[bold red]⑧ Port Scan[/bold red]"))
    display_port_scan(data.get("ports", {}))


def prompt_report_save(domain: str, data: Dict[str, Any]):
    """Ask user if they want to save a report."""
    console.print(
        Panel(
            "[bold white]Save the report?[/bold white]\n"
            "[dim]Reports are saved to the /reports/ directory.[/dim]",
            title="💾 Report Generation",
            border_style="white",
        )
    )
    choice = console.input("[bold green]➜ Save report? [Y/n]: [/bold green]").strip().lower()

    if choice in ("", "y", "yes"):
        with console.status("[cyan]Generating reports...[/cyan]"):
            paths = generate_reports(domain, data)
        console.print()
        for fmt, path in paths.items():
            console.print(f"  [bold green]✓[/bold green] {fmt.upper()} report saved: [cyan]{path}[/cyan]")
        console.print()


def main():
    print_banner()

    # Disclaimer
    console.print(
        Panel(
            "[bold red]⚠  LEGAL DISCLAIMER[/bold red]\n\n"
            "This tool is developed for [bold]educational and authorized security testing purposes only[/bold].\n"
            "Unauthorized use against systems you do not own or have explicit written\n"
            "permission to test is [bold red]illegal[/bold red] and may result in criminal prosecution.\n\n"
            "[dim]By continuing, you confirm you have authorization to scan the target.[/dim]",
            border_style="red",
            padding=(1, 2),
        )
    )
    console.print()

    confirm = console.input("[bold yellow]➜ Do you agree and wish to continue? [Y/n]: [/bold yellow]").strip().lower()
    if confirm not in ("", "y", "yes"):
        console.print("[red]Exiting. Stay ethical![/red]")
        sys.exit(0)

    console.print()

    domain = get_target_domain()

    console.print()
    console.print(
        Panel(
            f"[bold green]Target locked: [cyan]{domain}[/cyan][/bold green]",
            border_style="green",
        )
    )
    console.print()

    # Run all modules
    data = run_recon(domain)

    # Display results
    display_all_results(domain, data)

    # Optional report save
    prompt_report_save(domain, data)

    # Final footer
    console.print(
        Panel(
            "[bold cyan]Reconnaissance complete.[/bold cyan]\n"
            "[dim]Remember: This data is for authorized testing only.[/dim]\n"
            "[bold green]Stay ethical. Stay legal. Happy hacking! 🛡[/bold green]",
            border_style="cyan",
            padding=(1, 2),
        )
    )


if __name__ == "__main__":
    main()