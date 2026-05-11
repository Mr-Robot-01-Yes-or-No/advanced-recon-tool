"""
port_scanner.py
---------------
Performs a fast TCP connect scan on common ports.

HOW PORT SCANNING WORKS:
- TCP connect scan: attempts a full three-way handshake (SYN → SYN-ACK → ACK)
- If port responds = OPEN, if refused = CLOSED, if no reply within timeout = FILTERED
- Common ports reveal exposed services → each is a potential attack vector

WHY IT MATTERS IN RECON:
- Port 21 (FTP)   → potential anonymous login, cleartext credentials
- Port 22 (SSH)   → brute-force target, version-specific exploits
- Port 23 (Telnet)→ cleartext protocol, major security risk if open
- Port 25 (SMTP)  → open relay? Email spoofing vector
- Port 80 (HTTP)  → web app, check for redirects to HTTPS
- Port 443 (HTTPS)→ web app, check cert
- Port 3306 (MySQL)→ database exposed to internet? Critical finding
- Port 6379 (Redis)→ often misconfigured, unauthenticated access
- Port 8080/8443  → admin panels, secondary web apps

DISCLAIMER: Only scan systems you own or have explicit permission to test.
"""

import socket
import concurrent.futures
from typing import Dict, List, Tuple

# Common ports with service names and risk notes
PORT_INFO: Dict[int, Dict[str, str]] = {
    21:   {"service": "FTP",          "risk": "Cleartext file transfer"},
    22:   {"service": "SSH",          "risk": "Remote shell access"},
    23:   {"service": "Telnet",       "risk": "Cleartext remote access (critical)"},
    25:   {"service": "SMTP",         "risk": "Mail server / open relay"},
    53:   {"service": "DNS",          "risk": "Zone transfer possible"},
    80:   {"service": "HTTP",         "risk": "Unencrypted web traffic"},
    110:  {"service": "POP3",         "risk": "Email retrieval (cleartext)"},
    143:  {"service": "IMAP",         "risk": "Email access"},
    443:  {"service": "HTTPS",        "risk": "Encrypted web traffic"},
    445:  {"service": "SMB",          "risk": "File sharing / EternalBlue"},
    3306: {"service": "MySQL",        "risk": "Database exposed to internet"},
    3389: {"service": "RDP",          "risk": "Remote Desktop (brute-force target)"},
    5432: {"service": "PostgreSQL",   "risk": "Database exposed to internet"},
    6379: {"service": "Redis",        "risk": "Often unauthenticated"},
    8080: {"service": "HTTP-Alt",     "risk": "Secondary web app / admin panel"},
    8443: {"service": "HTTPS-Alt",    "risk": "Alternate HTTPS / admin panel"},
    8888: {"service": "HTTP-Dev",     "risk": "Dev server / Jupyter Notebook"},
    9200: {"service": "Elasticsearch","risk": "Often unauthenticated"},
    27017:{"service": "MongoDB",      "risk": "Database exposed to internet"},
}

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                 3306, 3389, 5432, 6379, 8080, 8443, 8888, 9200, 27017]


def scan_port(ip: str, port: int, timeout: float = 1.5) -> Tuple[int, bool, str]:
    """
    Attempt a TCP connection to a single port.

    Args:
        ip:      Target IP address
        port:    Port number to scan
        timeout: Connection timeout in seconds

    Returns:
        Tuple of (port, is_open, service_name)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        is_open = result == 0
        service = PORT_INFO.get(port, {}).get("service", "Unknown")
        return (port, is_open, service)
    except Exception:
        service = PORT_INFO.get(port, {}).get("service", "Unknown")
        return (port, False, service)


def run_port_scan(
    ip: str,
    ports: List[int] = None,
    max_workers: int = 50
) -> Dict[str, List[Dict]]:
    """
    Scan multiple ports concurrently using a thread pool.

    Args:
        ip:          Target IP address
        ports:       List of ports to scan (defaults to DEFAULT_PORTS)
        max_workers: Number of concurrent threads

    Returns:
        Dictionary with 'open' and 'closed' port lists
    """
    if ports is None:
        ports = DEFAULT_PORTS

    open_ports: List[Dict] = []
    closed_ports: List[Dict] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open, service = future.result()
            info = PORT_INFO.get(port, {})
            entry = {
                "port": port,
                "service": service,
                "risk": info.get("risk", "Unknown"),
            }
            if is_open:
                open_ports.append(entry)
            else:
                closed_ports.append(entry)

    open_ports.sort(key=lambda x: x["port"])
    closed_ports.sort(key=lambda x: x["port"])

    return {"open": open_ports, "closed": closed_ports}