# -*- coding: utf-8 -*-

"""
=============================================================
                         SECURITYKIT
                  Passive Security Analysis
                         Final Edition
=============================================================
Purpose:
    Defensive / passive security analysis only.

Modules:
    1.  Port Scanner
    2.  Hash Analyzer
    3.  HTTP Security Checker
    4.  Web Security Analyzer
    5.  DNS Analyzer
    6.  Network Information
    7.  URL Analyzer
    8.  TLS / Certificate Analyzer
    9.  HTTP Redirect Analyzer
    10. Cookie Security Analyzer

No:
    - Exploitation
    - Brute forcing
    - Credential attacks
    - Payload delivery
    - Persistence
    - Destructive actions
    - Case/report management

Filename:
    SecurityKIT.py
============================================================
"""

import os
import re
import ssl
import socket
import hashlib
import platform
import urllib.parse
import urllib.request
import urllib.error
import time

from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# ============================================================
# CONFIG
# ============================================================

VERSION = "FINAL"

TYPE_SPEED = 0.004
SOCKET_TIMEOUT = 0.6
HTTP_TIMEOUT = 10
MAX_WORKERS = 100

USER_AGENT = "SecurityKIT"

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"


# ============================================================
# UI
# ============================================================

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def type_text(text, color=RESET, speed=TYPE_SPEED):
    print(color, end="")

    for char in text:
        print(char, end="", flush=True)
        time.sleep(speed)

    print(RESET, end="")


def type_line(text="", color=RESET, speed=TYPE_SPEED):
    type_text(text + "\n", color, speed)


def separator(char="─"):
    print(CYAN + char * 64 + RESET)


def pause():
    print()
    input(CYAN + "↵ Press ENTER to return..." + RESET)


def module_header(title, emoji):
    clear_screen()

    print()
    print(CYAN + "═" * 64 + RESET)
    print(CYAN + f"                  {emoji} {title}" + RESET)
    print(CYAN + "═" * 64 + RESET)
    print()


def banner():
    clear_screen()

    print()
    print(CYAN + "╔" + "═" * 62 + "╗" + RESET)
    print(
        CYAN
        + "║"
        + " " * 18
        + "SECURITYKIT"
        + " " * 33
        + "║"
        + RESET
    )
    print(
        CYAN
        + "║"
        + " " * 18
        + "PASSIVE SECURITY ANALYSIS"
        + " " * 19
        + "║"
        + RESET
    )
    print(CYAN + "╚" + "═" * 62 + "╝" + RESET)

    print()

    type_line(
        f"🛡️ • Security Analysis Console • ",
        GREEN
    )

    type_line(
        "🔒 • Defensive / Passive Analysis Only • ",
        CYAN
    )

    print()


# ============================================================
# COMMON HELPERS
# ============================================================

def normalize_url(url):
    url = url.strip()

    if not url:
        return ""

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def clean_domain(value):
    value = value.strip()

    value = re.sub(
        r"^https?://",
        "",
        value,
        flags=re.IGNORECASE
    )

    return value.split("/")[0].split("?")[0].split("#")[0]


def create_request(url):
    return urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*"
        }
    )


def get_http_response(url):
    request = create_request(url)

    try:
        response = urllib.request.urlopen(
            request,
            timeout=HTTP_TIMEOUT
        )

        return response, None

    except urllib.error.HTTPError as error:
        return error, None

    except Exception as error:
        return None, error


def get_header(headers, name):
    value = headers.get(name)

    if value is None:
        return ""

    return value.strip()


def severity_color(severity):
    severity = severity.upper()

    if severity in ("CRITICAL", "HIGH"):
        return RED

    if severity == "MEDIUM":
        return YELLOW

    if severity == "LOW":
        return BLUE

    return GREEN


def print_finding(severity, message):
    color = severity_color(severity)

    print(
        color
        + f"[{severity.upper():8}] {message}"
        + RESET
    )


# ============================================================
# 1. PORT SCANNER
# ============================================================

def get_service(port):
    services = {
        20: "FTP Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        69: "TFTP",
        80: "HTTP",
        110: "POP3",
        119: "NNTP",
        123: "NTP",
        135: "MS RPC",
        137: "NetBIOS",
        138: "NetBIOS",
        139: "NetBIOS",
        143: "IMAP",
        161: "SNMP",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        587: "SMTP Submission",
        636: "LDAPS",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        2049: "NFS",
        2375: "Docker",
        2376: "Docker TLS",
        3000: "HTTP Alt",
        3306: "MySQL",
        3389: "RDP",
        5000: "HTTP Alt",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8000: "HTTP Alt",
        8080: "HTTP Proxy / Alt",
        8443: "HTTPS Alt",
        9200: "Elasticsearch",
    }

    return services.get(port, "Unknown")


def scan_port(target, port, timeout=SOCKET_TIMEOUT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target, port))

        if result != 0:
            return port, False, ""

        banner_data = ""

        try:
            sock.settimeout(0.25)

            data = sock.recv(512)

            banner_data = (
                data
                .decode("utf-8", errors="replace")
                .replace("\r", " ")
                .replace("\n", " ")
                .strip()
            )

        except Exception:
            pass

        return port, True, banner_data

    except Exception:
        return port, False, ""

    finally:
        sock.close()


def port_scanner():
    module_header("PORT SCANNER", "🔎")

    target = input("🎯 Target IP / hostname: ").strip()

    if not target:
        print(RED + "\n[!] No target entered." + RESET)
        pause()
        return

    try:
        target_ip = socket.gethostbyname(target)

    except socket.gaierror:
        print(RED + "\n[!] Could not resolve target." + RESET)
        pause()
        return

    print()

    type_line(
        f"[+] Resolved: {target_ip}",
        GREEN
    )

    print()

    print("  Scan range:")
    print("  [1] 1-1024")
    print("  [2] Common ports")
    print("  [0] Back")
    print()

    choice = input("🎮 Select → ").strip()

    if choice == "0":
        return

    if choice == "2":
        ports = sorted({
            20, 21, 22, 23, 25, 53, 67, 68,
            69, 80, 110, 119, 123, 135, 137,
            138, 139, 143, 161, 389, 443, 445,
            465, 587, 636, 993, 995, 1433, 1521,
            2049, 2375, 2376, 3000, 3306, 3389,
            5000, 5432, 5900, 6379, 8000,
            8080, 8443, 9200
        })

    else:
        ports = range(1, 1025)

    print()

    type_line(
        f"[*] Scanning {len(ports)} TCP ports...",
        MAGENTA
    )

    print()

    start_time = time.time()
    open_ports = []

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = [
            executor.submit(
                scan_port,
                target_ip,
                port
            )
            for port in ports
        ]

        for future in as_completed(futures):

            port, is_open, banner_data = future.result()

            if is_open:

                open_ports.append(port)

                service = get_service(port)

                print(
                    GREEN
                    + f"[+] {port:<5} OPEN     {service}"
                    + RESET
                )

                if banner_data:
                    print(
                        CYAN
                        + f"    Banner: {banner_data[:100]}"
                        + RESET
                    )

    elapsed = time.time() - start_time

    print()
    separator("=")

    open_ports.sort()

    if open_ports:

        type_line(
            f"[+] {len(open_ports)} open port(s) detected.",
            GREEN
        )

        print(
            "    Ports:",
            ", ".join(str(port) for port in open_ports)
        )

        print()

        type_line(
            "[i] Open ports are observations, not proof of vulnerability.",
            CYAN,
            0.002
        )

    else:

        type_line(
            "[-] No open ports detected in the selected range.",
            YELLOW
        )

    print(f"    Scan time: {elapsed:.2f}s")

    separator("=")

    pause()


# ============================================================
# 2. HASH ANALYZER
# ============================================================

def identify_hash(value):
    value = value.strip()

    if value.startswith(("$2a$", "$2b$", "$2y$")):
        return "bcrypt"

    if value.startswith("$argon2"):
        return "Argon2"

    if value.startswith("$6$"):
        return "sha512crypt"

    if value.startswith("$5$"):
        return "sha256crypt"

    if value.startswith("$1$"):
        return "md5crypt"

    patterns = {
        32: "MD5",
        40: "SHA-1",
        56: "SHA-224",
        64: "SHA-256",
        96: "SHA-384",
        128: "SHA-512",
    }

    length = len(value)

    if (
        length in patterns
        and re.fullmatch(r"[0-9a-fA-F]+", value)
    ):
        return f"Likely {patterns[length]}"

    return "Unknown"


def hash_analyzer():
    while True:

        module_header("HASH ANALYZER", "🔐")

        value = input("🔑 Enter hash: ").strip()

        if not value:
            print(RED + "\n[!] Empty input." + RESET)
            pause()
            return

        detected = identify_hash(value)

        hexadecimal = bool(
            re.fullmatch(
                r"[0-9a-fA-F]+",
                value
            )
        )

        print()

        separator("=")

        type_line(
            "HASH ANALYSIS",
            WHITE
        )

        print()

        print(f"Length       : {len(value)}")

        print(
            "Characters   : "
            + (
                "Hexadecimal"
                if hexadecimal
                else "Mixed / Other"
            )
        )

        if detected == "Unknown":

            print(
                RED
                + "Likely type  : Unknown"
                + RESET
            )

        else:

            print(
                GREEN
                + f"Likely type  : {detected}"
                + RESET
            )

        print()

        detected_lower = detected.lower()

        if (
            "bcrypt" in detected_lower
            or "argon2" in detected_lower
        ):

            print(
                GREEN
                + "Password use : Designed for password hashing"
                + RESET
            )

        elif detected.startswith("Likely"):

            print(
                YELLOW
                + "Password use : Fast general-purpose hash; "
                  "not ideal by itself for password storage"
                + RESET
            )

        else:

            print(
                YELLOW
                + "Password use : Cannot determine from format alone"
                + RESET
            )

        separator("=")

        print()

        again = input(
            "🔄 Analyze another hash? [Y/N] → "
        ).strip().upper()

        if again == "N":
            break


# ============================================================
# 3. HTTP SECURITY CHECKER
# ============================================================

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def http_security_checker():
    while True:

        module_header(
            "HTTP SECURITY CHECKER",
            "🌐"
        )

        url = normalize_url(
            input("🎯 Target URL: ")
        )

        if not url:
            print(RED + "\n[!] Invalid URL." + RESET)
            pause()
            return

        print()

        type_line(
            "[*] Requesting headers...",
            MAGENTA
        )

        response, error = get_http_response(url)

        if error:

            print(
                RED
                + f"\n[!] Request failed: {error}"
                + RESET
            )

        else:

            headers = response.headers
            final_url = response.geturl()

            print()

            separator("=")

            type_line(
                "SECURITY HEADERS",
                WHITE
            )

            print()

            detected = 0
            missing = 0

            for header in SECURITY_HEADERS:

                value = headers.get(header)

                if value:

                    print(
                        GREEN
                        + f"[+] {header}"
                        + RESET
                    )

                    detected += 1

                else:

                    print(
                        YELLOW
                        + f"[-] {header} missing"
                        + RESET
                    )

                    missing += 1

            print()

            type_line(
                "TRANSPORT",
                WHITE
            )

            print()

            if final_url.startswith("https://"):

                print(
                    GREEN
                    + "[+] HTTPS detected"
                    + RESET
                )

            else:

                print(
                    YELLOW
                    + "[-] HTTPS not detected"
                    + RESET
                )

            print()

            type_line(
                "SERVER INFORMATION",
                WHITE
            )

            print()

            server = headers.get("Server")
            powered = headers.get("X-Powered-By")

            print(
                "Server       :",
                server if server else "Not disclosed"
            )

            print(
                "X-Powered-By :",
                powered if powered else "Not disclosed"
            )

            print()

            type_line(
                "RESPONSE",
                WHITE
            )

            print()

            print(
                f"Status       : {response.status}"
            )

            print(
                f"Final URL    : {final_url}"
            )

            print()

            separator()

            print(
                f"Header coverage: "
                f"{detected}/{len(SECURITY_HEADERS)}"
            )

            if missing:

                print(
                    YELLOW
                    + f"Missing: {missing}"
                    + RESET
                )

            else:

                print(
                    GREEN
                    + "All checked security headers detected."
                    + RESET
                )

            separator("=")

        print()

        again = input(
            "🔄 Check another URL? [Y/N] → "
        ).strip().upper()

        if again == "N":
            break


# ============================================================
# 4. PASSIVE WEB SECURITY ANALYZER
# ============================================================

def web_security_analyzer():
    while True:

        module_header(
            "WEB SECURITY ANALYZER",
            "🕷️"
        )

        url = normalize_url(
            input("🎯 Target URL: ")
        )

        if not url:
            print(RED + "\n[!] Invalid URL." + RESET)
            pause()
            return

        print()

        type_line(
            "[*] Performing passive analysis...",
            MAGENTA
        )

        response, error = get_http_response(url)

        if error:

            print(
                RED
                + f"\n[!] Request failed: {error}"
                + RESET
            )

            pause()
            return

        headers = response.headers
        final_url = response.geturl()

        findings = []

        print()

        # ----------------------------------------------------
        # HTTPS
        # ----------------------------------------------------

        print(
            CYAN
            + "[1] HTTPS"
            + RESET
        )

        if final_url.startswith("https://"):

            print(
                GREEN
                + "    [+] HTTPS enabled"
                + RESET
            )

        else:

            print(
                YELLOW
                + "    [-] HTTPS not detected"
                + RESET
            )

            findings.append(
                (
                    "HIGH",
                    "HTTPS is not being used."
                )
            )

        # ----------------------------------------------------
        # CSP
        # ----------------------------------------------------

        print(
            CYAN
            + "[2] Content Security Policy"
            + RESET
        )

        csp = headers.get(
            "Content-Security-Policy",
            ""
        )

        if csp:

            print(
                GREEN
                + "    [+] CSP detected"
                + RESET
            )

        else:

            print(
                YELLOW
                + "    [-] CSP missing"
                + RESET
            )

            findings.append(
                (
                    "MEDIUM",
                    "Content-Security-Policy is missing."
                )
            )

        # ----------------------------------------------------
        # MIME
        # ----------------------------------------------------

        print(
            CYAN
            + "[3] MIME Sniffing Protection"
            + RESET
        )

        nosniff = headers.get(
            "X-Content-Type-Options",
            ""
        ).lower()

        if nosniff == "nosniff":

            print(
                GREEN
                + "    [+] nosniff enabled"
                + RESET
            )

        else:

            print(
                YELLOW
                + "    [-] nosniff missing"
                + RESET
            )

            findings.append(
                (
                    "MEDIUM",
                    "X-Content-Type-Options: nosniff is missing."
                )
            )

        # ----------------------------------------------------
        # CLICKJACKING
        # ----------------------------------------------------

        print(
            CYAN
            + "[4] Clickjacking Protection"
            + RESET
        )

        frame_header = headers.get(
            "X-Frame-Options",
            ""
        )

        if (
            frame_header
            or "frame-ancestors" in csp.lower()
        ):

            print(
                GREEN
                + "    [+] Frame protection detected"
                + RESET
            )

        else:

            print(
                YELLOW
                + "    [-] Frame protection not detected"
                + RESET
            )

            findings.append(
                (
                    "MEDIUM",
                    "No obvious clickjacking protection detected."
                )
            )

        # ----------------------------------------------------
        # SERVER
        # ----------------------------------------------------

        print(
            CYAN
            + "[5] Server Disclosure"
            + RESET
        )

        server = headers.get("Server")

        if server:

            print(
                YELLOW
                + f"    [-] Server exposed: {server}"
                + RESET
            )

            findings.append(
                (
                    "LOW",
                    f"Server information is exposed: {server}"
                )
            )

        else:

            print(
                GREEN
                + "    [+] Server not disclosed"
                + RESET
            )

        # ----------------------------------------------------
        # POWERED BY
        # ----------------------------------------------------

        print(
            CYAN
            + "[6] Technology Disclosure"
            + RESET
        )

        powered = headers.get(
            "X-Powered-By"
        )

        if powered:

            print(
                YELLOW
                + f"    [-] X-Powered-By exposed: {powered}"
                + RESET
            )

            findings.append(
                (
                    "LOW",
                    f"X-Powered-By disclosure detected: {powered}"
                )
            )

        else:

            print(
                GREEN
                + "    [+] X-Powered-By not disclosed"
                + RESET
            )

        # ----------------------------------------------------
        # REFERRER
        # ----------------------------------------------------

        print(
            CYAN
            + "[7] Referrer Policy"
            + RESET
        )

        referrer = headers.get(
            "Referrer-Policy"
        )

        if referrer:

            print(
                GREEN
                + f"    [+] {referrer}"
                + RESET
            )

        else:

            print(
                YELLOW
                + "    [-] Referrer-Policy missing"
                + RESET
            )

            findings.append(
                (
                    "LOW",
                    "Referrer-Policy is missing."
                )
            )

        # ----------------------------------------------------
        # PERMISSIONS
        # ----------------------------------------------------

        print(
            CYAN
            + "[8] Permissions Policy"
            + RESET
        )

        permissions = headers.get(
            "Permissions-Policy"
        )

        if permissions:

            print(
                GREEN
                + "    [+] Permissions-Policy detected"
                + RESET
            )

        else:

            print(
                YELLOW
                + "    [-] Permissions-Policy missing"
                + RESET
            )

            findings.append(
                (
                    "LOW",
                    "Permissions-Policy is missing."
                )
            )

        # ----------------------------------------------------
        # HSTS
        # ----------------------------------------------------

        print(
            CYAN
            + "[9] HSTS"
            + RESET
        )

        hsts = headers.get(
            "Strict-Transport-Security"
        )

        if hsts:

            print(
                GREEN
                + "    [+] HSTS detected"
                + RESET
            )

            print(
                CYAN
                + f"        {hsts}"
                + RESET
            )

        else:

            print(
                YELLOW
                + "    [-] HSTS missing"
                + RESET
            )

            findings.append(
                (
                    "MEDIUM",
                    "Strict-Transport-Security is missing."
                )
            )

        # ----------------------------------------------------
        # FINDINGS
        # ----------------------------------------------------

        print()

        separator("=")

        type_line(
            "FINDINGS",
            WHITE
        )

        print()

        if findings:

            for severity, finding in findings:

                print_finding(
                    severity,
                    finding
                )

        else:

            print(
                GREEN
                + "[+] No obvious passive issues detected."
                + RESET
            )

        print()

        type_line(
            "[i] Findings are indicators, "
            "not proof of exploitability.",
            CYAN,
            0.002
        )

        separator("=")

        print()

        again = input(
            "🔄 Analyze another URL? [Y/N] → "
        ).strip().upper()

        if again == "N":
            break


# ============================================================
# 5. DNS ANALYZER
# ============================================================

def dns_analyzer():
    while True:

        module_header(
            "DNS ANALYZER",
            "📡"
        )

        domain = input(
            "🌍 Domain: "
        ).strip()

        if not domain:

            print(
                RED
                + "\n[!] No domain entered."
                + RESET
            )

            pause()
            return

        domain = clean_domain(domain)

        print()

        try:

            addresses = socket.getaddrinfo(
                domain,
                None
            )

            ipv4 = sorted({
                result[4][0]
                for result in addresses
                if "." in result[4][0]
            })

            ipv6 = sorted({
                result[4][0]
                for result in addresses
                if ":" in result[4][0]
            })

            print(
                CYAN
                + "DNS RESULTS"
                + RESET
            )

            separator()

            print(
                "Domain       :",
                domain
            )

            print()

            print("IPv4:")

            if ipv4:

                for address in ipv4:
                    print(
                        GREEN
                        + f"  [+] {address}"
                        + RESET
                    )

            else:
                print("  None found")

            print()

            print("IPv6:")

            if ipv6:

                for address in ipv6:
                    print(
                        GREEN
                        + f"  [+] {address}"
                        + RESET
                    )

            else:
                print("  None found")

            try:

                canonical = socket.getfqdn(
                    domain
                )

                print()
                print(
                    "Canonical name:",
                    canonical
                )

            except Exception:
                pass

        except socket.gaierror:

            print(
                RED
                + "[!] DNS resolution failed."
                + RESET
            )

        separator("=")

        print()

        again = input(
            "🔄 Analyze another domain? [Y/N] → "
        ).strip().upper()

        if again == "N":
            break


# ============================================================
# 6. NETWORK INFORMATION
# ============================================================

def network_information():
    module_header(
        "NETWORK INFORMATION",
        "🖥️"
    )

    hostname = socket.gethostname()

    try:
        local_ip = socket.gethostbyname(
            hostname
        )

    except Exception:
        local_ip = "Unavailable"

    print()

    separator("=")

    type_line(
        "SYSTEM",
        WHITE
    )

    print()

    print(
        f"Hostname       : {hostname}"
    )

    print(
        f"Operating Sys. : {platform.system()}"
    )

    print(
        f"OS Version     : {platform.version()}"
    )

    print(
        f"Architecture   : {platform.machine()}"
    )

    print(
        f"Python         : {platform.python_version()}"
    )

    print()

    type_line(
        "NETWORK",
        WHITE
    )

    print()

    print(
        f"Local hostname : {hostname}"
    )

    print(
        f"Local IP       : {local_ip}"
    )

    print(
        "Loopback       : 127.0.0.1"
    )

    try:

        dns_test = socket.gethostbyname(
            "example.com"
        )

        print(
            f"DNS test       : {dns_test}"
        )

    except Exception:

        print(
            "DNS test       : Failed"
        )

    print()

    type_line(
        "[i] This module reports information "
        "available to the local machine.",
        CYAN,
        0.002
    )

    separator("=")

    pause()


# ============================================================
# 7. URL ANALYZER
# ============================================================

def url_analyzer():
    while True:

        module_header(
            "URL ANALYZER",
            "🔗"
        )

        raw_url = input(
            "🌐 URL: "
        ).strip()

        if not raw_url:

            print(
                RED
                + "\n[!] No URL entered."
                + RESET
            )

            pause()
            return

        url = normalize_url(
            raw_url
        )

        parsed = urllib.parse.urlparse(
            url
        )

        print()

        separator("=")

        type_line(
            "URL COMPONENTS",
            WHITE
        )

        print()

        print(
            f"Scheme       : {parsed.scheme}"
        )

        print(
            f"Hostname     : {parsed.hostname}"
        )

        print(
            f"Port         : "
            f"{parsed.port if parsed.port else 'Default'}"
        )

        print(
            f"Path         : "
            f"{parsed.path if parsed.path else '/'}"
        )

        print(
            f"Query        : "
            f"{parsed.query if parsed.query else 'None'}"
        )

        print(
            f"Fragment     : "
            f"{parsed.fragment if parsed.fragment else 'None'}"
        )

        print()

        type_line(
            "QUERY PARAMETERS",
            WHITE
        )

        print()

        parameters = urllib.parse.parse_qs(
            parsed.query
        )

        if parameters:

            for key, values in parameters.items():

                print(
                    f"  {key} = {', '.join(values)}"
                )

        else:

            print(
                "  No query parameters."
            )

        print()

        type_line(
            "URL SECURITY OBSERVATIONS",
            WHITE
        )

        print()

        if parsed.scheme == "https":

            print(
                GREEN
                + "[+] HTTPS scheme"
                + RESET
            )

        else:

            print(
                YELLOW
                + "[-] URL is not using HTTPS"
                + RESET
            )

        if parsed.username:

            print(
                YELLOW
                + "[!] Username component present"
                + RESET
            )

        else:

            print(
                GREEN
                + "[+] No username component"
                + RESET
            )

        if parsed.password:

            print(
                YELLOW
                + "[!] Password component present"
                + RESET
            )

        else:

            print(
                GREEN
                + "[+] No password component"
                + RESET
            )

        separator("=")

        print()

        again = input(
            "🔄 Analyze another URL? [Y/N] → "
        ).strip().upper()

        if again == "N":
            break


# ============================================================
# 8. TLS / CERTIFICATE ANALYZER
# ============================================================

def format_certificate_name(name):
    """
    Convert Python's certificate tuple format into readable text.

    Example:
        ((('commonName', 'example.com'),),)

    becomes:

        commonName: example.com
    """

    parts = []

    for section in name:

        for item in section:

            if len(item) >= 2:

                key = str(item[0])
                value = str(item[1])

                parts.append(
                    f"{key}: {value}"
                )

    return ", ".join(parts)


def tls_certificate_analyzer():
    while True:

        module_header(
            "TLS / CERTIFICATE ANALYZER",
            "🔒"
        )

        target = input(
            "🎯 Domain / URL: "
        ).strip()

        if not target:

            print(
                RED
                + "\n[!] No target entered."
                + RESET
            )

            pause()
            return

        domain = clean_domain(target)

        print()

        type_line(
            f"[*] Connecting to {domain}:443...",
            MAGENTA
        )

        context = ssl.create_default_context()

        try:

            with socket.create_connection(
                (domain, 443),
                timeout=HTTP_TIMEOUT
            ) as raw_socket:

                with context.wrap_socket(
                    raw_socket,
                    server_hostname=domain
                ) as tls_socket:

                    certificate = tls_socket.getpeercert()

                    cipher = tls_socket.cipher()

                    tls_version = tls_socket.version()

                    print()

                    separator("=")

                    type_line(
                        "TLS CONNECTION",
                        WHITE
                    )

                    print()

                    print(
                        f"TLS Version : "
                        f"{tls_version or 'Unknown'}"
                    )

                    if cipher:

                        print(
                            f"Cipher      : "
                            f"{cipher[0]}"
                        )

                        print(
                            f"Cipher Bits : "
                            f"{cipher[2]}"
                        )

                    print()

                    type_line(
                        "CERTIFICATE",
                        WHITE
                    )

                    print()

                    subject = certificate.get(
                        "subject"
                    )

                    issuer = certificate.get(
                        "issuer"
                    )

                    serial = certificate.get(
                        "serialNumber"
                    )

                    version = certificate.get(
                        "version"
                    )

                    not_before = certificate.get(
                        "notBefore"
                    )

                    not_after = certificate.get(
                        "notAfter"
                    )

                    print(
                        "Subject    :",
                        format_certificate_name(
                            subject
                        )
                    )

                    print(
                        "Issuer     :",
                        format_certificate_name(
                            issuer
                        )
                    )

                    print(
                        "Serial     :",
                        serial or "Unavailable"
                    )

                    print(
                        "Version    :",
                        version if version is not None else "Unknown"
                    )

                    print(
                        "Valid From :",
                        not_before or "Unavailable"
                    )

                    print(
                        "Valid Until:",
                        not_after or "Unavailable"
                    )

                    print()

                    type_line(
                        "SUBJECT ALTERNATIVE NAMES",
                        WHITE
                    )

                    print()

                    san = certificate.get(
                        "subjectAltName",
                        []
                    )

                    if san:

                        for entry_type, value in san:

                            print(
                                GREEN
                                + f"  [+] {entry_type}: {value}"
                                + RESET
                            )

                    else:

                        print(
                            "  None observed."
                        )

                    print()

                    # Certificate expiration check
                    if not_after:

                        try:

                            expiration = ssl.cert_time_to_seconds(
                                not_after
                            )

                            remaining = (
                                expiration
                                - time.time()
                            )

                            days = int(
                                remaining / 86400
                            )

                            if days < 0:

                                print_finding(
                                    "HIGH",
                                    "Certificate appears expired."
                                )

                            elif days <= 30:

                                print_finding(
                                    "MEDIUM",
                                    f"Certificate expires in approximately {days} day(s)."
                                )

                            else:

                                print(
                                    GREEN
                                    + f"[+] Certificate validity: ~{days} day(s) remaining"
                                    + RESET
                                )

                        except Exception:
                            pass

                    separator("=")

        except ssl.SSLCertVerificationError as error:

            print()

            print_finding(
                "HIGH",
                "TLS certificate verification failed."
            )

            print(
                RED
                + f"    {error}"
                + RESET
            )

        except Exception as error:

            print()

            print(
                RED
                + f"[!] TLS analysis failed: {error}"
                + RESET
            )

        pause()

        break


# ============================================================
# 9. HTTP REDIRECT ANALYZER
# ============================================================

def redirect_analyzer():
    while True:

        module_header(
            "HTTP REDIRECT ANALYZER",
            "↪️"
        )

        url = normalize_url(
            input("🎯 Target URL: ")
        )

        if not url:

            print(
                RED
                + "\n[!] Invalid URL."
                + RESET
            )

            pause()
            return

        print()

        type_line(
            "[*] Inspecting redirect chain...",
            MAGENTA
        )

        current = url
        visited = set()
        chain = []

        try:

            for _ in range(10):

                if current in visited:

                    chain.append(
                        (
                            current,
                            "LOOP"
                        )
                    )

                    break

                visited.add(current)

                request = urllib.request.Request(
                    current,
                    headers={
                        "User-Agent": USER_AGENT
                    }
                )

                opener = urllib.request.build_opener(
                    urllib.request.HTTPRedirectHandler()
                )

                response = opener.open(
                    request,
                    timeout=HTTP_TIMEOUT
                )

                final_url = response.geturl()

                chain.append(
                    (
                        current,
                        response.status
                    )
                )

                if final_url == current:
                    break

                current = final_url

            print()

            separator("=")

            type_line(
                "REDIRECT CHAIN",
                WHITE
            )

            print()

            if len(chain) == 1:

                print(
                    GREEN
                    + "[+] No redirect chain observed."
                    + RESET
                )

            else:

                for index, (
                    location,
                    status
                ) in enumerate(
                    chain,
                    start=1
                ):

                    print(
                        f"  [{index}] "
                        f"{status} → {location}"
                    )

            print()

            print(
                "Final URL:",
                current
            )

            if (
                url.startswith("http://")
                and current.startswith("https://")
            ):

                print(
                    GREEN
                    + "[+] HTTP → HTTPS upgrade observed."
                    + RESET
                )

            elif current.startswith("http://"):

                print_finding(
                    "MEDIUM",
                    "Final destination is still HTTP."
                )

            separator("=")

        except Exception as error:

            print(
                RED
                + f"\n[!] Redirect analysis failed: {error}"
                + RESET
            )

        pause()

        break


# ============================================================
# 10. COOKIE SECURITY ANALYZER
# ============================================================

def cookie_security_analyzer():
    while True:

        module_header(
            "COOKIE SECURITY ANALYZER",
            "🍪"
        )

        url = normalize_url(
            input("🎯 Target URL: ")
        )

        if not url:

            print(
                RED
                + "\n[!] Invalid URL."
                + RESET
            )

            pause()
            return

        print()

        type_line(
            "[*] Inspecting Set-Cookie headers...",
            MAGENTA
        )

        response, error = get_http_response(
            url
        )

        if error:

            print(
                RED
                + f"\n[!] Request failed: {error}"
                + RESET
            )

            pause()
            return

        cookies = response.headers.get_all(
            "Set-Cookie"
        )

        print()

        separator("=")

        type_line(
            "COOKIE ANALYSIS",
            WHITE
        )

        print()

        if not cookies:

            print(
                YELLOW
                + "[i] No Set-Cookie headers observed."
                + RESET
            )

            separator("=")
            pause()
            return

        print(
            f"[+] {len(cookies)} cookie(s) observed."
        )

        print()

        for index, cookie in enumerate(
            cookies,
            start=1
        ):

            lower = cookie.lower()

            parts = cookie.split(";")

            cookie_name = (
                parts[0].split(
                    "=",
                    1
                )[0].strip()
                if "=" in parts[0]
                else parts[0].strip()
            )

            print(
                CYAN
                + f"[{index}] {cookie_name}"
                + RESET
            )

            secure = "secure" in lower
            httponly = "httponly" in lower
            samesite = "samesite" in lower

            if secure:

                print(
                    GREEN
                    + "    [+] Secure"
                    + RESET
                )

            else:

                print(
                    YELLOW
                    + "    [-] Secure missing"
                    + RESET
                )

            if httponly:

                print(
                    GREEN
                    + "    [+] HttpOnly"
                    + RESET
                )

            else:

                print(
                    YELLOW
                    + "    [-] HttpOnly missing"
                    + RESET
                )

            if samesite:

                print(
                    GREEN
                    + "    [+] SameSite"
                    + RESET
                )

            else:

                print(
                    YELLOW
                    + "    [-] SameSite missing"
                    + RESET
                )

            print()

        print()

        type_line(
            "[i] Cookie attributes are evaluated from "
            "observed response headers only.",
            CYAN,
            0.002
        )

        separator("=")

        pause()

        break

# ============================================================
# AEGIS BACKEND API
# ============================================================

def api_port_scan(target, ports_spec="1-1024"):
    """
    Backend-safe AEGIS port scanner.
    Returns structured data instead of printing to the CLI.
    """

    if not target:
        return {
            "success": False,
            "message": "Target is required.",
            "data": None
        }

    try:
        target_ip = socket.gethostbyname(target)

    except socket.gaierror:
        return {
            "success": False,
            "message": "Could not resolve target.",
            "data": None
        }

    try:
        ports = parse_backend_ports(ports_spec)

    except ValueError:
        return {
            "success": False,
            "message": "Invalid port specification.",
            "data": None
        }

    if len(ports) > 5000:
        return {
            "success": False,
            "message": "Maximum scan size is 5000 ports.",
            "data": None
        }

    opened = []

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = [
            executor.submit(
                scan_port,
                target_ip,
                port
            )
            for port in ports
        ]

        for future in as_completed(futures):

            port, is_open, banner_data = future.result()

            if is_open:

                opened.append({
                    "port": port,
                    "service": get_service(port),
                    "banner": banner_data
                })

    opened.sort(
        key=lambda item: item["port"]
    )

    return {
        "success": True,
        "message": "AEGIS port scan completed.",
        "data": {
            "target": target,
            "resolved_ip": target_ip,
            "scanned": len(ports),
            "open_ports": opened
        }
    }


def parse_backend_ports(spec):
    """
    Parse:
        80
        80,443,8080
        1-1024
        22,80,443
        1-100,443
    """

    spec = str(spec).strip()

    if not spec:
        raise ValueError(
            "Empty port specification."
        )

    ports = set()

    for part in spec.split(","):

        part = part.strip()

        if not part:
            continue

        if "-" in part:

            pieces = part.split("-", 1)

            if len(pieces) != 2:
                raise ValueError(
                    "Invalid range."
                )

            start = int(
                pieces[0].strip()
            )

            end = int(
                pieces[1].strip()
            )

            if start > end:
                raise ValueError(
                    "Invalid port range."
                )

            if start < 1 or end > 65535:
                raise ValueError(
                    "Port must be between 1 and 65535."
                )

            ports.update(
                range(start, end + 1)
            )

        else:

            port = int(part)

            if port < 1 or port > 65535:
                raise ValueError(
                    "Port must be between 1 and 65535."
                )

            ports.add(port)

    if not ports:
        raise ValueError(
            "No ports specified."
        )

    return sorted(ports)


def api_hash_analyze(value):
    """
    Backend-safe hash analysis.
    """

    if not value:
        return {
            "success": False,
            "message": "Hash is required.",
            "data": None
        }

    value = str(value).strip()

    detected = identify_hash(value)

    hexadecimal = bool(
        re.fullmatch(
            r"[0-9a-fA-F]+",
            value
        )
    )

    detected_lower = detected.lower()

    if (
        "bcrypt" in detected_lower
        or "argon2" in detected_lower
    ):

        password_use = (
            "Designed for password hashing."
        )

    elif detected.startswith("Likely"):

        password_use = (
            "Fast general-purpose hash; "
            "not ideal by itself for password storage."
        )

    else:

        password_use = (
            "Cannot determine from format alone."
        )

    return {
        "success": True,
        "message": "Hash analysis completed.",
        "data": {
            "length": len(value),
            "characters": (
                "Hexadecimal"
                if hexadecimal
                else "Mixed / Other"
            ),
            "likely_type": detected,
            "password_use": password_use
        }
    }


def api_http_security_check(target):
    """
    Backend-safe HTTP security header analysis.
    """

    if not target:
        return {
            "success": False,
            "message": "URL is required.",
            "data": None
        }

    url = normalize_url(target)

    if not url:
        return {
            "success": False,
            "message": "Invalid URL.",
            "data": None
        }

    response, error = get_http_response(url)

    if error:

        return {
            "success": False,
            "message": f"Request failed: {error}",
            "data": None
        }

    headers = response.headers
    final_url = response.geturl()

    results = []

    for header in SECURITY_HEADERS:

        value = headers.get(header)

        results.append({
            "header": header,
            "present": bool(value),
            "value": value or None
        })

    return {
        "success": True,
        "message": "HTTP security analysis completed.",
        "data": {
            "status": response.status,
            "final_url": final_url,
            "https": final_url.startswith("https://"),
            "headers": results,
            "server": headers.get("Server"),
            "powered_by": headers.get("X-Powered-By")
        }
    }


def api_web_security(target):
    """
    Backend-safe passive web security analysis.
    """

    if not target:
        return {
            "success": False,
            "message": "URL is required.",
            "data": None
        }

    url = normalize_url(target)

    response, error = get_http_response(url)

    if error:

        return {
            "success": False,
            "message": f"Request failed: {error}",
            "data": None
        }

    headers = response.headers
    final_url = response.geturl()

    findings = []

    def finding(
        severity,
        message
    ):
        findings.append({
            "severity": severity,
            "message": message
        })

    # HTTPS
    if not final_url.startswith("https://"):
        finding(
            "HIGH",
            "HTTPS is not being used."
        )

    # CSP
    csp = headers.get(
        "Content-Security-Policy",
        ""
    )

    if not csp:
        finding(
            "MEDIUM",
            "Content-Security-Policy is missing."
        )

    # MIME protection
    nosniff = headers.get(
        "X-Content-Type-Options",
        ""
    ).lower()

    if nosniff != "nosniff":
        finding(
            "MEDIUM",
            "X-Content-Type-Options: nosniff is missing."
        )

    # Clickjacking
    frame_header = headers.get(
        "X-Frame-Options",
        ""
    )

    if (
        not frame_header
        and "frame-ancestors" not in csp.lower()
    ):
        finding(
            "MEDIUM",
            "No obvious clickjacking protection detected."
        )

    # Server disclosure
    server = headers.get("Server")

    if server:
        finding(
            "LOW",
            f"Server information is exposed: {server}"
        )

    # Technology disclosure
    powered = headers.get(
        "X-Powered-By"
    )

    if powered:
        finding(
            "LOW",
            f"X-Powered-By disclosure detected: {powered}"
        )

    # Referrer
    if not headers.get("Referrer-Policy"):
        finding(
            "LOW",
            "Referrer-Policy is missing."
        )

    # Permissions
    if not headers.get("Permissions-Policy"):
        finding(
            "LOW",
            "Permissions-Policy is missing."
        )

    # HSTS
    if not headers.get(
        "Strict-Transport-Security"
    ):
        finding(
            "MEDIUM",
            "Strict-Transport-Security is missing."
        )

    return {
        "success": True,
        "message": "Passive web security analysis completed.",
        "data": {
            "status": response.status,
            "final_url": final_url,
            "findings": findings,
            "finding_count": len(findings)
        }
    }


def api_dns_analyze(domain):
    """
    Backend-safe DNS analysis.
    """

    if not domain:
        return {
            "success": False,
            "message": "Domain is required.",
            "data": None
        }

    domain = clean_domain(domain)

    try:

        addresses = socket.getaddrinfo(
            domain,
            None
        )

        ipv4 = sorted({
            item[4][0]
            for item in addresses
            if "." in item[4][0]
        })

        ipv6 = sorted({
            item[4][0]
            for item in addresses
            if ":" in item[4][0]
        })

        canonical = socket.getfqdn(
            domain
        )

        return {
            "success": True,
            "message": "DNS analysis completed.",
            "data": {
                "domain": domain,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "canonical": canonical
            }
        }

    except socket.gaierror:

        return {
            "success": False,
            "message": "DNS resolution failed.",
            "data": None
        }


def api_network_information():
    """
    Backend-safe local network/system information.
    """

    hostname = socket.gethostname()

    try:
        local_ip = socket.gethostbyname(
            hostname
        )

    except Exception:
        local_ip = "Unavailable"

    try:
        dns_test = socket.gethostbyname(
            "example.com"
        )

    except Exception:
        dns_test = None

    return {
        "success": True,
        "message": "Network information collected.",
        "data": {
            "hostname": hostname,
            "operating_system": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
            "local_ip": local_ip,
            "loopback": "127.0.0.1",
            "dns_test": dns_test
        }
    }


def api_url_analyze(raw_url):
    """
    Backend-safe URL analysis.
    """

    if not raw_url:
        return {
            "success": False,
            "message": "URL is required.",
            "data": None
        }

    url = normalize_url(raw_url)

    try:

        parsed = urllib.parse.urlparse(
            url
        )

        parameters = urllib.parse.parse_qs(
            parsed.query
        )

        return {
            "success": True,
            "message": "URL analysis completed.",
            "data": {
                "scheme": parsed.scheme,
                "hostname": parsed.hostname,
                "port": (
                    parsed.port
                    if parsed.port
                    else None
                ),
                "path": (
                    parsed.path
                    if parsed.path
                    else "/"
                ),
                "query": parsed.query,
                "fragment": parsed.fragment,
                "parameters": parameters,
                "https": parsed.scheme == "https",
                "username_present": bool(
                    parsed.username
                ),
                "password_present": bool(
                    parsed.password
                )
            }
        }

    except ValueError:

        return {
            "success": False,
            "message": "Invalid URL.",
            "data": None
        }


def api_tls_analyze(target):
    """
    Backend-safe TLS certificate analysis.
    """

    if not target:
        return {
            "success": False,
            "message": "Target is required.",
            "data": None
        }

    domain = clean_domain(target)

    context = ssl.create_default_context()

    try:

        with socket.create_connection(
            (domain, 443),
            timeout=HTTP_TIMEOUT
        ) as raw_socket:

            with context.wrap_socket(
                raw_socket,
                server_hostname=domain
            ) as tls_socket:

                certificate = (
                    tls_socket.getpeercert()
                )

                cipher = tls_socket.cipher()

                return {
                    "success": True,
                    "message": "TLS analysis completed.",
                    "data": {
                        "domain": domain,
                        "tls_version":
                            tls_socket.version(),
                        "cipher":
                            cipher[0]
                            if cipher
                            else None,
                        "cipher_bits":
                            cipher[2]
                            if cipher
                            else None,
                        "subject":
                            format_certificate_name(
                                certificate.get(
                                    "subject"
                                )
                            ),
                        "issuer":
                            format_certificate_name(
                                certificate.get(
                                    "issuer"
                                )
                            ),
                        "serial":
                            certificate.get(
                                "serialNumber"
                            ),
                        "version":
                            certificate.get(
                                "version"
                            ),
                        "valid_from":
                            certificate.get(
                                "notBefore"
                            ),
                        "valid_until":
                            certificate.get(
                                "notAfter"
                            ),
                        "subject_alt_names":
                            list(
                                certificate.get(
                                    "subjectAltName",
                                    []
                                )
                            )
                    }
                }

    except ssl.SSLCertVerificationError as error:

        return {
            "success": False,
            "message":
                f"TLS certificate verification failed: {error}",
            "data": None
        }

    except Exception as error:

        return {
            "success": False,
            "message":
                f"TLS analysis failed: {error}",
            "data": None
        }


def api_redirect_analyze(target):
    """
    Backend-safe redirect-chain analysis.
    """

    if not target:
        return {
            "success": False,
            "message": "URL is required.",
            "data": None
        }

    url = normalize_url(target)

    current = url
    visited = set()
    chain = []

    try:

        for _ in range(10):

            if current in visited:

                chain.append({
                    "url": current,
                    "status": "LOOP"
                })

                break

            visited.add(current)

            request = urllib.request.Request(
                current,
                headers={
                    "User-Agent": USER_AGENT
                }
            )

            opener = urllib.request.build_opener(
                urllib.request.HTTPRedirectHandler()
            )

            response = opener.open(
                request,
                timeout=HTTP_TIMEOUT
            )

            final_url = response.geturl()

            chain.append({
                "url": current,
                "status": response.status
            })

            if final_url == current:
                break

            current = final_url

        return {
            "success": True,
            "message": "Redirect analysis completed.",
            "data": {
                "original_url": url,
                "final_url": current,
                "chain": chain
            }
        }

    except Exception as error:

        return {
            "success": False,
            "message":
                f"Redirect analysis failed: {error}",
            "data": None
        }


def api_cookie_analyze(target):
    """
    Backend-safe cookie security analysis.
    """

    if not target:
        return {
            "success": False,
            "message": "URL is required.",
            "data": None
        }

    url = normalize_url(target)

    response, error = get_http_response(
        url
    )

    if error:

        return {
            "success": False,
            "message": f"Request failed: {error}",
            "data": None
        }

    cookies = response.headers.get_all(
        "Set-Cookie"
    )

    results = []

    for cookie in cookies:

        parts = cookie.split(";")

        name = (
            parts[0].split(
                "=",
                1
            )[0].strip()
            if "=" in parts[0]
            else parts[0].strip()
        )

        lower = cookie.lower()

        results.append({
            "name": name,
            "secure": "secure" in lower,
            "httponly": "httponly" in lower,
            "samesite": "samesite" in lower
        })

    return {
        "success": True,
        "message": "Cookie analysis completed.",
        "data": {
            "url": url,
            "cookies": results,
            "count": len(results)
        }
    }

# ============================================================
# MAIN MENU
# ============================================================

def main():
    while True:

        banner()

        type_line(
            "🧰 SECURITY MODULES",
            WHITE
        )

        print()

        print(
            "  [1] 🔎  Port Scanner"
        )

        print(
            "  [2] 🔐  Hash Analyzer"
        )

        print(
            "  [3] 🌐  HTTP Security Checker"
        )

        print(
            "  [4] 🕷️  Web Security Analyzer"
        )

        print(
            "  [5] 📡  DNS Analyzer"
        )

        print(
            "  [6] 🖥️  Network Information"
        )

        print(
            "  [7] 🔗  URL Analyzer"
        )

        print(
            "  [8] 🔒  TLS / Certificate Analyzer"
        )

        print(
            "  [9] ↪️  HTTP Redirect Analyzer"
        )

        print(
            "  [10] 🍪 Cookie Security Analyzer"
        )

        print(
            "  [0] 🚪 Exit"
        )

        print()

        separator()

        choice = input(
            "\n🎮 Select module → "
        ).strip()

        if choice == "1":

            port_scanner()

        elif choice == "2":

            hash_analyzer()

        elif choice == "3":

            http_security_checker()

        elif choice == "4":

            web_security_analyzer()

        elif choice == "5":

            dns_analyzer()

        elif choice == "6":

            network_information()

        elif choice == "7":

            url_analyzer()

        elif choice == "8":

            tls_certificate_analyzer()

        elif choice == "9":

            redirect_analyzer()

        elif choice == "10":

            cookie_security_analyzer()

        elif choice == "0":

            clear_screen()

            type_line(
                "👋 Closing SecurityKIT...",
                CYAN
            )

            type_line(
                "🛡️ Passive analysis complete.",
                GREEN
            )

            print()

            break

        else:

            print()

            type_line(
                "[!] Invalid option.",
                RED
            )

            time.sleep(0.7)


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    main()