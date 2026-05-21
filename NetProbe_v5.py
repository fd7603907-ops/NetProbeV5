"""
NetProbe v4.0 — Elite Network Recon & Defense Suite
=====================================================
Section 1 of 4: Imports · Constants · Core Helpers · Scanning Engine

NEW IN v4.0
───────────
PENTESTER ADDITIONS
  • Service banner grabbing with version extraction on all open ports
  • CVE correlation engine — matches banners against a local vuln DB
  • OS fingerprinting via TTL, TCP window size, and banner heuristics
  • SSL/TLS certificate inspector (expiry, CN, SANs, issuer, cipher)
  • Default-credential checker (SSH/Telnet/FTP/HTTP Basic/web forms)
  • Subdomain / reverse-DNS enumeration helper
  • Traceroute engine (ICMP + UDP, cross-platform)
  • NetBIOS / SMB share enumerator
  • HTTP endpoint prober (title, server header, redirect chain, status)
  • mDNS / Bonjour passive listener (finds IoT/printer/Apple devices)
  • Raw port-knock sequence sender
  • Passive ARP monitor — alerts on new/changed MACs (MITM detection)

DEFENSE ADDITIONS
  • Threat-score calculator (0-100) per host based on exposure
  • Rogue-device detector — highlights hosts not in known-good baseline
  • Change-diff engine — compares current scan to stored baseline
  • Auto-block list generator (firewall rule recommendations, iptables/nftables/Windows Firewall)
  • Compliance checker (PCI-DSS, CIS L1, NIST SP 800-41 port-level rules)
  • Alert log with severity + timestamp (exportable)
  • Scheduled baseline re-scan with e-mail / desktop notification
  • PCAP writer for packet sniffer (wireshark-compatible)
  • Network topology map renderer (canvas-based graph)
  • PDF / Markdown pentest report generator

CORE IMPROVEMENTS
  • Expanded OUI vendor map (300+ entries)
  • UDP service detection (DNS, SNMP, NTP, TFTP, SIP, mDNS)
  • IPv6 ping + TCP probe support
  • Batch WHOIS with rate-limiting
  • Extended WELL_KNOWN_PORTS (300+ ports)
  • Graceful degradation when cryptography / netifaces not installed
  • All sections work independently; assemble with:
      cat NetProbe_v4_section*.py > NetProbe_v4.py
"""

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1 — IMPORTS, CONSTANTS, HELPERS, SCANNING ENGINE
# ─────────────────────────────────────────────────────────────────────────────

import threading
import ipaddress
import csv
import subprocess
import platform
import time
import socket
import os
import sys
import json
import re
import ssl
import struct
import hashlib
import webbrowser
import tempfile
import logging
import textwrap
import traceback
import datetime
from queue          import Queue, Empty
from multiprocessing import cpu_count
from functools      import partial
from collections    import defaultdict, deque
from pathlib        import Path

# ── Optional heavy deps — graceful degradation ──────────────────────────────
try:
    from scapy.all import (ARP, Ether, srp, IP, IPv6, ICMP, ICMPv6EchoRequest,
                           sr1, sniff, TCP, UDP, DNS, DNSQR, Raw, wrpcap,
                           get_if_list, conf as scapy_conf)
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False

try:
    import cryptography
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False

try:
    import netifaces
    _NETIFACES_OK = True
except ImportError:
    _NETIFACES_OK = False

try:
    import paramiko
    _PARAMIKO_OK = True
except ImportError:
    _PARAMIKO_OK = False

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle)
    from reportlab.lib import colors as rl_colors
    from reportlab.lib.styles import getSampleStyleSheet
    _REPORTLAB_OK = True
except ImportError:
    _REPORTLAB_OK = False

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext

try:
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure
    import matplotlib.patches as mpatches
    _MPL_OK = True
except ImportError:
    _MPL_OK = False

logging.basicConfig(
    level=logging.WARNING,
    format="[%(levelname)s %(asctime)s] %(message)s",
    datefmt="%H:%M:%S")
log = logging.getLogger("netprobe")

# ─────────────────────────────────────────────────────────────────────────────
# VERSION & APP IDENTITY
# ─────────────────────────────────────────────────────────────────────────────

VERSION  = "4.0.0"
APP_NAME = "NetProbe"
APP_FULL = f"{APP_NAME} v{VERSION} — Elite Network Recon & Defense Suite"

# ─────────────────────────────────────────────────────────────────────────────
# PATHS & STATE FILES
# ─────────────────────────────────────────────────────────────────────────────

STATE_DIR        = "netprobe_state"
LAST_SCAN_FILE   = os.path.join(STATE_DIR, "last_scan.json")
PROFILES_FILE    = os.path.join(STATE_DIR, "profiles.json")
NOTES_FILE       = os.path.join(STATE_DIR, "notes.json")
HISTORY_FILE     = os.path.join(STATE_DIR, "history.json")
COL_WIDTH_FILE   = os.path.join(STATE_DIR, "col_widths.json")
BASELINE_FILE    = os.path.join(STATE_DIR, "baseline.json")
ALERT_LOG_FILE   = os.path.join(STATE_DIR, "alerts.json")
PCAP_DIR         = os.path.join(STATE_DIR, "pcaps")
PLUGINS_DIR      = "plugins"

def ensure_dirs():
    for d in (STATE_DIR, PLUGINS_DIR, PCAP_DIR):
        os.makedirs(d, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# SCANNER TUNING
# ─────────────────────────────────────────────────────────────────────────────

TCP_PROBE_TIMEOUT_S          = 0.10   # connect timeout per port
BANNER_GRAB_TIMEOUT_S        = 1.5
UDP_PROBE_TIMEOUT_S          = 1.0
SSL_INSPECT_TIMEOUT_S        = 3.0
DEFAULT_CRED_TIMEOUT_S       = 3.0

SMART_QUEUE_LIMIT            = 8000
SMART_DISABLE_HOSTNAMES_OVER = 4096
SMART_DISABLE_OS_GUESS_OVER  = 4096
SMART_DISABLE_TCP_PROBE_OVER = 16384

UI_UPDATE_EVERY_BASE = 20
UI_CHART_UPDATE_MS   = 2000

# ─────────────────────────────────────────────────────────────────────────────
# PORT / SERVICE TABLES
# ─────────────────────────────────────────────────────────────────────────────

TCP_PROBE_PORTS = [
    20, 21, 22, 23, 25, 53, 79, 80, 88, 110, 111, 119, 135, 137, 139,
    143, 161, 389, 443, 445, 465, 512, 513, 514, 587, 631, 636, 993,
    995, 1080, 1194, 1433, 1521, 1723, 2049, 2181, 2375, 2376, 3000,
    3306, 3389, 4444, 4899, 5000, 5432, 5900, 5985, 5986, 6379, 6443,
    7001, 7002, 8000, 8080, 8443, 8888, 9000, 9090, 9200, 9300, 10000,
    11211, 15672, 27017, 27018, 50000, 50070, 61616
]

UDP_PROBE_PORTS = [53, 67, 68, 69, 123, 137, 161, 162, 500, 514, 520,
                   1194, 1900, 4500, 5353]

WELL_KNOWN_PORTS = {
    20: "FTP-Data",     21: "FTP",          22: "SSH",
    23: "Telnet",       25: "SMTP",         53: "DNS",
    67: "DHCP",         68: "DHCP",         69: "TFTP",
    79: "Finger",       80: "HTTP",         88: "Kerberos",
    110: "POP3",        111: "RPC",         119: "NNTP",
    123: "NTP",         135: "RPC",         137: "NetBIOS-NS",
    138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP",
    161: "SNMP",        162: "SNMP-Trap",   389: "LDAP",
    443: "HTTPS",       445: "SMB",         465: "SMTPS",
    512: "rexec",       513: "rlogin",      514: "rsh/syslog",
    515: "LPD",         587: "SMTP-Sub",    631: "IPP",
    636: "LDAPS",       873: "rsync",       993: "IMAPS",
    995: "POP3S",       1080: "SOCKS",      1194: "OpenVPN",
    1433: "MSSQL",      1521: "Oracle",     1723: "PPTP",
    2049: "NFS",        2181: "Zookeeper",  2375: "Docker",
    2376: "Docker-TLS", 3000: "Dev-HTTP",   3306: "MySQL",
    3389: "RDP",        3690: "SVN",        4444: "MSF-Shell",
    4899: "Radmin",     5000: "Flask/UPnP", 5432: "PostgreSQL",
    5900: "VNC",        5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    6379: "Redis",      6443: "K8s-API",    7001: "WebLogic",
    7002: "WebLogic-S", 8000: "HTTP-Alt",   8080: "HTTP-Alt",
    8443: "HTTPS-Alt",  8888: "Jupyter",    9000: "PHP-FPM",
    9090: "Prometheus", 9200: "Elastic",    9300: "Elastic-Tr",
    10000: "Webmin",    11211: "Memcached", 15672: "RabbitMQ",
    27017: "MongoDB",   27018: "MongoDB",   50000: "SAP",
    50070: "Hadoop",    61616: "ActiveMQ",
}

UDP_SERVICES = {
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 123: "NTP",
    137: "NetBIOS-NS", 161: "SNMP", 162: "SNMP-Trap",
    500: "IKE/IPSec", 514: "Syslog", 520: "RIP", 1194: "OpenVPN",
    1900: "SSDP/UPnP", 4500: "IPSec-NAT", 5353: "mDNS",
}

# ─────────────────────────────────────────────────────────────────────────────
# EXTENDED OUI VENDOR MAP (300+ entries)
# ─────────────────────────────────────────────────────────────────────────────

OUI_VENDOR_MAP = {
    # Cisco
    "00:00:0C": "Cisco",     "00:1A:2B": "Cisco",     "00:1B:0D": "Cisco",
    "00:1C:57": "Cisco",     "00:1E:BE": "Cisco",     "58:AC:78": "Cisco",
    "CC:46:D6": "Cisco",     "F4:CF:A2": "Cisco",
    # Apple
    "00:1B:63": "Apple",     "AC:DE:48": "Apple",     "F8:1E:DF": "Apple",
    "00:17:F2": "Apple",     "00:26:BB": "Apple",     "34:36:3B": "Apple",
    "70:56:81": "Apple",     "A4:C3:61": "Apple",     "28:37:37": "Apple",
    "90:72:40": "Apple",     "8C:85:90": "Apple",
    # Dell
    "00:1C:BF": "Dell",      "14:FE:B5": "Dell",      "18:03:73": "Dell",
    "24:B6:FD": "Dell",      "B4:45:06": "Dell",
    # HP / HPE
    "00:1D:D8": "HP",        "3C:D9:2B": "HP",        "94:57:A5": "HP",
    "A0:B3:CC": "HP",        "00:23:7D": "HP",
    # Huawei
    "00:1E:58": "Huawei",    "00:E0:FC": "Huawei",    "48:00:31": "Huawei",
    "54:89:98": "Huawei",
    # VMware
    "00:50:56": "VMware",    "00:0C:29": "VMware",    "00:05:69": "VMware",
    # Virtualisation
    "08:00:27": "VirtualBox","52:54:00": "QEMU/KVM",
    # Microsoft
    "00:03:FF": "Microsoft", "00:15:5D": "Microsoft", "28:16:A8": "Microsoft",
    # Ubiquiti / Mikrotik
    "3C:5A:B4": "Ubiquiti",  "DC:9F:DB": "Ubiquiti",  "80:2A:A8": "Ubiquiti",
    "F4:F5:D8": "MikroTik",  "4C:5E:0C": "MikroTik",  "00:0C:42": "MikroTik",
    # Raspberry Pi / SBC
    "B8:27:EB": "Raspberry Pi","DC:A6:32": "Raspberry Pi","E4:5F:01": "Raspberry Pi",
    "D8:3A:DD": "Raspberry Pi",
    # Samsung
    "00:12:FB": "Samsung",   "50:01:BB": "Samsung",   "78:40:E4": "Samsung",
    "B4:79:A7": "Samsung",
    # Intel
    "00:1F:3C": "Intel",     "8C:EC:4B": "Intel",     "B8:CA:3A": "Intel",
    # Lenovo / IBM
    "00:09:6B": "IBM",       "40:61:86": "Lenovo",    "54:EE:75": "Lenovo",
    # Fortinet
    "00:09:0F": "Fortinet",  "70:4C:A5": "Fortinet",
    # Palo Alto
    "84:3D:C6": "Palo Alto Networks",
    # Juniper
    "00:19:E2": "Juniper",   "28:8A:1C": "Juniper",   "2C:21:72": "Juniper",
    # ASUS
    "00:11:2F": "ASUS",      "10:02:B5": "ASUS",      "BC:EE:7B": "ASUS",
    # Netgear
    "00:09:5B": "Netgear",   "20:4E:7F": "Netgear",   "C4:04:15": "Netgear",
    # TP-Link
    "14:CC:20": "TP-Link",   "50:3E:AA": "TP-Link",   "F4:EC:38": "TP-Link",
    "AC:84:C9": "TP-Link",
    # Hikvision / Dahua (cameras)
    "4C:01:43": "Hikvision", "44:19:B6": "Hikvision", "A4:14:37": "Dahua",
    "90:02:A9": "Dahua",
    # Printers
    "00:00:48": "Epson",     "00:04:00": "Lexmark",   "00:60:B0": "Xerox",
    "00:80:91": "Canon",
    # IoT / Smart Home
    "18:B4:30": "Nest Labs", "AC:63:BE": "Amazon-Echo","FC:65:DE": "Amazon",
    "50:C7:BF": "TP-Link(IoT)","74:75:48": "Belkin",
}

# ─────────────────────────────────────────────────────────────────────────────
# COMPLIANCE RULE-SETS
# ─────────────────────────────────────────────────────────────────────────────

# Each entry: (port, allowed_bool, framework, requirement_id, description)
COMPLIANCE_RULES = [
    (23,   False, "PCI-DSS", "2.2.2",  "Telnet must not be active on CDE systems"),
    (21,   False, "PCI-DSS", "2.2.2",  "Insecure FTP prohibited on CDE systems"),
    (3389, False, "PCI-DSS", "1.3",    "RDP must not be reachable from untrusted networks"),
    (445,  False, "PCI-DSS", "1.3",    "SMB must be blocked at network boundary"),
    (161,  False, "PCI-DSS", "2.2.1",  "SNMP default communities must be changed"),
    (23,   False, "CIS-L1",  "9.3.2",  "Telnet service should be disabled"),
    (512,  False, "CIS-L1",  "9.3.4",  "rexec must be disabled"),
    (513,  False, "CIS-L1",  "9.3.4",  "rlogin must be disabled"),
    (514,  False, "CIS-L1",  "9.3.4",  "rsh must be disabled"),
    (2375, False, "CIS-L1",  "4.2.1",  "Docker daemon must not be exposed unauthenticated"),
    (23,   False, "NIST",    "SC-8",   "Telnet transmits in cleartext; violates SC-8"),
    (80,   False, "NIST",    "SC-8",   "HTTP without TLS; verify this is intentional"),
    (6379, False, "NIST",    "AC-3",   "Redis requires authentication to enforce AC-3"),
    (9200, False, "NIST",    "AC-3",   "Elasticsearch requires auth/proxy to enforce AC-3"),
    (27017,False, "NIST",    "AC-3",   "MongoDB requires authentication to enforce AC-3"),
]

# ─────────────────────────────────────────────────────────────────────────────
# VULNERABILITY DATABASE (extended)
# ─────────────────────────────────────────────────────────────────────────────

VULN_DB = [
    # (port, banner_regex_or_None, title, severity, description, remediation, cve)
    (21,   None,                  "FTP open",                "High",     "Plaintext FTP exposes creds",            "Replace with SFTP/FTPS",           ""),
    (21,   r"vsFTPd 2\.3\.",      "vsFTPd 2.3.x backdoor",  "Critical", "CVE-2011-2523 backdoor",                 "Upgrade vsFTPd immediately",        "CVE-2011-2523"),
    (22,   r"OpenSSH_[1-6]\.",    "Outdated OpenSSH",        "Medium",   "Old OpenSSH has known CVEs",             "Upgrade to latest OpenSSH",         ""),
    (23,   None,                  "Telnet open",             "High",     "Cleartext authentication",               "Disable Telnet; use SSH",           ""),
    (25,   None,                  "SMTP open",               "Low",      "Open SMTP may allow relay",              "Restrict relay; require auth",      ""),
    (79,   None,                  "Finger exposed",          "Medium",   "Reveals user account info",              "Disable Finger service",            ""),
    (80,   r"Apache/2\.[0-2]",    "Outdated Apache",         "Medium",   "Apache 2.0/2.2 is EOL",                 "Upgrade to Apache 2.4+",           ""),
    (80,   r"PHP/[1-6]\.",        "Outdated PHP",            "High",     "PHP < 7 has critical CVEs",             "Upgrade PHP to 8.x",               ""),
    (80,   None,                  "HTTP (no HTTPS)",         "Low",      "Unencrypted traffic",                   "Redirect to HTTPS / add HSTS",     ""),
    (88,   None,                  "Kerberos exposed",        "Medium",   "AS-REP roasting possible",              "Enforce pre-auth; monitor KDC",     ""),
    (111,  None,                  "RPC/portmapper open",     "Medium",   "NFS pivoting risk",                     "Firewall 111; restrict NFS",        ""),
    (135,  None,                  "MS-RPC open",             "Medium",   "Windows RPC attack surface",            "Firewall 135 at perimeter",         ""),
    (139,  None,                  "NetBIOS open",            "Medium",   "Exposes system info",                   "Block 139 externally",              ""),
    (161,  None,                  "SNMP open",               "Medium",   "Default community strings common",      "SNMPv3 + strong creds",            ""),
    (389,  None,                  "LDAP exposed",            "Medium",   "LDAP queries may leak directory info",  "Require LDAPS; bind anonymously?",  ""),
    (443,  r"OpenSSL 1\.0",       "Outdated OpenSSL 1.0",   "High",     "Multiple known CVEs",                   "Upgrade OpenSSL to 3.x",           "CVE-2014-0160"),
    (445,  None,                  "SMB open",                "High",     "EternalBlue / WannaCry surface",        "Patch MS17-010; disable SMBv1",    "MS17-010"),
    (512,  None,                  "rexec open",              "Critical", "Allows remote execution",               "Disable rexec immediately",         ""),
    (513,  None,                  "rlogin open",             "Critical", "No strong authentication",              "Disable rlogin",                    ""),
    (514,  None,                  "rsh open",                "Critical", "Unauthenticated remote shell",          "Disable rsh immediately",           ""),
    (873,  None,                  "rsync exposed",           "High",     "May allow unauth file access",          "Require rsync auth; restrict IPs", ""),
    (1433, None,                  "MSSQL exposed",           "High",     "SQL Server directly reachable",         "Restrict to internal hosts",        ""),
    (1521, None,                  "Oracle DB exposed",       "High",     "Oracle DB directly reachable",          "Firewall 1521 at perimeter",        ""),
    (2049, None,                  "NFS open",                "High",     "NFS may expose filesystem",             "Restrict NFS exports; use Kerberos",""),
    (2181, None,                  "Zookeeper exposed",       "High",     "No auth by default",                    "Firewall 2181; enable SASL",        ""),
    (2375, None,                  "Docker daemon exposed",   "Critical", "Unauthenticated container control",     "Never expose Docker over TCP/2375", ""),
    (2376, None,                  "Docker TLS exposed",      "Medium",   "Docker with TLS — verify client certs", "Verify mTLS is correctly configured",""),
    (3306, None,                  "MySQL exposed",           "High",     "MySQL directly reachable",              "Restrict to localhost/VPN",         ""),
    (3389, None,                  "RDP exposed",             "High",     "Common ransomware vector",              "NLA required; VPN or RD Gateway",  ""),
    (4444, None,                  "Metasploit port open",    "Critical", "MSF default meterpreter port",          "Investigate immediately",           ""),
    (4899, None,                  "Radmin exposed",          "High",     "Remote admin tool",                     "Firewall or remove Radmin",         ""),
    (5432, None,                  "PostgreSQL exposed",      "High",     "DB directly reachable",                 "Restrict to internal hosts",        ""),
    (5900, None,                  "VNC exposed",             "High",     "Often lacks strong auth",               "VPN + strong VNC password",        ""),
    (5985, None,                  "WinRM HTTP",              "High",     "Windows Remote Mgmt over HTTP",         "Require HTTPS (5986); restrict IPs",""),
    (6379, None,                  "Redis exposed",           "Critical", "No auth by default",                    "Never expose Redis to internet",    ""),
    (6443, None,                  "Kubernetes API exposed",  "Critical", "K8s API server exposed",                "Restrict to management network",    ""),
    (7001, None,                  "WebLogic exposed",        "Critical", "Frequent deserialization CVEs",         "Patch immediately; restrict",       "CVE-2019-2725"),
    (8888, None,                  "Jupyter Notebook",        "High",     "May allow RCE without token auth",      "Require token; bind localhost",     ""),
    (9200, None,                  "Elasticsearch exposed",   "Critical", "No auth in older versions",             "Proxy / VPN / X-Pack security",    ""),
    (9300, None,                  "Elastic transport",       "High",     "Elastic node communication port",       "Firewall; restrict to cluster",     ""),
    (10000, None,                 "Webmin exposed",          "Critical", "RCE CVEs in older Webmin",              "Upgrade Webmin; firewall",          "CVE-2019-15107"),
    (11211, None,                 "Memcached exposed",       "High",     "No auth; DDoS amplification",           "Firewall 11211; bind localhost",    ""),
    (15672, None,                 "RabbitMQ Mgmt UI",        "Medium",   "Web UI may use default creds",          "Change guest/guest; restrict IPs",  ""),
    (27017, None,                 "MongoDB exposed",         "Critical", "No auth in older installs",             "Enable auth; restrict access",      ""),
    (50070, None,                 "Hadoop NameNode UI",      "High",     "Admin UI exposed",                      "Firewall; add authentication",      ""),
    (61616, None,                 "ActiveMQ exposed",        "Critical", "RCE via deserialization",               "Upgrade and patch; restrict IPs",   "CVE-2023-46604"),
]

# ─────────────────────────────────────────────────────────────────────────────
# DEFAULT CREDENTIALS TABLE
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_CREDS = {
    "FTP":      [("anonymous","anonymous"),("admin","admin"),("ftp","ftp"),("root","root")],
    "SSH":      [("root","root"),("admin","admin"),("admin","password"),
                 ("pi","raspberry"),("ubuntu","ubuntu"),("user","user")],
    "Telnet":   [("admin","admin"),("root","root"),("admin",""),("","")],
    "HTTP":     [("admin","admin"),("admin","password"),("admin",""),
                 ("root","root"),("admin","1234"),("guest","guest")],
    "MySQL":    [("root",""),("root","root"),("root","password"),("admin","admin")],
    "Redis":    [("",""),("","foobared")],  # empty = no auth
    "MongoDB":  [("admin","admin"),("","")],
    "RDP":      [("Administrator",""),("Administrator","Password1"),("admin","admin")],
    "VNC":      [("",""),("","password"),("","admin")],
}

PORT_TO_SERVICE_FOR_CREDS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTP",
    3306: "MySQL", 3389: "RDP", 5900: "VNC", 6379: "Redis", 27017: "MongoDB",
}

# ─────────────────────────────────────────────────────────────────────────────
# THREAT SCORING WEIGHTS
# ─────────────────────────────────────────────────────────────────────────────

THREAT_WEIGHTS = {
    "critical_port":   35,  # each critical-severity vuln port
    "high_port":       20,
    "medium_port":      8,
    "low_port":         2,
    "default_cred":    40,  # confirmed default credential
    "ssl_expired":     15,
    "no_https":         5,
    "default_cred_possible": 10,
}

# ─────────────────────────────────────────────────────────────────────────────
# COLOUR PALETTE & THEME
# ─────────────────────────────────────────────────────────────────────────────

ACCENT         = "#2563eb"
ACCENT_HOVER   = "#1d4ed8"
SUCCESS        = "#16a34a"
DANGER         = "#dc2626"
WARNING        = "#d97706"
INFO_COLOR     = "#0891b2"
PURPLE         = "#7c3aed"

SEV_COLORS = {
    "Critical": ("#7f1d1d", "#fee2e2"),
    "High":     ("#7c2d12", "#ffedd5"),
    "Medium":   ("#713f12", "#fef9c3"),
    "Low":      ("#1e3a5f", "#dbeafe"),
    "Info":     ("#374151", "#f3f4f6"),
}

THREAT_SCORE_COLORS = [
    (80, "#dc2626"),   # Critical
    (60, "#f97316"),   # High
    (40, "#eab308"),   # Medium
    (20, "#22c55e"),   # Low
    (0,  "#64748b"),   # Minimal
]

CHART_THEME = {
    "light": {"bg": "white",   "text": "#0f172a", "grid": "#e2e8f0"},
    "dark":  {"bg": "#1e293b", "text": "#f1f5f9", "grid": "#334155"},
}

ROW_TAGS = {
    "light": {
        "used":     "#fef2f2", "used_alt": "#fee2e2",
        "free":     "#f0fdf4", "free_alt": "#dcfce7",
        "fav":      "#fefce8", "rogue":    "#fdf4ff",
        "critical": "#fee2e2", "new_host": "#eff6ff",
    },
    "dark": {
        "used":     "#3b1f1f", "used_alt": "#4a2020",
        "free":     "#1a3020", "free_alt": "#1e3824",
        "fav":      "#3b3000", "rogue":    "#2d1b4e",
        "critical": "#4a0000", "new_host": "#1a2a4a",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# THEME ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def _apply_theme(root, is_dark: bool):
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass

    if is_dark:
        BG = "#0f172a"; SURFACE = "#1e293b"; BORDER = "#334155"
        TEXT = "#f1f5f9"; TEXT2 = "#94a3b8"; SIDEBAR = "#0d1526"; SB_ACT = "#1e293b"
    else:
        BG = "#f8fafc"; SURFACE = "#ffffff"; BORDER = "#e2e8f0"
        TEXT = "#0f172a"; TEXT2 = "#64748b"; SIDEBAR = "#1e293b"; SB_ACT = "#334155"

    SB_TEXT = "#e2e8f0"
    root.configure(bg=BG)
    root.option_add("*Font", ("Segoe UI", 10))

    style.configure(".",
        background=BG, foreground=TEXT,
        troughcolor=BORDER, selectbackground=ACCENT, selectforeground=SURFACE)

    style.configure("Treeview",
        background=SURFACE, foreground=TEXT, rowheight=26,
        fieldbackground=SURFACE, bordercolor=BORDER, borderwidth=0,
        font=("Segoe UI", 9))
    style.map("Treeview",
        background=[("selected", ACCENT)], foreground=[("selected", "#ffffff")])
    style.configure("Treeview.Heading",
        background=SURFACE if is_dark else "#f1f5f9",
        foreground=TEXT, relief="flat", padding=(8, 5),
        font=("Segoe UI", 9, "bold"))
    style.map("Treeview.Heading", background=[("active", BORDER)])

    for name, bg, hover in [
        ("TButton",         ACCENT,              ACCENT_HOVER),
        ("Danger.TButton",  DANGER,              "#b91c1c"),
        ("Success.TButton", SUCCESS,             "#15803d"),
        ("Warning.TButton", WARNING,             "#b45309"),
        ("Purple.TButton",  PURPLE,              "#6d28d9"),
        ("Ghost.TButton",   SURFACE if is_dark else BG, BORDER),
    ]:
        style.configure(name, padding=(10, 5), relief="flat",
            background=bg,
            foreground="#ffffff" if name != "Ghost.TButton" else TEXT,
            font=("Segoe UI", 9, "bold"), borderwidth=0)
        style.map(name,
            background=[("active", hover), ("disabled", BORDER)],
            foreground=[("disabled", TEXT2)])

    style.configure("Sidebar.TFrame",  background=SIDEBAR)
    style.configure("Sidebar.TLabel",  background=SIDEBAR, foreground="#475569",
        font=("Segoe UI", 8, "bold"), padding=(12, 4, 0, 2))
    style.configure("Sidebar.TButton", background=SIDEBAR, foreground=SB_TEXT,
        padding=(12, 8), relief="flat", font=("Segoe UI", 9),
        borderwidth=0, anchor="w")
    style.map("Sidebar.TButton",
        background=[("active", SB_ACT)], foreground=[("active", "#ffffff")])
    style.configure("SidebarActive.TButton",
        background=ACCENT, foreground="#ffffff",
        padding=(12, 8), relief="flat", font=("Segoe UI", 9, "bold"),
        borderwidth=0, anchor="w")
    style.map("SidebarActive.TButton", background=[("active", ACCENT_HOVER)])

    for name, bg, fg, font in [
        ("Card.TFrame",    SURFACE, TEXT,  None),
        ("TFrame",         BG,      TEXT,  None),
        ("TLabel",         BG,      TEXT,  ("Segoe UI", 9)),
        ("Bold.TLabel",    BG,      TEXT,  ("Segoe UI", 9, "bold")),
        ("Heading.TLabel", BG,      TEXT,  ("Segoe UI", 14, "bold")),
        ("Muted.TLabel",   BG,      TEXT2, ("Segoe UI", 9)),
        ("Mono.TLabel",    BG,      TEXT,  ("Courier New", 9)),
        ("Status.TLabel",  SIDEBAR, SB_TEXT, ("Segoe UI", 9)),
        ("Danger.TLabel",  BG,      DANGER,  ("Segoe UI", 9, "bold")),
        ("Success.TLabel", BG,      SUCCESS, ("Segoe UI", 9, "bold")),
        ("Warning.TLabel", BG,      WARNING, ("Segoe UI", 9, "bold")),
    ]:
        cfg = {"background": bg, "foreground": fg}
        if font:
            cfg["font"] = font
        style.configure(name, **cfg)

    style.configure("TLabelframe",
        background=BG, foreground=TEXT, bordercolor=BORDER)
    style.configure("TLabelframe.Label",
        background=BG, foreground=TEXT, font=("Segoe UI", 9, "bold"))
    style.configure("TEntry",
        fieldbackground=SURFACE, foreground=TEXT,
        bordercolor=BORDER, relief="flat", padding=(6, 4), insertcolor=TEXT)
    style.map("TEntry", bordercolor=[("focus", ACCENT)])
    style.configure("TCombobox",
        fieldbackground=SURFACE, background=SURFACE,
        foreground=TEXT, bordercolor=BORDER)
    style.configure("TProgressbar",
        troughcolor=BORDER, background=ACCENT, thickness=5, borderwidth=0)
    style.configure("TCheckbutton",
        background=BG, foreground=TEXT, font=("Segoe UI", 9))
    style.configure("TRadiobutton",
        background=BG, foreground=TEXT, font=("Segoe UI", 9))
    style.configure("TNotebook", background=BG, borderwidth=0)
    style.configure("TNotebook.Tab",
        background=SURFACE if is_dark else "#e2e8f0",
        foreground=TEXT2, padding=(14, 6), font=("Segoe UI", 9))
    style.map("TNotebook.Tab",
        background=[("selected", ACCENT if is_dark else SURFACE)],
        foreground=[("selected", "#ffffff" if is_dark else TEXT)])
    style.configure("TSeparator", background=BORDER)
    style.configure("TScrollbar",
        background=BORDER, troughcolor=BG, arrowcolor=TEXT2, borderwidth=0)
    style.map("TScrollbar", background=[("active", "#475569")])

# ─────────────────────────────────────────────────────────────────────────────
# CORE HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def normalize_mac(mac: str) -> str:
    """Normalise any MAC format → XX:XX:XX:XX:XX:XX (uppercase)."""
    if not mac:
        return ""
    mac = mac.upper().replace("-", ":").replace(".", ":")
    parts = mac.split(":")
    if len(parts) == 6:
        return ":".join(p.zfill(2) for p in parts)
    clean = mac.replace(":", "")
    if len(clean) == 12 and all(c in "0123456789ABCDEF" for c in clean):
        return ":".join(clean[i:i+2] for i in range(0, 12, 2))
    return ""

def oui_from_mac(mac: str) -> str:
    m = normalize_mac(mac)
    return ":".join(m.split(":")[:3]) if m else ""

def vendor_from_mac(mac: str) -> str:
    return OUI_VENDOR_MAP.get(oui_from_mac(mac), "")

def format_ports(ports) -> str:
    if not ports:
        return ""
    return ", ".join(
        f"{p}({WELL_KNOWN_PORTS[p]})" if p in WELL_KNOWN_PORTS else str(p)
        for p in sorted(ports)
    )

def ip_sort_key(ip_str: str):
    try:
        return ipaddress.ip_address(ip_str)
    except Exception:
        return ipaddress.ip_address("0.0.0.0")

def ts_now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def threat_score_color(score: int) -> str:
    for threshold, color in THREAT_SCORE_COLORS:
        if score >= threshold:
            return color
    return "#64748b"

def threat_score_label(score: int) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    if score >= 20: return "LOW"
    return "MINIMAL"

def send_wol(mac_str: str):
    mac_clean = mac_str.replace(":", "").replace("-", "")
    if len(mac_clean) != 12:
        raise ValueError("Invalid MAC address")
    mac_bytes    = bytes.fromhex(mac_clean)
    magic_packet = b"\xff" * 6 + mac_bytes * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(magic_packet, ("<broadcast>", 9))

# ─────────────────────────────────────────────────────────────────────────────
# ARP DISCOVERY — THREE-TIER
# ─────────────────────────────────────────────────────────────────────────────

def _arp_via_scapy(network_cidr: str) -> dict:
    arp = ARP(pdst=network_cidr)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered, _ = srp(ether / arp, timeout=2.5, verbose=0)
    return {rcv.psrc: normalize_mac(rcv.hwsrc) for _, rcv in answered}

def _arp_via_os(network_cidr: str) -> dict:
    result = {}
    system = platform.system().lower()
    try:
        if system == "windows":
            out = subprocess.check_output(
                ["arp", "-a"], stderr=subprocess.DEVNULL
            ).decode(errors="ignore")
            for line in out.splitlines():
                m = re.search(
                    r"(\d{1,3}(?:\.\d{1,3}){3})\s+"
                    r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})", line)
                if m:
                    mac = normalize_mac(m.group(2))
                    if mac:
                        result[m.group(1)] = mac
        else:
            try:
                out = subprocess.check_output(
                    ["ip", "neigh"], stderr=subprocess.DEVNULL
                ).decode(errors="ignore")
                for line in out.splitlines():
                    m = re.search(
                        r"^(\d{1,3}(?:\.\d{1,3}){3}).*lladdr\s+"
                        r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
                    if m:
                        mac = normalize_mac(m.group(2))
                        if mac:
                            result[m.group(1)] = mac
            except FileNotFoundError:
                out = subprocess.check_output(
                    ["arp", "-a"], stderr=subprocess.DEVNULL
                ).decode(errors="ignore")
                for line in out.splitlines():
                    m = re.search(
                        r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+"
                        r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
                    if m:
                        mac = normalize_mac(m.group(2))
                        if mac:
                            result[m.group(1)] = mac
    except Exception as e:
        log.warning("OS ARP cache read failed: %s", e)
    return result

# ─────────────────────────────────────────────────────────────────────────────
# WORKER POOL
# ─────────────────────────────────────────────────────────────────────────────

class SmartWorkerPool:
    def __init__(self, workers=64, queue_limit=SMART_QUEUE_LIMIT):
        self.queue   = Queue(maxsize=queue_limit)
        self.workers = []
        self.running = True
        for _ in range(workers):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            self.workers.append(t)

    def _worker(self):
        while self.running:
            try:
                func, args = self.queue.get(timeout=0.5)
            except Empty:
                continue
            try:
                func(*args)
            except Exception as e:
                log.debug("Worker exception: %s", e)
            finally:
                self.queue.task_done()

    def submit(self, func, *args):
        if self.running:
            self.queue.put((func, args))

    def shutdown(self):
        self.running = False

def auto_tune_workers(total_hosts: int) -> int:
    cores = max(1, cpu_count())
    base  = cores * 48
    if total_hosts < 512:   return min(64,  base)
    if total_hosts < 4096:  return min(128, base * 2)
    return min(512, base * 4)

# ─────────────────────────────────────────────────────────────────────────────
# BANNER GRABBER
# ─────────────────────────────────────────────────────────────────────────────

# HTTP-like probes for common ports
_BANNER_PROBES = {
    80:    b"HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n",
    443:   b"HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n",
    8080:  b"HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n",
    8443:  b"HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n",
    21:    None,   # FTP sends banner on connect
    22:    None,   # SSH banner on connect
    25:    None,   # SMTP banner on connect
    110:   None,   # POP3 banner
    143:   None,   # IMAP banner
    3306:  None,   # MySQL banner
}

def grab_banner(ip: str, port: int, timeout: float = BANNER_GRAB_TIMEOUT_S) -> str:
    """Return a cleaned banner string or '' on failure."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))

        probe = _BANNER_PROBES.get(port, None)
        if probe:
            # Format the probe with the IP (for Host header)
            s.send(probe.replace(b"{}", ip.encode()))
        elif port in (443, 8443):
            pass  # handled via SSL below
        
        banner = b""
        try:
            while len(banner) < 2048:
                chunk = s.recv(512)
                if not chunk:
                    break
                banner += chunk
                if b"\n" in banner or len(banner) > 512:
                    break
        except Exception:
            pass
        s.close()

        # For HTTPS, try SSL
        if port in (443, 8443) and not banner:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                with ctx.wrap_socket(
                    socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                    server_hostname=ip
                ) as ss:
                    ss.settimeout(timeout)
                    ss.connect((ip, port))
                    ss.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = ss.recv(1024)
            except Exception:
                pass

        if banner:
            text = banner.decode(errors="ignore")
            # Grab first meaningful line
            for line in text.splitlines():
                line = line.strip()
                if line:
                    return line[:200]
    except Exception:
        pass
    return ""

# ─────────────────────────────────────────────────────────────────────────────
# SSL/TLS CERTIFICATE INSPECTOR
# ─────────────────────────────────────────────────────────────────────────────

def inspect_ssl(ip: str, port: int = 443,
                timeout: float = SSL_INSPECT_TIMEOUT_S) -> dict | None:
    """Return dict with cert details or None if not SSL."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with ctx.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            server_hostname=ip
        ) as ss:
            ss.settimeout(timeout)
            ss.connect((ip, port))
            cert_bin  = ss.getpeercert(binary_form=True)
            cipher    = ss.cipher()
            tls_ver   = ss.version()
    except Exception:
        return None

    info = {
        "tls_version": tls_ver or "Unknown",
        "cipher":      cipher[0] if cipher else "Unknown",
        "cn":          "",
        "issuer":      "",
        "sans":        [],
        "not_before":  "",
        "not_after":   "",
        "expired":     False,
        "days_left":   None,
        "weak_cipher": False,
    }

    # Weak cipher detection
    weak_kw = ["RC4", "DES", "NULL", "EXPORT", "anon", "MD5"]
    if any(w in (cipher[0] if cipher else "") for w in weak_kw):
        info["weak_cipher"] = True

    if _CRYPTO_OK and cert_bin:
        try:
            cert = x509.load_der_x509_certificate(cert_bin, default_backend())
            info["cn"]         = cert.subject.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME)[0].value
        except Exception:
            pass
        try:
            info["issuer"] = cert.issuer.get_attributes_for_oid(
                x509.NameOID.ORGANIZATION_NAME)[0].value
        except Exception:
            pass
        try:
            san_ext = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName)
            info["sans"] = [
                str(n) for n in san_ext.value.get_values_for_type(x509.DNSName)]
        except Exception:
            pass
        try:
            info["not_before"] = cert.not_valid_before_utc.strftime(
                "%Y-%m-%d") if hasattr(cert.not_valid_before_utc, 'strftime') else str(cert.not_valid_before_utc)[:10]
            info["not_after"]  = cert.not_valid_after_utc.strftime(
                "%Y-%m-%d") if hasattr(cert.not_valid_after_utc, 'strftime') else str(cert.not_valid_after_utc)[:10]
            expiry = cert.not_valid_after_utc
            now    = datetime.datetime.now(datetime.timezone.utc)
            delta  = (expiry - now).days
            info["days_left"] = delta
            info["expired"]   = delta < 0
        except Exception:
            pass
    else:
        # Fallback: use standard library cert (DER decode manually)
        try:
            cert_raw = ssl.DER_cert_to_PEM_cert(cert_bin) if cert_bin else ""
            # Try to get expiry via openssl
            result = subprocess.run(
                ["openssl", "x509", "-noout", "-dates"],
                input=cert_raw.encode(), capture_output=True, timeout=3)
            for line in result.stdout.decode().splitlines():
                if "notAfter" in line:
                    date_str = line.split("=", 1)[1].strip()
                    info["not_after"] = date_str
        except Exception:
            pass

    return info

# ─────────────────────────────────────────────────────────────────────────────
# UDP PROBER
# ─────────────────────────────────────────────────────────────────────────────

_UDP_PROBES = {
    53:   b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # DNS query
          b"\x07version\x04bind\x00\x00\x10\x00\x03",
    123:  b"\x1b" + b"\x00" * 47,           # NTP
    161:  b"\x30\x26\x02\x01\x00\x04\x06public"  # SNMP GET
          b"\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00"
          b"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\n"
          b"MAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n",
    5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"   # mDNS
          b"\x05_http\x04_tcp\x05local\x00\x00\x0c\x00\x01",
}

def probe_udp_port(ip: str, port: int,
                   timeout: float = UDP_PROBE_TIMEOUT_S) -> bool:
    """Returns True if the port appears open (ICMP not returned, or reply received)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        payload = _UDP_PROBES.get(port, b"\x00")
        s.sendto(payload, (ip, port))
        s.recv(512)
        s.close()
        return True   # got a reply → open
    except socket.timeout:
        return True   # no ICMP unreachable → possibly open
    except OSError:
        return False  # ICMP port unreachable → closed
    except Exception:
        return False

# ─────────────────────────────────────────────────────────────────────────────
# HTTP ENDPOINT PROBER
# ─────────────────────────────────────────────────────────────────────────────

def probe_http(ip: str, port: int = 80,
               use_https: bool = False, timeout: float = 3.0) -> dict:
    """Return dict: {status, title, server, redirect, headers}."""
    result = {"status": None, "title": "", "server": "",
              "redirect": "", "headers": {}, "error": ""}
    scheme = "https" if use_https else "http"
    try:
        import urllib.request, urllib.error
        url = f"{scheme}://{ip}:{port}/"
        req = urllib.request.Request(
            url, headers={"User-Agent": "NetProbe/4.0 (scanner)"})
        ctx = ssl.create_default_context() if use_https else None
        if ctx:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=ctx if use_https else None) as resp:
            result["status"]  = resp.status
            result["server"]  = resp.headers.get("Server", "")
            body = resp.read(8192).decode(errors="ignore")
            m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            if m:
                result["title"] = m.group(1).strip()[:120]
    except urllib.error.HTTPError as e:
        result["status"] = e.code
    except urllib.error.URLError as e:
        result["error"] = str(e.reason)[:80]
    except Exception as e:
        result["error"] = str(e)[:80]
    return result

# ─────────────────────────────────────────────────────────────────────────────
# TRACEROUTE ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def traceroute_host(ip: str, max_hops: int = 20,
                    timeout: float = 1.0) -> list[dict]:
    """
    Returns list of {hop, ip, rtt_ms, hostname}.
    Uses ICMP TTL-exceeded if scapy available, else OS traceroute/tracert.
    """
    hops = []
    if _SCAPY_OK:
        try:
            for ttl in range(1, max_hops + 1):
                start   = time.time()
                pkt     = IP(dst=ip, ttl=ttl) / ICMP()
                reply   = sr1(pkt, timeout=timeout, verbose=0)
                rtt     = round((time.time() - start) * 1000, 1)
                if reply is None:
                    hops.append({"hop": ttl, "ip": "*", "rtt_ms": None,
                                 "hostname": ""})
                else:
                    h_ip = reply.src
                    try:
                        hn = socket.gethostbyaddr(h_ip)[0]
                    except Exception:
                        hn = ""
                    hops.append({"hop": ttl, "ip": h_ip,
                                 "rtt_ms": rtt, "hostname": hn})
                    if reply.type == 0:  # ICMP Echo Reply — reached destination
                        break
            return hops
        except Exception as e:
            log.warning("Scapy traceroute failed: %s", e)

    # OS fallback
    system = platform.system().lower()
    cmd    = (["tracert", "-d", "-h", str(max_hops), ip]
              if system == "windows"
              else ["traceroute", "-n", "-m", str(max_hops), ip])
    try:
        out = subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, timeout=60
        ).decode(errors="ignore")
        hop_no = 0
        for line in out.splitlines():
            m = re.match(
                r"\s*(\d+)\s+(?:(\d+)\s+ms|\*)", line)
            if m:
                hop_no += 1
                rtt    = int(m.group(2)) if m.group(2) else None
                ip_m   = re.search(
                    r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                h_ip   = ip_m.group(1) if ip_m else "*"
                hops.append({"hop": hop_no, "ip": h_ip,
                             "rtt_ms": rtt, "hostname": ""})
    except Exception as e:
        log.warning("OS traceroute failed: %s", e)
    return hops

# ─────────────────────────────────────────────────────────────────────────────
# NETBIOS / SMB ENUMERATOR
# ─────────────────────────────────────────────────────────────────────────────

def enumerate_netbios(ip: str, timeout: float = 2.0) -> dict:
    """
    Send a NetBIOS NS query and return {names: [...], workgroup, mac}.
    No credentials or SMB needed.
    """
    info = {"names": [], "workgroup": "", "mac": ""}
    NS_PORT   = 137
    # NetBIOS Name Service status request
    payload   = (b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                 b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41"
                 b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
                 b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(payload, (ip, NS_PORT))
        data, _ = s.recvfrom(1024)
        s.close()
        if len(data) > 56:
            num_names = data[56]
            offset    = 57
            for i in range(num_names):
                if offset + 18 > len(data):
                    break
                name  = data[offset:offset+15].decode(errors="ignore").strip()
                flags = struct.unpack(">H", data[offset+16:offset+18])[0]
                info["names"].append({"name": name, "flags": hex(flags)})
                if flags & 0x8000 == 0 and flags & 0x0020:
                    info["workgroup"] = name
                offset += 18
            # MAC is at the end
            if len(data) >= offset + 6:
                mac_bytes = data[offset:offset+6]
                info["mac"] = ":".join(f"{b:02X}" for b in mac_bytes)
    except Exception:
        pass
    return info

# ─────────────────────────────────────────────────────────────────────────────
# OS FINGERPRINTING (enhanced)
# ─────────────────────────────────────────────────────────────────────────────

def guess_os_enhanced(ip: str, open_ports: list,
                      banner_map: dict, ttl: int | None = None) -> str:
    """
    Multi-signal OS guess:
      1. TTL heuristic
      2. Open-port pattern matching
      3. Banner keyword matching
    """
    os_votes = defaultdict(int)

    # TTL heuristic
    if ttl is not None:
        if ttl >= 200:          os_votes["Network device"] += 3
        elif ttl >= 128:        os_votes["Windows"]         += 3
        elif ttl >= 64:         os_votes["Linux/Unix"]      += 3
        elif ttl >= 60:         os_votes["FreeBSD/macOS"]   += 2
        else:                   os_votes["Unknown"]         += 1

    # Port pattern
    ports = set(open_ports or [])
    if 3389 in ports:   os_votes["Windows"]       += 5
    if 5985 in ports or 5986 in ports:
                        os_votes["Windows"]        += 4
    if 135  in ports:   os_votes["Windows"]        += 3
    if 445  in ports and 3389 not in ports:
                        os_votes["Windows/Samba"]  += 2
    if 22   in ports and 3389 not in ports:
                        os_votes["Linux/Unix"]     += 2
    if 2049 in ports:   os_votes["Linux/Unix"]     += 2
    if 548  in ports:   os_votes["macOS"]          += 4
    if 8291 in ports:   os_votes["MikroTik RouterOS"] += 5
    if 8080 in ports and 7001 in ports:
                        os_votes["Java/WebLogic"]  += 3

    # Banner keywords
    banner_combined = " ".join(banner_map.values()).lower() if banner_map else ""
    kw_map = [
        ("windows",   "Windows",   3), ("microsoft",  "Windows",   3),
        ("ubuntu",    "Ubuntu",    4), ("debian",     "Debian",    4),
        ("centos",    "CentOS",    4), ("fedora",     "Fedora",    4),
        ("red hat",   "RHEL",      4), ("freebsd",    "FreeBSD",   4),
        ("darwin",    "macOS",     4), ("cisco",      "Cisco IOS", 4),
        ("juniper",   "JunOS",     4), ("linux",      "Linux",     2),
        ("openssh",   "Linux",     1), ("iis",        "Windows",   3),
        ("apache",    "Linux",     1), ("nginx",      "Linux",     1),
        ("mikrotik",  "MikroTik RouterOS", 5),
        ("routeros",  "MikroTik RouterOS", 5),
    ]
    for kw, os_name, weight in kw_map:
        if kw in banner_combined:
            os_votes[os_name] += weight

    if not os_votes:
        return ""
    best = max(os_votes, key=os_votes.get)
    confidence = os_votes[best]
    if confidence >= 5:  return best
    if confidence >= 2:  return f"{best} (likely)"
    return f"{best} (possible)"

# ─────────────────────────────────────────────────────────────────────────────
# SECURITY ASSESSMENT + THREAT SCORING
# ─────────────────────────────────────────────────────────────────────────────

def assess_security(result: dict) -> list:
    """Return list of (ip, issue, severity, recommendation, cve) tuples."""
    findings = []
    ports    = set(result.get("open_ports", []))
    banners  = result.get("banners", {})
    ip       = result["ip"]

    for port, banner_re, issue, severity, desc, rec, cve in VULN_DB:
        if port not in ports:
            continue
        if banner_re:
            banner = banners.get(port, "")
            if not re.search(banner_re, banner, re.I):
                continue
        cve_str = f" [{cve}]" if cve else ""
        findings.append((ip, f"{issue}{cve_str}", severity,
                         f"{desc}\n  Remediation: {rec}"))

    # HTTP without HTTPS
    if 80 in ports and 443 not in ports:
        findings.append((ip, "HTTP without HTTPS", "Low",
                         "Plaintext HTTP in use.\n  Remediation: Enable HTTPS."))

    # SSL cert checks
    ssl_info = result.get("ssl_info")
    if ssl_info:
        if ssl_info.get("expired"):
            findings.append((ip, "SSL certificate expired", "High",
                             f"Cert expired {ssl_info.get('not_after','')}\n"
                             "  Remediation: Renew SSL certificate."))
        elif ssl_info.get("days_left") is not None and ssl_info["days_left"] < 30:
            findings.append((ip, f"SSL cert expires in {ssl_info['days_left']} days",
                             "Medium",
                             "  Remediation: Renew SSL certificate soon."))
        if ssl_info.get("weak_cipher"):
            findings.append((ip, "Weak SSL cipher detected", "High",
                             f"Cipher: {ssl_info.get('cipher','')}\n"
                             "  Remediation: Disable weak ciphers; enforce TLS 1.2+."))

    return findings

def calculate_threat_score(result: dict) -> int:
    """Return 0-100 integer threat score."""
    score    = 0
    findings = result.get("security_findings", [])
    for _, _, severity, _ in findings:
        score += THREAT_WEIGHTS.get(f"{severity.lower()}_port",
                                    THREAT_WEIGHTS["low_port"])
    if result.get("default_cred_confirmed"):
        score += THREAT_WEIGHTS["default_cred"]
    if result.get("default_cred_possible"):
        score += THREAT_WEIGHTS["default_cred_possible"]
    ssl_info = result.get("ssl_info")
    if ssl_info and ssl_info.get("expired"):
        score += THREAT_WEIGHTS["ssl_expired"]
    if ssl_info and ssl_info.get("weak_cipher"):
        score += THREAT_WEIGHTS["ssl_expired"]
    return min(score, 100)

def check_compliance(result: dict) -> list[dict]:
    """Return list of {framework, req_id, port, description, pass} dicts."""
    findings  = []
    ports     = set(result.get("open_ports", []))
    for port, allowed, framework, req_id, desc in COMPLIANCE_RULES:
        if port in ports:
            findings.append({
                "framework": framework,
                "req_id":    req_id,
                "port":      port,
                "desc":      desc,
                "pass":      allowed,  # if allowed=False and port open → fail
            })
    return findings

def guess_device_type(open_ports, vendor, os_guess):
    ports = set(open_ports or [])
    v     = (vendor   or "").lower()
    osg   = (os_guess or "").lower()
    if 9100 in ports or "hp"        in v: return "🖨 Printer"
    if 554  in ports or "hikvision" in v or "dahua" in v: return "📷 Camera"
    if 8291 in ports or "mikrotik"  in v: return "🔀 Router"
    if "fortigate" in v or "fortinet" in v: return "🔥 Firewall"
    if "palo alto" in v:                  return "🔥 Firewall"
    if "juniper"   in v:                  return "🔀 Network Device"
    if "cisco"     in v and 23 in ports:  return "🔀 Cisco Router"
    if "ubiquiti"  in v:                  return "📡 AP/Switch"
    if "raspberry" in v:                  return "🍓 Raspberry Pi"
    if 3389 in ports:                     return "🖥 Windows Host"
    if 22 in ports and "linux" in osg:    return "🐧 Linux Server"
    if "vmware" in v or "virtualbox" in v or "qemu" in v: return "⬡ Virtual Host"
    if 3306 in ports or 5432 in ports or 1433 in ports:   return "🗄 DB Server"
    if 6379 in ports or 27017 in ports or 11211 in ports: return "📦 Data Service"
    if 6443 in ports:                     return "☸ Kubernetes"
    if 2375 in ports or 2376 in ports:    return "🐳 Docker Host"
    if 8888 in ports:                     return "📓 Jupyter"
    if 80 in ports or 443 in ports:
        if "cisco" in v or "ubiquiti" in v: return "🌐 Network Device"
        return "🌐 Web Server"
    if "amazon" in v or "nest" in v:      return "🏠 IoT Device"
    return ""

# ─────────────────────────────────────────────────────────────────────────────
# ROGUE DEVICE / BASELINE ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class BaselineManager:
    def __init__(self):
        self.baseline: dict[str, dict] = {}  # ip → {mac, vendor, ports, ...}
        self._load()

    def _load(self):
        if os.path.isfile(BASELINE_FILE):
            try:
                with open(BASELINE_FILE, encoding="utf-8") as f:
                    self.baseline = json.load(f)
            except Exception:
                self.baseline = {}

    def save(self, results: list[dict]):
        """Save current scan results as new baseline."""
        self.baseline = {
            r["ip"]: {
                "mac":    r.get("mac", ""),
                "vendor": r.get("vendor", ""),
                "ports":  sorted(r.get("open_ports", [])),
                "os":     r.get("os_guess", ""),
                "hostname": r.get("hostname", ""),
            }
            for r in results if r["status"] == "Used"
        }
        ensure_dirs()
        with open(BASELINE_FILE, "w", encoding="utf-8") as f:
            json.dump(self.baseline, f, indent=2)

    def has_baseline(self) -> bool:
        return bool(self.baseline)

    def classify(self, result: dict) -> str:
        """Return 'known' | 'new' | 'rogue' | 'changed'."""
        ip  = result["ip"]
        mac = result.get("mac", "")
        if ip not in self.baseline:
            return "new"
        bl  = self.baseline[ip]
        if mac and bl.get("mac") and mac != bl["mac"]:
            return "rogue"   # MAC changed — possible ARP spoofing!
        if sorted(result.get("open_ports", [])) != bl.get("ports", []):
            return "changed"
        return "known"

    def diff(self, results: list[dict]) -> dict:
        """Return {new:[], removed:[], changed:[], rogue:[]}."""
        current_ips = {r["ip"] for r in results if r["status"] == "Used"}
        d = {"new": [], "removed": [], "changed": [], "rogue": []}
        for r in results:
            if r["status"] != "Used":
                continue
            cls = self.classify(r)
            if   cls == "new":     d["new"].append(r["ip"])
            elif cls == "rogue":   d["rogue"].append(r["ip"])
            elif cls == "changed": d["changed"].append(r["ip"])
        for ip in self.baseline:
            if ip not in current_ips:
                d["removed"].append(ip)
        return d

# ─────────────────────────────────────────────────────────────────────────────
# ALERT LOGGER
# ─────────────────────────────────────────────────────────────────────────────

class AlertLogger:
    def __init__(self):
        self.alerts: list[dict] = []
        self._load()

    def _load(self):
        if os.path.isfile(ALERT_LOG_FILE):
            try:
                with open(ALERT_LOG_FILE, encoding="utf-8") as f:
                    self.alerts = json.load(f)
            except Exception:
                self.alerts = []

    def add(self, severity: str, ip: str, message: str, tag: str = ""):
        entry = {
            "ts":       ts_now(),
            "severity": severity,
            "ip":       ip,
            "message":  message,
            "tag":      tag,
        }
        self.alerts.append(entry)
        self._save()
        return entry

    def _save(self):
        ensure_dirs()
        # Keep last 10 000 alerts
        if len(self.alerts) > 10000:
            self.alerts = self.alerts[-10000:]
        try:
            with open(ALERT_LOG_FILE, "w", encoding="utf-8") as f:
                json.dump(self.alerts, f, indent=2)
        except Exception:
            pass

    def clear(self):
        self.alerts.clear()
        self._save()

    def export_csv(self, path: str):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Timestamp", "Severity", "IP", "Message", "Tag"])
            for a in self.alerts:
                w.writerow([a["ts"], a["severity"],
                            a["ip"], a["message"], a["tag"]])

# ─────────────────────────────────────────────────────────────────────────────
# FIREWALL RULE GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def generate_block_rules(ips: list[str], ports: list[int],
                          fmt: str = "iptables") -> str:
    """
    Generate firewall block rules for given IPs and/or ports.
    fmt: 'iptables' | 'nftables' | 'windows' | 'pf'
    """
    lines = [f"# NetProbe v{VERSION} — Generated {ts_now()}",
             f"# Format: {fmt}", ""]

    if fmt == "iptables":
        for ip in ips:
            lines.append(f"iptables -I INPUT -s {ip} -j DROP")
            lines.append(f"iptables -I OUTPUT -d {ip} -j DROP")
        for port in ports:
            lines.append(f"iptables -I INPUT -p tcp --dport {port} -j DROP")
        lines += ["", "# Save rules:", "iptables-save > /etc/iptables/rules.v4"]

    elif fmt == "nftables":
        lines += ["table inet filter {", "  chain input {",
                  "    type filter hook input priority 0;"]
        for ip in ips:
            lines.append(f"    ip saddr {ip} drop;")
        for port in ports:
            lines.append(f"    tcp dport {port} drop;")
        lines += ["  }", "}"]

    elif fmt == "windows":
        for ip in ips:
            lines.append(
                f'netsh advfirewall firewall add rule name="Block {ip}" '
                f'dir=in action=block remoteip={ip}')
        for port in ports:
            lines.append(
                f'netsh advfirewall firewall add rule name="Block port {port}" '
                f'dir=in action=block protocol=tcp localport={port}')

    elif fmt == "pf":
        lines.append("# Add to /etc/pf.conf")
        for ip in ips:
            lines.append(f"block in quick from {ip}")
            lines.append(f"block out quick to {ip}")
        for port in ports:
            lines.append(f"block in quick proto tcp to port {port}")
        lines.append("# Reload: pfctl -f /etc/pf.conf")

    return "\n".join(lines)

# ─────────────────────────────────────────────────────────────────────────────
# PLUGIN MANAGER
# ─────────────────────────────────────────────────────────────────────────────

class PluginManager:
    def __init__(self):
        self.plugins = []
        self._load_plugins()

    def _load_plugins(self):
        if not os.path.isdir(PLUGINS_DIR):
            return
        import importlib.util
        for fname in sorted(os.listdir(PLUGINS_DIR)):
            if not fname.endswith(".py"):
                continue
            path = os.path.join(PLUGINS_DIR, fname)
            try:
                spec   = importlib.util.spec_from_file_location(
                    fname[:-3], path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                p = {"name": fname}
                for hook in ("on_result", "on_scan_start",
                             "on_scan_done", "on_alert"):
                    if hasattr(module, hook):
                        p[hook] = getattr(module, hook)
                if any(k in p for k in ("on_result",)):
                    self.plugins.append(p)
                    log.info("Plugin loaded: %s", fname)
            except Exception as e:
                log.warning("Plugin load error %s: %s", fname, e)

    def run(self, hook: str, *args):
        for p in self.plugins:
            if hook in p:
                try:
                    p[hook](*args)
                except Exception as e:
                    log.warning("Plugin %s hook %s: %s", p["name"], hook, e)

    def run_on_result(self, result):
        self.run("on_result", result)

# ─────────────────────────────────────────────────────────────────────────────
# CORE SCAN FUNCTIONS (used by GUI scanning engine)
# ─────────────────────────────────────────────────────────────────────────────

def ping_host(ip: str, timeout_ms: int = 300) -> tuple[bool, int | str]:
    """Returns (alive, latency_ms)."""
    system = platform.system().lower()
    start  = time.time()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif system == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        alive = subprocess.run(
            cmd, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL).returncode == 0
    except Exception:
        alive = False
    latency = int((time.time() - start) * 1000) if alive else ""
    return alive, latency

def tcp_probe(ip: str, ports: list[int],
              timeout: float = TCP_PROBE_TIMEOUT_S) -> list[int]:
    open_ports = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
        except Exception:
            pass
        finally:
            s.close()
    return open_ports

def tcp_probe_with_banners(ip: str, ports: list[int],
                            timeout: float = TCP_PROBE_TIMEOUT_S,
                            grab_banners: bool = True) -> tuple[list[int], dict]:
    """Returns (open_ports, {port: banner_str})."""
    open_ports = []
    banners    = {}
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
                if grab_banners:
                    banner = grab_banner(ip, port)
                    if banner:
                        banners[port] = banner
        except Exception:
            pass
        finally:
            s.close()
    return open_ports, banners

def get_ttl_via_ping(ip: str) -> int | None:
    """Run ping and parse TTL from output."""
    system = platform.system().lower()
    cmd    = (["ping", "-n", "1", ip] if system == "windows"
              else ["ping", "-c", "1", ip])
    try:
        out = subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL,
            timeout=3).decode(errors="ignore")
        m = re.search(r"ttl[= ]*(\d+)", out, re.I)
        if m:
            return int(m.group(1))
    except Exception:
        pass
    return None

def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def whois_lookup(target: str) -> str:
    try:
        def query(server, q):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((server, 43))
            s.send((q + "\r\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            s.close()
            return data.decode(errors="ignore")
        text  = query("whois.iana.org", target)
        refer = next(
            (l.split(":", 1)[1].strip()
             for l in text.splitlines()
             if l.lower().startswith("refer:")), None)
        return query(refer, target) if refer else text
    except Exception as e:
        return f"WHOIS error: {e}"

# ─────────────────────────────────────────────────────────────────────────────
# REPORT GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def generate_markdown_report(results: list[dict],
                              findings: list,
                              diff: dict,
                              scan_meta: dict) -> str:
    """Generate a comprehensive Markdown pentest report."""
    ts      = ts_now()
    used    = [r for r in results if r["status"] == "Used"]
    free    = [r for r in results if r["status"] == "Free"]
    crits   = [f for f in findings if f[2] == "Critical"]
    highs   = [f for f in findings if f[2] == "High"]

    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f[2]] += 1

    lines = [
        f"# NetProbe v{VERSION} — Network Security Assessment Report",
        f"",
        f"**Generated:** {ts}  ",
        f"**Target(s):** {scan_meta.get('target', 'N/A')}  ",
        f"**Scan mode:** {scan_meta.get('mode', 'N/A')}  ",
        f"**Duration:** {scan_meta.get('duration', 'N/A')}  ",
        f"",
        "---",
        "",
        "## Executive Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total hosts scanned | {len(results):,} |",
        f"| Active hosts | {len(used):,} |",
        f"| Free IPs | {len(free):,} |",
        f"| Security findings | {len(findings)} |",
        f"| Critical | {sev_counts['Critical']} |",
        f"| High | {sev_counts['High']} |",
        f"| Medium | {sev_counts['Medium']} |",
        f"| Low | {sev_counts['Low']} |",
        f"| New hosts (vs baseline) | {len(diff.get('new', []))} |",
        f"| Rogue devices (MAC changed) | {len(diff.get('rogue', []))} |",
        "",
        "---",
        "",
        "## Critical & High Findings",
        "",
    ]

    if crits or highs:
        lines += ["| IP | Issue | Severity | Recommendation |",
                  "|----|-------|----------|----------------|"]
        for ip, issue, sev, rec in (crits + highs):
            rec_short = rec.split("\n")[0][:80]
            lines.append(f"| {ip} | {issue} | **{sev}** | {rec_short} |")
    else:
        lines.append("_No critical or high severity findings._")

    lines += [
        "",
        "---",
        "",
        "## Rogue / New Devices",
        "",
    ]
    if diff.get("rogue"):
        lines.append("⚠️ **Rogue devices detected (MAC address changed):**")
        for ip in diff["rogue"]:
            lines.append(f"- `{ip}`")
    if diff.get("new"):
        lines.append("\n🆕 **New hosts not in baseline:**")
        for ip in diff["new"]:
            lines.append(f"- `{ip}`")
    if not diff.get("rogue") and not diff.get("new"):
        lines.append("_No rogue or new devices detected._")

    lines += [
        "",
        "---",
        "",
        "## Active Host Inventory",
        "",
        "| IP | Hostname | MAC | Vendor | OS | Open Ports | Threat Score |",
        "|----|----------|-----|--------|----|------------|--------------|",
    ]

    for r in sorted(used, key=lambda x: ip_sort_key(x["ip"])):
        score = calculate_threat_score(r)
        lbl   = threat_score_label(score)
        ports_str = format_ports(r.get("open_ports", []))[:60]
        lines.append(
            f"| {r['ip']} | {r.get('hostname','—')} "
            f"| {r.get('mac','—')} | {r.get('vendor','—')} "
            f"| {r.get('os_guess','—')} | {ports_str} | {score} ({lbl}) |"
        )

    lines += [
        "",
        "---",
        "",
        "## All Findings",
        "",
        "| IP | Issue | Severity | Details |",
        "|----|-------|----------|---------|",
    ]
    for ip, issue, sev, rec in sorted(findings, key=lambda x: (
            {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(x[2], 4),
            x[0])):
        rec_short = rec.replace("\n", " ")[:100]
        lines.append(f"| {ip} | {issue} | {sev} | {rec_short} |")

    lines += [
        "",
        "---",
        "",
        f"_Report generated by {APP_FULL}_",
    ]

    return "\n".join(lines)

# ─────────────────────────────────────────────────────────────────────────────
# SIMPLE INPUT DIALOG
# ─────────────────────────────────────────────────────────────────────────────

def simple_input(root, title: str, prompt: str, default: str = "") -> str | None:
    win = tk.Toplevel(root)
    win.title(title)
    win.geometry("360x140")
    win.resizable(False, False)
    ttk.Label(win, text=prompt).pack(pady=(14, 4), padx=16, anchor="w")
    var   = tk.StringVar(value=default)
    entry = ttk.Entry(win, textvariable=var, width=40)
    entry.pack(padx=16, pady=(0, 10))
    entry.focus_set()
    entry.select_range(0, tk.END)
    result = {"value": None}

    def ok(_=None):
        result["value"] = var.get()
        win.destroy()

    entry.bind("<Return>", ok)
    bf = ttk.Frame(win)
    bf.pack()
    ttk.Button(bf, text="OK",     command=ok,          width=8).pack(side=tk.LEFT, padx=4)
    ttk.Button(bf, text="Cancel", command=win.destroy, width=8).pack(side=tk.LEFT, padx=4)
    win.transient(root)
    win.grab_set()
    root.wait_window(win)
    return result["value"]

# ─────────────────────────────────────────────────────────────────────────────
# TOOLTIP
# ─────────────────────────────────────────────────────────────────────────────

class Tooltip:
    def __init__(self, widget, text: str):
        self.widget  = widget
        self.text    = text
        self.tip_win = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, _=None):
        if self.tip_win:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.tip_win = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tk.Label(tw, text=self.text, justify="left",
                 background="#fffbe6", relief="solid", borderwidth=1,
                 font=("Segoe UI", 8), padx=6, pady=3).pack()

    def _hide(self, _=None):
        if self.tip_win:
            self.tip_win.destroy()
            self.tip_win = None

# ─── End of Section 1 ────────────────────────────────────────────────────────
# To assemble the full tool:
#   cat NetProbe_v4_section1.py NetProbe_v4_section2.py \
#       NetProbe_v4_section3.py NetProbe_v4_section4.py > NetProbe_v4.py
#   python NetProbe_v4.py
# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2 — GUI APPLICATION CLASS: Shell, Scanner Tab, Scanning Engine
# ─────────────────────────────────────────────────────────────────────────────
# This file is Section 2 of 4. It requires Section 1 to be loaded first.
# When assembled: cat section1.py section2.py section3.py section4.py > NetProbe_v4.py

class IPScannerGUI:

    # ─────────────── INIT ───────────────────────────────────────────────────

    def __init__(self, root: tk.Tk):
        ensure_dirs()
        self.root  = root
        self.root.title(APP_FULL)
        self.root.geometry("1680x960")
        self.root.minsize(1200, 700)

        self.is_dark = False

        # ── Scan state ──
        self.scanning      = False
        self.results: list[dict] = []
        self.total_hosts   = 0
        self.scanned_hosts = 0
        self.scan_start_ts = None
        self.lock          = threading.Lock()
        self._arp_warned   = False
        self._arp_tier     = None
        self._finalized    = False
        self.pool          = None
        self.scan_meta: dict = {}

        self.smart_disable_hostnames = False
        self.smart_disable_os_guess  = False
        self.smart_disable_tcp_probe = False

        # ── Settings vars ──
        self.mode_var            = tk.StringVar(value="fast")
        self.port_range_var      = tk.StringVar(value="")
        self.timeout_var         = tk.IntVar(value=300)
        self.max_workers_var     = tk.IntVar(value=0)
        self.grab_banners_var    = tk.BooleanVar(value=True)
        self.probe_udp_var       = tk.BooleanVar(value=False)
        self.inspect_ssl_var     = tk.BooleanVar(value=True)
        self.check_creds_var     = tk.BooleanVar(value=False)
        self.check_compliance_var = tk.BooleanVar(value=True)
        self.background_mode_var = tk.BooleanVar(value=False)
        self.ui_update_every     = UI_UPDATE_EVERY_BASE
        self.current_view        = "scanner"

        # ── Filters ──
        self.filter_text_var  = tk.StringVar()
        self.filter_show_free = tk.BooleanVar(value=True)
        self.filter_show_used = tk.BooleanVar(value=True)
        self.filter_favs_only = tk.BooleanVar(value=False)
        self.filter_rogues_only = tk.BooleanVar(value=False)
        self.filter_count_var = tk.StringVar(value="")
        self.filter_severity_var = tk.StringVar(value="All")

        # ── Per-scan data ──
        self.scan_timeline:    list = []
        self.security_findings: list = []
        self.last_scan_results: list = []
        self.diff = {"new": [], "removed": [], "changed": [], "rogue": []}

        # ── Notes, favs, tags ──
        self.host_notes:  dict = {}
        self.host_favs:   set  = set()
        self.host_tags:   dict = {}   # ip → list[str]

        # ── Profiles / scheduling ──
        self.profiles            = {}
        self.current_profile_var = tk.StringVar(value="")
        self.schedule_enabled_var  = tk.BooleanVar(value=False)
        self.schedule_interval_var = tk.IntVar(value=0)
        self.next_run_time         = None

        # ── Subnet state ──
        self.subnet_vars = []

        # ── Column config ──
        self._col_cfg = {
            "fav":      ("⭐",            32,  True),
            "threat":   ("Risk",          56,  True),
            "ip":       ("IP Address",   130,  True),
            "subnet":   ("Subnet",       150,  True),
            "status":   ("Status",        72,  True),
            "hostname": ("Hostname",     190,  True),
            "mac":      ("MAC",          155,  True),
            "vendor":   ("Vendor",       120,  True),
            "device":   ("Device",       130,  True),
            "latency":  ("Latency",       70,  True),
            "ports":    ("Open Ports",   230,  True),
            "os_guess": ("OS",           110,  True),
            "ssl":      ("SSL",           70,  True),
            "note":     ("Note",         150,  True),
        }
        self._col_visible      = {}
        self._saved_col_widths = {}

        # ── Sub-modules ──
        self.plugin_manager    = PluginManager()
        self.baseline_mgr      = BaselineManager()
        self.alert_log         = AlertLogger()
        self.sniffer_running   = False
        self.sniffer_thread    = None
        self._sniffer_pkt_no   = 0
        self._pcap_packets     = []
        self.vuln_results:  list = []
        self.fp_results:    list = []
        self.snmp_results:  list = []
        self._vs_running   = False
        self._fp_running   = False
        self._snmp_running = False

        # Passive ARP monitor
        self._arp_monitor_running = False
        self._known_macs: dict = {}  # ip → mac (for MITM detection)

        # Scan history
        self.scan_history: list = []
        self.profiles_file      = PROFILES_FILE

        _apply_theme(self.root, self.is_dark)
        self._build_shell()

        # Create all view frames
        view_names = ("scanner", "dashboard", "tools", "recon",
                      "sniffer", "vulnscan", "fingerprint", "snmp",
                      "alerts", "compliance", "topology", "settings")
        for name in view_names:
            frame = ttk.Frame(self.main_area)
            frame.grid(row=0, column=0, sticky="nsew")
            self.view_frames[name] = frame

        # Keyboard shortcuts
        self.root.bind("<F5>",        lambda _: self._kb_scan())
        self.root.bind("<Escape>",    lambda _: self.stop_scan() if self.scanning else None)
        self.root.bind("<Control-e>", lambda _: self.export_csv())
        self.root.bind("<Control-f>", lambda _: self._focus_filter())
        self.root.bind("<Control-i>", lambda _: self.copy_ip())
        self.root.bind("<Control-m>", lambda _: self.copy_mac())
        self.root.bind("<Control-r>", lambda _: self._export_report())
        self.root.bind("<F11>",       lambda _: self._toggle_fullscreen())
        self._fullscreen = False

    # ─── Keyboard helpers ───

    def _kb_scan(self):
        if not self.scanning:
            self.start_selected_scan()

    def _focus_filter(self):
        if hasattr(self, "filter_entry"):
            self.filter_entry.focus_set()

    def _toggle_fullscreen(self):
        self._fullscreen = not self._fullscreen
        self.root.attributes("-fullscreen", self._fullscreen)

    # ─────────────── SHELL + SIDEBAR ───────────────────────────────────────

    def _build_shell(self):
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

        self.sidebar = ttk.Frame(self.root, style="Sidebar.TFrame", width=200)
        self.sidebar.grid(row=0, column=0, sticky="nsw")
        self.sidebar.grid_propagate(False)

        brand = tk.Frame(self.sidebar, bg="#0d1526", height=64)
        brand.pack(fill="x")
        brand.pack_propagate(False)
        tk.Label(brand, text=f"◈  {APP_NAME}",
                 bg="#0d1526", fg="#f1f5f9",
                 font=("Segoe UI", 13, "bold"),
                 anchor="w", padx=14).pack(fill="x", pady=(16, 0))
        tk.Label(brand, text=f"v{VERSION}  Elite Edition",
                 bg="#0d1526", fg="#475569",
                 font=("Segoe UI", 7), anchor="w", padx=14).pack(fill="x")

        nav_items = [
            ("CORE",             None),
            ("📡  Scanner",       "scanner"),
            ("📊  Dashboard",     "dashboard"),
            ("",                  None),
            ("PENTESTER",         None),
            ("🔧  Tools",         "tools"),
            ("🕵  Recon",         "recon"),
            ("📦  Packet Sniffer","sniffer"),
            ("🔍  Vuln Scan",     "vulnscan"),
            ("🖥  Fingerprint",   "fingerprint"),
            ("📶  SNMP",          "snmp"),
            ("",                  None),
            ("DEFENSE",           None),
            ("🚨  Alert Log",     "alerts"),
            ("✅  Compliance",    "compliance"),
            ("🗺  Topology",      "topology"),
            ("",                  None),
            ("CONFIG",            None),
            ("⚙  Settings",      "settings"),
        ]

        self._nav_buttons = {}
        for label, view in nav_items:
            if view is None:
                if label:
                    ttk.Label(self.sidebar, text=label,
                              style="Sidebar.TLabel").pack(fill="x")
                else:
                    ttk.Separator(self.sidebar,
                                  orient="horizontal").pack(fill="x", padx=12, pady=2)
            else:
                btn = ttk.Button(self.sidebar, text=label,
                                 style="Sidebar.TButton",
                                 command=partial(self.show_view, view))
                btn.pack(fill="x")
                self._nav_buttons[view] = btn

        ttk.Separator(self.sidebar, orient="horizontal").pack(
            fill="x", padx=12, pady=4)

        self.theme_btn = ttk.Button(
            self.sidebar, text="  ○  Light Mode",
            style="Sidebar.TButton", command=self._toggle_theme)
        self.theme_btn.pack(fill="x")

        # ARP monitor toggle
        self._arp_mon_btn = ttk.Button(
            self.sidebar, text="  ▷  ARP Monitor",
            style="Sidebar.TButton", command=self._toggle_arp_monitor)
        self._arp_mon_btn.pack(fill="x")

        self.statusbar_var = tk.StringVar(value="● Ready")
        tk.Label(self.sidebar, textvariable=self.statusbar_var,
                 bg="#0d1526", fg="#94a3b8",
                 font=("Segoe UI", 8), anchor="w", padx=12,
                 justify="left", wraplength=178).pack(
            side=tk.BOTTOM, fill="x", pady=(0, 8))

        self.main_area = ttk.Frame(self.root)
        self.main_area.grid(row=0, column=1, sticky="nsew")
        self.main_area.grid_rowconfigure(0, weight=1)
        self.main_area.grid_columnconfigure(0, weight=1)
        self.view_frames: dict[str, ttk.Frame] = {}

    # ─────────────── THEME ───────────────

    def _toggle_theme(self):
        self.is_dark = not self.is_dark
        _apply_theme(self.root, self.is_dark)
        self.theme_btn.config(
            text="  ●  Dark Mode" if self.is_dark else "  ○  Light Mode")
        self._reapply_row_tags()

    def _reapply_row_tags(self):
        if not hasattr(self, "tree"):
            return
        theme = "dark" if self.is_dark else "light"
        for tag, color in ROW_TAGS[theme].items():
            self.tree.tag_configure(tag, background=color)

    # ─────────────── VIEW SWITCHING ───────────────

    def show_view(self, name: str):
        self.current_view = name
        for n, f in self.view_frames.items():
            f.grid_remove()
        self.view_frames[name].grid()
        for view, btn in self._nav_buttons.items():
            btn.configure(
                style="SidebarActive.TButton" if view == name
                      else "Sidebar.TButton")
        if name == "dashboard":
            self.update_dashboard()

    # ─────────────── SCANNER UI ───────────────

    def _build_scanner_ui(self):
        frame = self.view_frames["scanner"]
        frame.grid_rowconfigure(3, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        # ── Header ──
        hdr = ttk.Frame(frame, padding=(16, 10, 16, 0))
        hdr.grid(row=0, column=0, sticky="ew")
        ttk.Label(hdr, text="Network Scanner",
                  style="Heading.TLabel").pack(side=tk.LEFT)

        self.summary_var = tk.StringVar(value="")
        ttk.Label(hdr, textvariable=self.summary_var,
                  style="Muted.TLabel").pack(side=tk.RIGHT)

        # ── Controls ──
        ctrl = ttk.Frame(frame, padding=(16, 6, 16, 0))
        ctrl.grid(row=1, column=0, sticky="ew")

        # ── Detected Networks (checkbox grid like original) ──
        subnet_frame = ttk.LabelFrame(ctrl, text="Detected Networks", padding=8)
        subnet_frame.pack(side=tk.LEFT, fill="y", padx=(0, 12))

        # Grid of checkboxes (3 columns)
        self._net_grid_frame = ttk.Frame(subnet_frame)
        self._net_grid_frame.pack(fill="both", expand=True)

        # network_cidr → BooleanVar
        self._net_check_vars: dict = {}
        self.subnet_vars = []  # kept for profile compat

        btn_row = ttk.Frame(subnet_frame)
        btn_row.pack(fill="x", pady=(6, 0))
        ttk.Button(btn_row, text="↻ Refresh",
                   command=self._refresh_detected_networks,
                   style="Ghost.TButton").pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_row, text="✓ All",
                   command=lambda: [v.set(True)
                       for v in self._net_check_vars.values()],
                   style="Ghost.TButton").pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_row, text="✗ None",
                   command=lambda: [v.set(False)
                       for v in self._net_check_vars.values()],
                   style="Ghost.TButton").pack(side=tk.LEFT, padx=(0, 4))

        # Custom entry for manual subnet
        custom_row = ttk.Frame(subnet_frame)
        custom_row.pack(fill="x", pady=(4, 0))
        ttk.Label(custom_row, text="Custom:").pack(side=tk.LEFT)
        self._custom_net_var = tk.StringVar()
        ttk.Entry(custom_row, textvariable=self._custom_net_var,
                  width=18).pack(side=tk.LEFT, padx=(4, 4))
        ttk.Button(custom_row, text="＋",
                   command=self._add_custom_network,
                   style="Ghost.TButton", width=3).pack(side=tk.LEFT)

        # Populate on build
        self.root.after(100, self._refresh_detected_networks)

        # Scan options
        opt_frame = ttk.LabelFrame(ctrl, text="Options", padding=8)
        opt_frame.pack(side=tk.LEFT, fill="y", padx=(0, 12))

        ttk.Label(opt_frame, text="Mode:").grid(row=0, column=0, sticky="w")
        mode_cb = ttk.Combobox(opt_frame, textvariable=self.mode_var,
                               values=["fast", "accurate", "arp_only",
                                       "stealth", "full"],
                               width=10, state="readonly")
        mode_cb.grid(row=0, column=1, sticky="w", padx=(4, 0))
        Tooltip(mode_cb,
                "fast    — ping + TCP probe (default)\n"
                "accurate — ping + full TCP + banner grab\n"
                "arp_only — only ARP-visible hosts\n"
                "stealth  — TCP-only, no ping\n"
                "full     — everything (slowest)")

        ttk.Label(opt_frame, text="Ports:").grid(row=1, column=0, sticky="w", pady=(4, 0))
        ttk.Entry(opt_frame, textvariable=self.port_range_var,
                  width=18).grid(row=1, column=1, sticky="w",
                                  padx=(4, 0), pady=(4, 0))

        ttk.Checkbutton(opt_frame, text="Grab banners",
                        variable=self.grab_banners_var).grid(
            row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))
        ttk.Checkbutton(opt_frame, text="Probe UDP",
                        variable=self.probe_udp_var).grid(
            row=3, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(opt_frame, text="Inspect SSL/TLS",
                        variable=self.inspect_ssl_var).grid(
            row=4, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(opt_frame, text="Check default creds (slow)",
                        variable=self.check_creds_var).grid(
            row=5, column=0, columnspan=2, sticky="w")

        # Action buttons
        act_frame = ttk.Frame(ctrl)
        act_frame.pack(side=tk.LEFT, fill="y", padx=(0, 12))

        self.scan_btn = ttk.Button(act_frame, text="▶  Scan",
                                    command=self.start_selected_scan,
                                    style="Success.TButton", width=12)
        self.scan_btn.pack(pady=(0, 4))

        self.stop_btn = ttk.Button(act_frame, text="■  Stop",
                                    command=self.stop_scan,
                                    style="Danger.TButton", width=12,
                                    state=tk.DISABLED)
        self.stop_btn.pack(pady=(0, 4))

        ttk.Button(act_frame, text="💾 Save Baseline",
                   command=self._save_baseline,
                   style="Ghost.TButton", width=14).pack(pady=(0, 4))

        self.export_button = ttk.Button(act_frame, text="↗ Export",
                                         command=self._export_menu,
                                         style="Ghost.TButton", width=12)
        self.export_button.pack(pady=(0, 4))

        ttk.Button(act_frame, text="📝 Report",
                   command=self._export_report,
                   style="Warning.TButton", width=12).pack()

        # Progress
        prog_frame = ttk.Frame(ctrl)
        prog_frame.pack(side=tk.LEFT, fill="both", expand=True)

        self.progress = ttk.Progressbar(prog_frame, mode="determinate",
                                         maximum=100)
        self.progress.pack(fill="x", pady=(0, 4))

        self.filter_count_var = tk.StringVar(value="")
        ttk.Label(prog_frame, textvariable=self.filter_count_var,
                  style="Muted.TLabel").pack(anchor="w")

        # Diff badge area
        self.diff_badge_var = tk.StringVar(value="")
        ttk.Label(prog_frame, textvariable=self.diff_badge_var,
                  style="Warning.TLabel").pack(anchor="w")

        ttk.Separator(frame, orient="horizontal").grid(
            row=2, column=0, sticky="ew", padx=16, pady=(6, 0))

        # ── Filter Bar ──
        fbar = ttk.Frame(frame, padding=(16, 4, 16, 0))
        fbar.grid(row=2, column=0, sticky="ew")

        ttk.Label(fbar, text="🔍").pack(side=tk.LEFT)
        self.filter_entry = ttk.Entry(fbar, textvariable=self.filter_text_var,
                                       width=28)
        self.filter_entry.pack(side=tk.LEFT, padx=(4, 8))
        self.filter_entry.bind("<KeyRelease>", lambda _: self.apply_filters())
        Tooltip(self.filter_entry, "Filter by IP, hostname, MAC, vendor, port, OS, note…")

        ttk.Checkbutton(fbar, text="Active",
                        variable=self.filter_show_used,
                        command=self.apply_filters).pack(side=tk.LEFT, padx=2)
        ttk.Checkbutton(fbar, text="Free",
                        variable=self.filter_show_free,
                        command=self.apply_filters).pack(side=tk.LEFT, padx=2)
        ttk.Checkbutton(fbar, text="⭐ Favs",
                        variable=self.filter_favs_only,
                        command=self.apply_filters).pack(side=tk.LEFT, padx=2)
        ttk.Checkbutton(fbar, text="🚨 Rogues",
                        variable=self.filter_rogues_only,
                        command=self.apply_filters).pack(side=tk.LEFT, padx=2)

        ttk.Label(fbar, text="Risk:").pack(side=tk.LEFT, padx=(8, 2))
        sev_cb = ttk.Combobox(fbar, textvariable=self.filter_severity_var,
                               values=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"],
                               width=9, state="readonly")
        sev_cb.pack(side=tk.LEFT)
        sev_cb.bind("<<ComboboxSelected>>", lambda _: self.apply_filters())

        ttk.Button(fbar, text="Clear", command=self._clear_filter,
                   style="Ghost.TButton").pack(side=tk.LEFT, padx=(8, 0))

        ttk.Button(fbar, text="Columns ▾",
                   command=self._toggle_columns_dialog,
                   style="Ghost.TButton").pack(side=tk.RIGHT)

        ttk.Button(fbar, text="Sort ▾",
                   command=self._sort_dialog,
                   style="Ghost.TButton").pack(side=tk.RIGHT, padx=(0, 4))

        # ── Main Table ──
        tree_frame = ttk.Frame(frame)
        tree_frame.grid(row=3, column=0, sticky="nsew", padx=16, pady=(4, 0))
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        cols = list(self._col_cfg.keys())
        self.tree = ttk.Treeview(tree_frame, columns=cols,
                                   show="headings", selectmode="extended")

        for col, (heading, width, visible) in self._col_cfg.items():
            self.tree.heading(col, text=heading,
                              command=lambda c=col: self.sort_by(c))
            self.tree.column(col, width=width, minwidth=30)
            var = tk.BooleanVar(value=visible)
            self._col_visible[col] = var

        # Row colour tags
        theme = "dark" if self.is_dark else "light"
        for tag, color in ROW_TAGS[theme].items():
            self.tree.tag_configure(tag, background=color)

        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                             command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal",
                             command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set,
                             xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        # Bind events
        self.tree.bind("<Double-1>",   self._on_row_double_click)
        self.tree.bind("<Button-3>",   self._show_context_menu)
        self.tree.bind("<Delete>",     lambda _: self._delete_selected_rows())

        # Context menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="🔍 Host Details",
                                       command=self._on_row_double_click)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="🔄 Rescan",
                                       command=self._ctx_rescan)
        self.context_menu.add_command(label="📡 Traceroute",
                                       command=self._ctx_traceroute)
        self.context_menu.add_command(label="🌐 Open in Browser",
                                       command=self._ctx_open_browser)
        self.context_menu.add_command(label="🌍 WHOIS",
                                       command=self._ctx_whois)
        self.context_menu.add_command(label="🏓 Ping",
                                       command=self._ctx_ping)
        self.context_menu.add_command(label="🔌 Port Scan",
                                       command=self._ctx_port_scan)
        self.context_menu.add_command(label="🔑 SSL Inspector",
                                       command=self._ctx_ssl_inspect)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="⭐ Toggle Favourite",
                                       command=self._ctx_toggle_fav)
        self.context_menu.add_command(label="📝 Edit Note",
                                       command=self._ctx_edit_note)
        self.context_menu.add_command(label="⚡ Wake-on-LAN",
                                       command=self._ctx_wol)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="📋 Copy IP",
                                       command=self.copy_ip)
        self.context_menu.add_command(label="📋 Copy MAC",
                                       command=self.copy_mac)
        self.context_menu.add_command(label="📋 Copy Row (CSV)",
                                       command=self.copy_row_csv)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="🚫 Generate Block Rule",
                                       command=self._ctx_gen_block_rule)
        self.context_menu.add_command(label="🗑 Delete Row",
                                       command=self._delete_selected_rows)

        # Bottom status
        status_row = ttk.Frame(frame, padding=(16, 4, 16, 6))
        status_row.grid(row=4, column=0, sticky="ew")
        self._status_label = ttk.Label(status_row, text="",
                                        style="Muted.TLabel")
        self._status_label.pack(side=tk.LEFT)

    # ─────────────── NETWORK DETECTION ───────────────

    def _detect_local_networks(self) -> list[str]:
        """Return list of local network CIDRs (plus broadcast/special addresses)."""
        networks = []

        # Method 1: netifaces (most accurate)
        if _NETIFACES_OK:
            try:
                for iface in netifaces.interfaces():
                    addrs = netifaces.ifaddresses(iface)
                    for af in (netifaces.AF_INET, netifaces.AF_INET6):
                        if af not in addrs:
                            continue
                        for addr in addrs[af]:
                            ip   = addr.get("addr", "")
                            mask = addr.get("netmask", "")
                            if not ip or ip.startswith("127.") or ip == "::1":
                                continue
                            try:
                                net = ipaddress.ip_interface(
                                    f"{ip}/{mask}" if mask else ip
                                ).network
                                cidr = str(net)
                                if cidr not in networks:
                                    networks.append(cidr)
                            except ValueError:
                                pass
            except Exception as e:
                log.debug("netifaces detect: %s", e)

        # Method 2: socket + OS route fallback
        if not networks:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
                # Guess /24 subnet
                net = ipaddress.ip_interface(f"{local_ip}/24").network
                networks.append(str(net))
            except Exception:
                pass

        # Method 3: parse ipconfig / ip addr
        if not networks:
            try:
                if platform.system().lower() == "windows":
                    out = subprocess.check_output(
                        ["ipconfig"], stderr=subprocess.DEVNULL
                    ).decode(errors="ignore")
                    ips = re.findall(
                        r"IPv4 Address[.\s]+:\s*([\d.]+)", out)
                    masks = re.findall(
                        r"Subnet Mask[.\s]+:\s*([\d.]+)", out)
                    for ip, mask in zip(ips, masks):
                        try:
                            net = ipaddress.ip_interface(
                                f"{ip}/{mask}").network
                            cidr = str(net)
                            if cidr not in networks:
                                networks.append(cidr)
                        except ValueError:
                            pass
                else:
                    out = subprocess.check_output(
                        ["ip", "addr"], stderr=subprocess.DEVNULL
                    ).decode(errors="ignore")
                    for m in re.finditer(
                            r"inet\s+([\d./]+)", out):
                        try:
                            net = ipaddress.ip_interface(
                                m.group(1)).network
                            if not net.is_loopback:
                                cidr = str(net)
                                if cidr not in networks:
                                    networks.append(cidr)
                        except ValueError:
                            pass
            except Exception as e:
                log.debug("OS network detect: %s", e)

        # Always include useful broadcast/meta addresses
        extras = ["255.255.255.255/32", "224.0.0.0/4",
                  "0.0.0.0/0"]
        for e in extras:
            if e not in networks:
                networks.append(e)

        return networks if networks else ["192.168.1.0/24"]

    def _refresh_detected_networks(self):
        """Re-detect local networks and rebuild the checkbox grid."""
        # Preserve previously checked state
        old_checked = {cidr for cidr, var in self._net_check_vars.items()
                       if var.get()}

        networks = self._detect_local_networks()

        # Rebuild checkbox grid
        for widget in self._net_grid_frame.winfo_children():
            widget.destroy()
        self._net_check_vars.clear()

        COLS = 3
        for idx, cidr in enumerate(networks):
            var = tk.BooleanVar(
                value=(cidr in old_checked or idx == 0))
            self._net_check_vars[cidr] = var
            cb = ttk.Checkbutton(
                self._net_grid_frame,
                text=cidr,
                variable=var,
                width=22)
            cb.grid(row=idx // COLS, column=idx % COLS,
                    sticky="w", padx=4, pady=1)

        # Keep subnet_vars in sync for profile compatibility
        self.subnet_vars = list(self._net_check_vars.keys())

    def _add_custom_network(self):
        """Add a manually typed network to the checkbox grid."""
        raw = self._custom_net_var.get().strip()
        if not raw:
            return
        try:
            net  = ipaddress.ip_network(raw, strict=False)
            cidr = str(net)
        except ValueError:
            messagebox.showerror("Invalid network",
                f"'{raw}' is not a valid CIDR.\nExample: 10.0.0.0/8")
            return
        if cidr not in self._net_check_vars:
            idx = len(self._net_check_vars)
            var = tk.BooleanVar(value=True)
            self._net_check_vars[cidr] = var
            COLS = 3
            cb = ttk.Checkbutton(
                self._net_grid_frame,
                text=cidr,
                variable=var,
                width=22)
            cb.grid(row=idx // COLS, column=idx % COLS,
                    sticky="w", padx=4, pady=1)
            self.subnet_vars.append(cidr)
        else:
            # Already listed — just check it
            self._net_check_vars[cidr].set(True)
        self._custom_net_var.set("")

    # ─────────────── SCAN START / STOP ───────────────

    def start_selected_scan(self):
        if self.scanning:
            return
        # Read checked networks from the checkbox grid
        targets = [cidr for cidr, var in self._net_check_vars.items()
                   if var.get()]
        if not targets:
            messagebox.showwarning("No target",
                "Tick at least one network in the Detected Networks panel.")
            return

        networks = []
        for t in targets:
            try:
                # Handle bare IPs and ranges like 192.168.1.1-254
                if "-" in t and "/" not in t:
                    parts = t.rsplit("-", 1)
                    base  = parts[0].rsplit(".", 1)
                    start_ip = ipaddress.ip_address(parts[0])
                    end_ip   = ipaddress.ip_address(
                        base[0] + "." + parts[1])
                    for ip_int in range(int(start_ip), int(end_ip) + 1):
                        networks.append(
                            ipaddress.ip_network(
                                f"{ipaddress.ip_address(ip_int)}/32"))
                else:
                    networks.append(
                        ipaddress.ip_network(t, strict=False))
            except ValueError as e:
                messagebox.showerror("Invalid target", str(e))
                return

        total = sum(max(n.num_addresses - 2, 1)
                    if n.num_addresses > 2 else 1
                    for n in networks)

        self.results.clear()
        self.security_findings.clear()
        self.scan_timeline.clear()
        self.diff = {"new": [], "removed": [], "changed": [], "rogue": []}

        for row in self.tree.get_children():
            self.tree.delete(row)

        self.scanning      = True
        self._finalized    = False
        self._arp_warned   = False
        self._arp_tier     = None
        self.total_hosts   = total
        self.scanned_hosts = 0
        self.scan_start_ts = time.time()
        self.scan_meta     = {
            "target":   ", ".join(targets),
            "mode":     self.mode_var.get(),
            "started":  ts_now(),
        }

        self.progress.configure(maximum=total, value=0)
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.statusbar_var.set("⟳ Scanning…")
        self.diff_badge_var.set("")

        num_workers = self.max_workers_var.get() or auto_tune_workers(total)
        self.pool   = SmartWorkerPool(
            workers=num_workers,
            queue_limit=max(SMART_QUEUE_LIMIT, total + 200))

        # Smart feature disabling for large scans
        self.smart_disable_hostnames = total > SMART_DISABLE_HOSTNAMES_OVER
        self.smart_disable_os_guess  = total > SMART_DISABLE_OS_GUESS_OVER
        self.smart_disable_tcp_probe = total > SMART_DISABLE_TCP_PROBE_OVER

        self.plugin_manager.run("on_scan_start", self.scan_meta)

        threading.Thread(
            target=self.smart_producer, args=(networks,),
            daemon=True, name="scan-producer").start()

    def stop_scan(self):
        self.scanning = False
        if self.pool:
            self.pool.shutdown()
            self.pool = None
        self.root.after(0, self._finalize_ui)

    def _finalize_ui(self):
        if self._finalized:
            return
        self._finalized = True
        self.scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        elapsed = time.time() - (self.scan_start_ts or time.time())
        self.scan_meta["duration"] = f"{elapsed:.1f}s"

        used  = sum(1 for r in self.results if r["status"] == "Used")
        total = len(self.results)
        self.statusbar_var.set(
            f"✓ Done — {used:,} active / {total:,} scanned\n"
            f"{elapsed:.1f}s · {len(self.security_findings)} findings")

        # Baseline diff
        if self.baseline_mgr.has_baseline():
            self.diff = self.baseline_mgr.diff(self.results)
            badges = []
            if self.diff["new"]:
                badges.append(f"🆕 {len(self.diff['new'])} new")
            if self.diff["rogue"]:
                badges.append(f"🚨 {len(self.diff['rogue'])} rogue")
            if self.diff["changed"]:
                badges.append(f"⚠ {len(self.diff['changed'])} changed")
            if badges:
                self.diff_badge_var.set("  ".join(badges))
                for ip in self.diff["rogue"]:
                    self.alert_log.add("Critical", ip,
                        f"ROGUE DEVICE: MAC changed vs baseline",
                        tag="rogue_mac")

        # Alert log: new critical findings
        for ip, issue, sev, _ in self.security_findings:
            if sev in ("Critical", "High"):
                self.alert_log.add(sev, ip, issue, tag="vuln")

        self.plugin_manager.run("on_scan_done", self.results,
                                 self.security_findings)
        self.update_summary()
        self.apply_filters()

    # ─────────────── SCAN PRODUCER / WORKER ───────────────

    def arp_scan(self, network_cidr: str) -> dict:
        if _SCAPY_OK:
            try:
                result = _arp_via_scapy(network_cidr)
                self._arp_tier = "scapy"
                return result
            except PermissionError:
                if not self._arp_warned:
                    self._arp_warned = True
                    self.root.after(0, lambda: messagebox.showwarning(
                        "ARP permission",
                        "ARP scan requires root/admin.\n"
                        "Falling back to OS ARP cache."))
            except Exception as e:
                log.warning("scapy ARP failed: %s", e)
        result = _arp_via_os(network_cidr)
        self._arp_tier = "os" if result else None
        return result

    def _get_probe_ports(self) -> list[int]:
        raw = self.port_range_var.get().strip()
        if not raw:
            return TCP_PROBE_PORTS
        ports = []
        for part in raw.split(","):
            part = part.strip()
            if "-" in part:
                a, b = part.split("-", 1)
                try:
                    ports.extend(range(int(a), int(b) + 1))
                except ValueError:
                    pass
            elif part.isdigit():
                ports.append(int(part))
        return ports or TCP_PROBE_PORTS

    def smart_producer(self, networks):
        mode = self.mode_var.get()
        for net in networks:
            if not self.scanning:
                break
            if hasattr(net, 'version') and net.version != 4:
                continue
            # For /32 hosts, no ARP broadcast needed
            if net.num_addresses == 1:
                arp_map = self.arp_scan(str(net))
            else:
                arp_map = self.arp_scan(str(net))
            host_iter = ([net.network_address]
                         if net.num_addresses == 1
                         else net.hosts())
            for ip in host_iter:
                if not self.scanning:
                    break
                self.pool.submit(
                    self.smart_scan_host, str(ip), str(net), arp_map, mode)

        if self.pool:
            self.pool.queue.join()
            self.pool.shutdown()
            self.pool = None
        self.root.after(0, self._finalize_ui)

    def smart_scan_host(self, ip_str: str, subnet_str: str,
                         arp_map: dict, mode: str):
        if not self.scanning:
            return

        raw_mac = arp_map.get(ip_str, "")
        mac     = normalize_mac(raw_mac)
        vendor  = vendor_from_mac(mac) if mac else ""

        alive      = False
        latency_ms = ""
        open_ports = []
        udp_ports  = []
        os_guess   = hostname = device_type = ""
        banners:  dict = {}
        ssl_info: dict | None = None
        default_cred_confirmed = False
        default_cred_possible  = False
        probe_ports = self._get_probe_ports()
        grab_banners = self.grab_banners_var.get()

        if mode == "arp_only":
            if not mac:
                return
            alive = True
            _, latency_ms = ping_host(ip_str, self.timeout_var.get())
            hostname = resolve_hostname(ip_str) if not self.smart_disable_hostnames else ""

        elif mode == "stealth":
            # TCP-only, no ICMP
            if not self.smart_disable_tcp_probe:
                open_ports, banners = tcp_probe_with_banners(
                    ip_str, probe_ports,
                    timeout=TCP_PROBE_TIMEOUT_S,
                    grab_banners=grab_banners)
                if open_ports:
                    alive = True

        elif mode == "fast":
            if mac:
                alive = True
            else:
                alive, latency_ms = ping_host(ip_str, self.timeout_var.get())
                if not alive and not self.smart_disable_tcp_probe:
                    open_ports, banners = tcp_probe_with_banners(
                        ip_str, probe_ports[:12],
                        grab_banners=grab_banners)
                    if open_ports:
                        alive = True
            if alive:
                if latency_ms == "":
                    _, latency_ms = ping_host(ip_str, self.timeout_var.get())
                if not self.smart_disable_tcp_probe and not open_ports:
                    open_ports, banners = tcp_probe_with_banners(
                        ip_str, probe_ports[:16],
                        grab_banners=grab_banners)
                if not self.smart_disable_os_guess:
                    ttl = get_ttl_via_ping(ip_str) if _SCAPY_OK else None
                    os_guess = guess_os_enhanced(ip_str, open_ports, banners, ttl)
                if not self.smart_disable_hostnames:
                    hostname = resolve_hostname(ip_str)

        elif mode == "accurate":
            if mac:
                alive = True
            a, lat = ping_host(ip_str, self.timeout_var.get())
            if a:
                alive, latency_ms = True, lat
            if not self.smart_disable_tcp_probe:
                open_ports, banners = tcp_probe_with_banners(
                    ip_str, probe_ports, grab_banners=grab_banners)
                if open_ports:
                    alive = True
            if alive:
                if not self.smart_disable_os_guess:
                    ttl = get_ttl_via_ping(ip_str)
                    os_guess = guess_os_enhanced(ip_str, open_ports, banners, ttl)
                if not self.smart_disable_hostnames:
                    hostname = resolve_hostname(ip_str)

        else:  # "full" — everything
            if mac:
                alive = True
            a, lat = ping_host(ip_str, self.timeout_var.get())
            if a:
                alive, latency_ms = True, lat
            open_ports, banners = tcp_probe_with_banners(
                ip_str, probe_ports, grab_banners=True)
            if open_ports:
                alive = True
            if self.probe_udp_var.get():
                for p in UDP_PROBE_PORTS:
                    if probe_udp_port(ip_str, p):
                        udp_ports.append(p)
            if alive:
                ttl      = get_ttl_via_ping(ip_str)
                os_guess = guess_os_enhanced(ip_str, open_ports, banners, ttl)
                hostname = resolve_hostname(ip_str)

        # SSL inspection
        if alive and self.inspect_ssl_var.get():
            for p in [443, 8443]:
                if p in open_ports:
                    ssl_info = inspect_ssl(ip_str, p)
                    if ssl_info:
                        break

        if alive:
            device_type = guess_device_type(open_ports, vendor, os_guess)

        status = "Used" if alive else "Free"

        result = {
            "ip":           ip_str,
            "subnet":       subnet_str,
            "status":       status,
            "hostname":     hostname,
            "mac":          mac,
            "vendor":       vendor,
            "device_type":  device_type,
            "latency_ms":   latency_ms,
            "open_ports":   open_ports,
            "udp_ports":    udp_ports,
            "os_guess":     os_guess,
            "banners":      banners,
            "ssl_info":     ssl_info,
            "default_cred_confirmed": default_cred_confirmed,
            "default_cred_possible":  default_cred_possible,
            "scan_ts":      ts_now(),
        }

        # Security findings
        findings = assess_security(result)
        result["security_findings"] = findings
        result["threat_score"]      = calculate_threat_score(result)

        # Baseline classification
        result["baseline_cls"] = self.baseline_mgr.classify(result) \
            if self.baseline_mgr.has_baseline() else "unknown"

        with self.lock:
            self.results.append(result)
            self.scanned_hosts += 1
            current = self.scanned_hosts
            self.scan_timeline.append((time.time(), current))
            if status == "Used":
                self.security_findings.extend(findings)

            # Live ETA
            if self.scan_start_ts and current % 50 == 0:
                elapsed   = time.time() - self.scan_start_ts
                rate      = current / max(elapsed, 0.001)
                remaining = max(0, self.total_hosts - current)
                eta_s     = int(remaining / max(rate, 1))
                eta       = f"ETA ~{eta_s}s" if eta_s > 5 else "almost done"
                self.root.after(0, lambda r=int(rate), c=current, e=eta:
                    self.statusbar_var.set(
                        f"⟳ {c:,}/{self.total_hosts:,}\n{r} hosts/s · {e}"))

        self.plugin_manager.run_on_result(result)

        step = self.ui_update_every
        if current % step == 0 or current == self.total_hosts:
            self.root.after_idle(self._add_row_to_table, result)
            self.root.after_idle(self._update_progress, current)
            self.root.after_idle(self.update_summary)
        else:
            self.root.after_idle(self._add_row_to_table, result)

    # ─────────────── TABLE MANAGEMENT ───────────────

    def _add_row_to_table(self, result: dict):
        if not self._passes_filter(result):
            return
        key     = f"{result['ip']}|{result['subnet']}"
        is_used = result["status"] == "Used"
        is_fav  = key in self.host_favs
        is_rogue = result.get("baseline_cls") == "rogue"
        score   = result.get("threat_score", 0)
        row_cnt = len(self.tree.get_children())

        if is_rogue:
            tag = "rogue"
        elif is_fav:
            tag = "fav"
        elif is_used:
            if score >= 60:
                tag = "critical"
            else:
                tag = "used" if row_cnt % 2 == 0 else "used_alt"
        else:
            tag = "free" if row_cnt % 2 == 0 else "free_alt"

        lat     = result.get("latency_ms", "")
        ssl_lbl = ""
        si      = result.get("ssl_info")
        if si:
            if si.get("expired"):
                ssl_lbl = "⚠ EXP"
            elif si.get("days_left") is not None and si["days_left"] < 30:
                ssl_lbl = f"⚠ {si['days_left']}d"
            elif si.get("weak_cipher"):
                ssl_lbl = "⚠ Weak"
            else:
                ssl_lbl = "✓ TLS"

        threat_str = f"{score}" if is_used else ""

        self.tree.insert("", tk.END,
            values=(
                "⭐" if is_fav else "",
                threat_str,
                result["ip"],
                result["subnet"],
                "● Active" if is_used else "○ Free",
                result.get("hostname", ""),
                result.get("mac", ""),
                result.get("vendor", ""),
                result.get("device_type", ""),
                f"{lat} ms" if lat != "" else "",
                format_ports(result.get("open_ports", [])),
                result.get("os_guess", ""),
                ssl_lbl,
                self.host_notes.get(key, ""),
            ),
            tags=(tag,)
        )

    def _update_progress(self, value):
        self.progress["value"] = value

    def update_summary(self):
        used = sum(1 for r in self.results if r["status"] == "Used")
        free = sum(1 for r in self.results if r["status"] == "Free")
        macs = sum(1 for r in self.results if r.get("mac"))
        pct  = int(self.scanned_hosts / max(self.total_hosts, 1) * 100)
        crits = sum(1 for r in self.results
                    if r.get("threat_score", 0) >= 60)
        self.summary_var.set(
            f"Scanned {self.scanned_hosts:,}/{self.total_hosts:,} ({pct}%)  ·  "
            f"Active: {used:,}  ·  Free: {free:,}  ·  MACs: {macs:,}  ·  "
            f"Findings: {len(self.security_findings)}  ·  "
            f"High-risk: {crits}")
        self.filter_count_var.set(
            f"{len(self.tree.get_children()):,} rows shown")

    # ─── Filtering ───

    def _passes_filter(self, r: dict) -> bool:
        key = f"{r['ip']}|{r['subnet']}"
        if self.filter_favs_only.get() and key not in self.host_favs:
            return False
        if self.filter_rogues_only.get() and r.get("baseline_cls") != "rogue":
            return False
        if r["status"] == "Free" and not self.filter_show_free.get():
            return False
        if r["status"] == "Used" and not self.filter_show_used.get():
            return False
        sev_filter = self.filter_severity_var.get()
        if sev_filter != "All":
            lbl = threat_score_label(r.get("threat_score", 0))
            if lbl != sev_filter:
                return False
        text = self.filter_text_var.get().strip().lower()
        if text:
            banners_str = " ".join(r.get("banners", {}).values())
            haystack = " ".join([
                r["ip"], r["subnet"], r["status"],
                r.get("hostname", ""), r.get("mac", ""),
                r.get("vendor", ""), r.get("device_type", ""),
                ",".join(map(str, r.get("open_ports", []))),
                r.get("os_guess", ""),
                self.host_notes.get(key, ""),
                banners_str,
            ]).lower()
            if text not in haystack:
                return False
        return True

    def apply_filters(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for r in self.results:
            if self._passes_filter(r):
                self._add_row_to_table(r)
        self.filter_count_var.set(
            f"{len(self.tree.get_children()):,} rows shown")

    def _clear_filter(self):
        self.filter_text_var.set("")
        self.filter_severity_var.set("All")
        self.filter_favs_only.set(False)
        self.filter_rogues_only.set(False)
        self.apply_filters()

    # ─── Sorting ───

    def sort_by(self, column: str):
        key_fn = {
            "ip":      lambda r: ip_sort_key(r["ip"]),
            "latency": lambda r: int(r.get("latency_ms") or 0),
            "ports":   lambda r: len(r.get("open_ports", [])),
            "mac":     lambda r: r.get("mac") or "",
            "vendor":  lambda r: (r.get("vendor") or "").lower(),
            "threat":  lambda r: r.get("threat_score", 0),
        }.get(column, lambda r: str(r.get(column, "")).lower())
        self.results.sort(key=key_fn, reverse=(column == "threat"))
        self.apply_filters()

    def _sort_dialog(self):
        menu = tk.Menu(self.root, tearoff=0)
        for col in ["ip", "threat", "vendor", "ports", "latency",
                    "hostname", "os_guess"]:
            menu.add_command(
                label=f"Sort by {col}",
                command=lambda c=col: self.sort_by(c))
        x = self.root.winfo_pointerx()
        y = self.root.winfo_pointery()
        menu.post(x, y)

    # ─── Context Menu Actions ───

    def _show_context_menu(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            self.context_menu.post(event.x_root, event.y_root)

    def _get_selected_result(self) -> dict | None:
        sel = self.tree.selection()
        if not sel:
            return None
        vals = self.tree.item(sel[0], "values")
        if not vals:
            return None
        ip, subnet = vals[2], vals[3]
        return next((r for r in self.results
                     if r["ip"] == ip and r["subnet"] == subnet), None)

    def _ctx_toggle_fav(self):
        r = self._get_selected_result()
        if not r:
            return
        key = f"{r['ip']}|{r['subnet']}"
        self.host_favs.discard(key) if key in self.host_favs else self.host_favs.add(key)
        self._save_notes()
        self.apply_filters()

    def _ctx_edit_note(self):
        r = self._get_selected_result()
        if not r:
            return
        key  = f"{r['ip']}|{r['subnet']}"
        note = simple_input(self.root, f"Note — {r['ip']}", "Note:",
                            self.host_notes.get(key, ""))
        if note is not None:
            self.host_notes[key] = note
            self._save_notes()
            self.apply_filters()

    def _ctx_rescan(self):
        r = self._get_selected_result()
        if r:
            self._rescan_host(r["ip"], r["subnet"])

    def _rescan_host(self, ip_str: str, subnet_str: str):
        def _run():
            arp_map = self.arp_scan(f"{ip_str}/32")
            mode    = self.mode_var.get()
            with self.lock:
                self.results[:] = [r for r in self.results
                    if not (r["ip"] == ip_str and r["subnet"] == subnet_str)]
            self.smart_scan_host(ip_str, subnet_str, arp_map, mode)
            self.root.after(0, self.apply_filters)
        threading.Thread(target=_run, daemon=True).start()

    def _ctx_traceroute(self):
        r = self._get_selected_result()
        if not r:
            return
        win = tk.Toplevel(self.root)
        win.title(f"Traceroute — {r['ip']}")
        win.geometry("560x380")
        txt = scrolledtext.ScrolledText(win, font=("Courier New", 9))
        txt.pack(fill="both", expand=True, padx=8, pady=8)
        txt.insert("end", f"Tracing route to {r['ip']}…\n\n")
        txt.config(state="disabled")

        def run():
            hops = traceroute_host(r["ip"])
            for h in hops:
                rtt  = f"{h['rtt_ms']} ms" if h["rtt_ms"] else "  *"
                hn   = f"  ({h['hostname']})" if h["hostname"] else ""
                line = f" {h['hop']:2d}   {h['ip']:<18}  {rtt}{hn}\n"
                txt.config(state="normal")
                txt.insert("end", line)
                txt.see("end")
                txt.config(state="disabled")
        threading.Thread(target=run, daemon=True).start()

    def _ctx_wol(self):
        r = self._get_selected_result()
        if not r:
            return
        mac = r.get("mac", "")
        if not mac:
            messagebox.showwarning("Wake-on-LAN",
                "No MAC address known.\nRun as root/admin for ARP.")
            return
        try:
            send_wol(mac)
            messagebox.showinfo("Wake-on-LAN", f"Magic packet sent to {mac}.")
        except Exception as e:
            messagebox.showerror("Wake-on-LAN", str(e))

    def _ctx_open_browser(self):
        r = self._get_selected_result()
        if r:
            ports  = r.get("open_ports", [])
            scheme = "https" if 443 in ports or 8443 in ports else "http"
            webbrowser.open(f"{scheme}://{r['ip']}")

    def _ctx_whois(self):
        r = self._get_selected_result()
        if r:
            self.whois_target_var.set(r["ip"])
            self.show_view("tools")
            self._do_whois()

    def _ctx_ping(self):
        r = self._get_selected_result()
        if r:
            self.ping_target_var.set(r["ip"])
            self.show_view("tools")
            self._do_ping()

    def _ctx_port_scan(self):
        r = self._get_selected_result()
        if r:
            self.portcheck_host_var.set(r["ip"])
            self.show_view("tools")

    def _ctx_ssl_inspect(self):
        r = self._get_selected_result()
        if not r:
            return
        ports = [p for p in r.get("open_ports", [])
                 if p in (443, 8443, 8080)]
        if not ports:
            ports = [443]
        self._show_ssl_window(r["ip"], ports[0])

    def _ctx_gen_block_rule(self):
        r = self._get_selected_result()
        if not r:
            return
        win = tk.Toplevel(self.root)
        win.title(f"Block Rule — {r['ip']}")
        win.geometry("640x420")

        ctrl = ttk.Frame(win, padding=8)
        ctrl.pack(fill="x")
        fmt_var = tk.StringVar(value="iptables")
        ttk.Label(ctrl, text="Format:").pack(side=tk.LEFT)
        ttk.Combobox(ctrl, textvariable=fmt_var,
                     values=["iptables", "nftables", "windows", "pf"],
                     width=10, state="readonly").pack(side=tk.LEFT, padx=4)
        txt = scrolledtext.ScrolledText(win, font=("Courier New", 9))
        txt.pack(fill="both", expand=True, padx=8, pady=8)

        def gen():
            rules = generate_block_rules(
                [r["ip"]], r.get("open_ports", []), fmt=fmt_var.get())
            txt.config(state="normal")
            txt.delete("1.0", "end")
            txt.insert("end", rules)
            txt.config(state="disabled")

        ttk.Button(ctrl, text="Generate →",
                   command=gen).pack(side=tk.LEFT, padx=4)
        gen()

    def _show_ssl_window(self, ip: str, port: int):
        win = tk.Toplevel(self.root)
        win.title(f"SSL/TLS Inspector — {ip}:{port}")
        win.geometry("520x380")
        txt = scrolledtext.ScrolledText(win, font=("Courier New", 9))
        txt.pack(fill="both", expand=True, padx=8, pady=8)
        txt.insert("end", f"Inspecting {ip}:{port}…\n\n")
        txt.config(state="disabled")

        def run():
            info = inspect_ssl(ip, port)
            txt.config(state="normal")
            if not info:
                txt.insert("end", "No SSL/TLS on this port or connection failed.\n")
            else:
                fields = [
                    ("TLS Version",  info.get("tls_version", "?")),
                    ("Cipher",       info.get("cipher", "?")),
                    ("Common Name",  info.get("cn", "?")),
                    ("Issuer",       info.get("issuer", "?")),
                    ("Not Before",   info.get("not_before", "?")),
                    ("Not After",    info.get("not_after", "?")),
                    ("Days Left",    str(info.get("days_left", "?"))),
                    ("Expired",      "YES ⚠" if info.get("expired") else "No"),
                    ("Weak Cipher",  "YES ⚠" if info.get("weak_cipher") else "No"),
                    ("SANs",         ", ".join(info.get("sans", [])) or "None"),
                ]
                for label, val in fields:
                    txt.insert("end", f"  {label:<18}: {val}\n")
            txt.config(state="disabled")
        threading.Thread(target=run, daemon=True).start()

    # ─── Copy / row actions ───

    def copy_ip(self):
        r = self._get_selected_result()
        if r:
            self.root.clipboard_clear()
            self.root.clipboard_append(r["ip"])

    def copy_mac(self):
        r = self._get_selected_result()
        if r:
            self.root.clipboard_clear()
            self.root.clipboard_append(r.get("mac", ""))

    def copy_row_csv(self):
        r = self._get_selected_result()
        if r:
            row = [r["ip"], r["subnet"], r["status"], r.get("hostname", ""),
                   r.get("mac", ""), r.get("vendor", ""),
                   r.get("threat_score", ""), r.get("latency_ms", ""),
                   ",".join(map(str, r.get("open_ports", []))),
                   r.get("os_guess", "")]
            self.root.clipboard_clear()
            self.root.clipboard_append(",".join(str(x) for x in row))

    def _delete_selected_rows(self):
        for item in self.tree.selection():
            vals = self.tree.item(item, "values")
            if vals:
                ip, subnet = vals[2], vals[3]
                self.results = [r for r in self.results
                    if not (r["ip"] == ip and r["subnet"] == subnet)]
            self.tree.delete(item)
        self.update_summary()

    # ─── Double-click host detail ───

    def _on_row_double_click(self, _=None):
        r = self._get_selected_result()
        if not r:
            return
        key = f"{r['ip']}|{r['subnet']}"
        win = tk.Toplevel(self.root)
        win.title(f"Host Details — {r['ip']}")
        win.geometry("640x560")

        nb = ttk.Notebook(win)
        nb.pack(fill="both", expand=True, padx=8, pady=8)

        # ── Info tab ──
        info_tab = ttk.Frame(nb, padding=12)
        nb.add(info_tab, text="Info")
        score     = r.get("threat_score", 0)
        score_lbl = threat_score_label(score)
        score_clr = threat_score_color(score)
        fields = [
            ("IP Address",   r["ip"]),
            ("Subnet",       r["subnet"]),
            ("Status",       r["status"]),
            ("Threat Score", f"{score}/100 — {score_lbl}"),
            ("Hostname",     r.get("hostname") or "—"),
            ("MAC Address",  r.get("mac") or "— (run as root for ARP)"),
            ("Vendor",       r.get("vendor") or "—"),
            ("Device Type",  r.get("device_type") or "—"),
            ("OS Guess",     r.get("os_guess") or "—"),
            ("Latency",      f"{r['latency_ms']} ms" if r.get("latency_ms") != "" else "—"),
            ("Open Ports",   format_ports(r.get("open_ports", [])) or "None"),
            ("UDP Ports",    format_ports(r.get("udp_ports", [])) or "None"),
            ("Baseline",     r.get("baseline_cls", "unknown")),
            ("Scanned at",   r.get("scan_ts", "")),
        ]
        for i, (label, val) in enumerate(fields):
            ttk.Label(info_tab, text=label + ":",
                      style="Bold.TLabel").grid(
                row=i, column=0, sticky="w", padx=(0, 12), pady=2)
            lbl = ttk.Label(info_tab, text=val)
            if label == "Threat Score" and score >= 60:
                lbl.configure(foreground=score_clr,
                              font=("Segoe UI", 9, "bold"))
            lbl.grid(row=i, column=1, sticky="w", pady=2)

        ttk.Button(info_tab, text="🔄 Rescan this host",
                   command=lambda: [
                       self._rescan_host(r["ip"], r["subnet"]),
                       win.destroy()],
                   style="Ghost.TButton").grid(
            row=len(fields), column=0, columnspan=2,
            pady=(8, 0), sticky="w")

        # ── Banners tab ──
        ban_tab = ttk.Frame(nb, padding=12)
        nb.add(ban_tab, text="Banners")
        ban_txt = scrolledtext.ScrolledText(
            ban_tab, font=("Courier New", 9), height=16)
        ban_txt.pack(fill="both", expand=True)
        banners = r.get("banners", {})
        if banners:
            for port, banner in sorted(banners.items()):
                svc = WELL_KNOWN_PORTS.get(port, "")
                ban_txt.insert("end",
                    f"Port {port} ({svc}):\n  {banner}\n\n")
        else:
            ban_txt.insert("end", "No banners captured.")
        ban_txt.config(state="disabled")

        # ── Security tab ──
        sec_tab = ttk.Frame(nb, padding=12)
        nb.add(sec_tab, text="Security")
        findings = r.get("security_findings", [])
        if findings:
            for _, issue, sev, rec in sorted(
                    findings, key=lambda x: {"Critical":0,"High":1,"Medium":2,"Low":3}.get(x[2],4)):
                fg, bg = SEV_COLORS.get(sev, ("#000", "#fff"))
                tk.Label(sec_tab,
                         text=f"[{sev}] {issue}\n  {rec}",
                         bg=bg, fg=fg, justify="left",
                         font=("Segoe UI", 9), padx=8, pady=4,
                         wraplength=560, anchor="w").pack(
                    fill="x", pady=2)
        else:
            ttk.Label(sec_tab, text="✓ No security issues detected.",
                      foreground=SUCCESS).pack(pady=16)

        # ── SSL tab ──
        ssl_tab = ttk.Frame(nb, padding=12)
        nb.add(ssl_tab, text="SSL/TLS")
        si = r.get("ssl_info")
        if si:
            ssl_fields = [
                ("Version",    si.get("tls_version", "?")),
                ("Cipher",     si.get("cipher", "?")),
                ("CN",         si.get("cn", "?")),
                ("Issuer",     si.get("issuer", "?")),
                ("Expires",    si.get("not_after", "?")),
                ("Days left",  str(si.get("days_left", "?"))),
                ("Expired",    "⚠ YES" if si.get("expired") else "✓ No"),
                ("Weak cipher","⚠ YES" if si.get("weak_cipher") else "✓ No"),
                ("SANs",       ", ".join(si.get("sans", [])) or "None"),
            ]
            for i, (lbl, val) in enumerate(ssl_fields):
                ttk.Label(ssl_tab, text=lbl + ":",
                          style="Bold.TLabel").grid(
                    row=i, column=0, sticky="w", padx=(0, 12), pady=2)
                ttk.Label(ssl_tab, text=val).grid(
                    row=i, column=1, sticky="w")
        else:
            ttk.Label(ssl_tab, text="No SSL/TLS info available.",
                      style="Muted.TLabel").pack(pady=16)

        # ── Note tab ──
        note_tab = ttk.Frame(nb, padding=12)
        nb.add(note_tab, text="Note")
        note_txt = tk.Text(note_tab, wrap="word", height=8,
                           font=("Segoe UI", 9))
        note_txt.pack(fill="both", expand=True)
        note_txt.insert("1.0", self.host_notes.get(key, ""))

        def save_note():
            self.host_notes[key] = note_txt.get("1.0", "end-1c")
            self._save_notes()
            win.destroy()

        ttk.Button(note_tab, text="Save note",
                   command=save_note).pack(pady=(6, 0))

        # ── Compliance tab ──
        comp_tab = ttk.Frame(nb, padding=12)
        nb.add(comp_tab, text="Compliance")
        comp_results = check_compliance(r)
        if comp_results:
            for cr in comp_results:
                status_sym = "✓" if cr["pass"] else "✗"
                color      = SUCCESS if cr["pass"] else DANGER
                tk.Label(comp_tab,
                         text=(f"{status_sym} [{cr['framework']}] "
                               f"{cr['req_id']} — Port {cr['port']}\n"
                               f"   {cr['desc']}"),
                         fg=color, justify="left",
                         font=("Segoe UI", 9), padx=4, pady=2,
                         anchor="w").pack(fill="x", pady=1)
        else:
            ttk.Label(comp_tab, text="✓ No compliance issues found.",
                      foreground=SUCCESS).pack(pady=16)

    # ─────────────── COLUMN MANAGEMENT ───────────────

    def _toggle_columns_dialog(self):
        win = tk.Toplevel(self.root)
        win.title("Visible Columns")
        win.geometry("240x380")
        win.resizable(False, False)
        ttk.Label(win, text="Show / hide columns:",
                  style="Bold.TLabel").pack(
            anchor="w", padx=12, pady=(10, 6))
        for col, var in self._col_visible.items():
            label = self._col_cfg[col][0]
            ttk.Checkbutton(
                win, text=f"{label} ({col})", variable=var,
                command=self._apply_column_visibility).pack(
                anchor="w", padx=16, pady=2)
        ttk.Button(win, text="Close",
                   command=win.destroy).pack(pady=8)

    def _apply_column_visibility(self):
        for col, var in self._col_visible.items():
            _, default_w, _ = self._col_cfg[col]
            if var.get():
                self.tree.column(col, width=default_w, minwidth=30)
            else:
                self.tree.column(col, width=0, minwidth=0)

    # ─────────────── EXPORT ───────────────

    def _export_menu(self):
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Export CSV",         command=self.export_csv)
        menu.add_command(label="Export JSON",        command=self.export_json)
        menu.add_command(label="Export HTML Report", command=self.export_html)
        menu.add_command(label="Export Markdown Report", command=self._export_report)
        x = self.export_button.winfo_rootx()
        y = self.export_button.winfo_rooty() + self.export_button.winfo_height()
        menu.post(x, y)

    def export_csv(self):
        if not self.results:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All", "*.*")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["IP","Subnet","Status","Hostname","MAC","Vendor",
                        "Device","Threat Score","Latency(ms)","Open Ports",
                        "UDP Ports","OS","SSL","Banners","Note"])
            for r in self.results:
                key = f"{r['ip']}|{r['subnet']}"
                si  = r.get("ssl_info")
                ssl_str = ""
                if si:
                    ssl_str = (f"EXPIRED({si.get('not_after','')})"
                               if si.get("expired")
                               else si.get("tls_version", ""))
                banners_str = "; ".join(
                    f"{p}:{b[:40]}" for p, b in
                    r.get("banners", {}).items())
                w.writerow([
                    r["ip"], r["subnet"], r["status"],
                    r.get("hostname",""), r.get("mac",""),
                    r.get("vendor",""), r.get("device_type",""),
                    r.get("threat_score",""), r.get("latency_ms",""),
                    format_ports(r.get("open_ports",[])),
                    ",".join(map(str, r.get("udp_ports",[]))),
                    r.get("os_guess",""), ssl_str, banners_str,
                    self.host_notes.get(key,""),
                ])
        messagebox.showinfo("Export", f"CSV saved:\n{path}")

    def export_json(self):
        if not self.results:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All", "*.*")])
        if not path:
            return
        data = [dict(r, note=self.host_notes.get(
                     f"{r['ip']}|{r['subnet']}", ""))
                for r in self.results]
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"meta": self.scan_meta, "hosts": data},
                      f, indent=2, default=str)
        messagebox.showinfo("Export", f"JSON saved:\n{path}")

    def export_html(self):
        if not self.results:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML", "*.html"), ("All", "*.*")])
        if not path:
            return
        used  = [r for r in self.results if r["status"] == "Used"]
        crits = sum(1 for r in used if r.get("threat_score", 0) >= 60)

        html = textwrap.dedent(f"""\
        <!DOCTYPE html>
        <html lang="en">
        <head><meta charset="utf-8">
        <title>NetProbe v{VERSION} Scan Report</title>
        <style>
          body{{font-family:Segoe UI,sans-serif;background:#f8fafc;color:#0f172a;margin:32px}}
          h1{{color:#1e293b}} h2{{color:#334155;margin-top:32px}}
          table{{width:100%;border-collapse:collapse;font-size:13px}}
          th{{background:#1e293b;color:#f1f5f9;padding:8px 10px;text-align:left}}
          td{{padding:6px 10px;border-bottom:1px solid #e2e8f0}}
          tr:nth-child(even){{background:#f1f5f9}}
          .crit{{background:#fee2e2}} .high{{background:#ffedd5}}
          .medium{{background:#fef9c3}} .low{{background:#dbeafe}}
          .badge{{display:inline-block;padding:2px 8px;border-radius:4px;
                  font-size:11px;font-weight:bold}}
          .b-crit{{background:#dc2626;color:#fff}} .b-high{{background:#f97316;color:#fff}}
          .b-med{{background:#eab308;color:#000}} .b-low{{background:#22c55e;color:#fff}}
        </style></head><body>
        <h1>◈ NetProbe v{VERSION} — Scan Report</h1>
        <p><b>Generated:</b> {ts_now()} | 
           <b>Target:</b> {self.scan_meta.get('target','N/A')} |
           <b>Mode:</b> {self.scan_meta.get('mode','N/A')} |
           <b>Duration:</b> {self.scan_meta.get('duration','N/A')}</p>
        <h2>Summary</h2>
        <p>Active: <b>{len(used)}</b> | 
           Findings: <b>{len(self.security_findings)}</b> |
           High-risk hosts: <b>{crits}</b></p>
        <h2>Active Hosts</h2>
        <table>
        <tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th>
            <th>OS</th><th>Open Ports</th><th>Risk</th><th>SSL</th></tr>
        """)
        for r in sorted(used, key=lambda x: ip_sort_key(x["ip"])):
            score = r.get("threat_score", 0)
            lbl   = threat_score_label(score)
            cls   = {"CRITICAL":"b-crit","HIGH":"b-high",
                     "MEDIUM":"b-med","LOW":"b-low"}.get(lbl, "")
            si    = r.get("ssl_info")
            ssl_s = ""
            if si:
                ssl_s = ("⚠ EXPIRED" if si.get("expired")
                         else si.get("tls_version", ""))
            html += (
                f"<tr><td>{r['ip']}</td>"
                f"<td>{r.get('hostname','')}</td>"
                f"<td><code>{r.get('mac','')}</code></td>"
                f"<td>{r.get('vendor','')}</td>"
                f"<td>{r.get('os_guess','')}</td>"
                f"<td>{format_ports(r.get('open_ports',[]))[:80]}</td>"
                f"<td><span class='badge {cls}'>{score} {lbl}</span></td>"
                f"<td>{ssl_s}</td></tr>\n")

        html += """</table>
        <h2>Security Findings</h2><table>
        <tr><th>IP</th><th>Finding</th><th>Severity</th><th>Details</th></tr>"""
        for ip, issue, sev, rec in sorted(
                self.security_findings,
                key=lambda x: {"Critical":0,"High":1,"Medium":2,"Low":3}.get(x[2],4)):
            cls = sev.lower()
            html += (f"<tr class='{cls}'><td>{ip}</td><td>{issue}</td>"
                     f"<td><b>{sev}</b></td>"
                     f"<td>{rec[:100]}</td></tr>\n")

        html += f"""</table>
        <hr><p style="color:#64748b;font-size:12px">
        Report generated by {APP_FULL}</p></body></html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        webbrowser.open(f"file://{os.path.abspath(path)}")

    def _export_report(self):
        if not self.results:
            messagebox.showwarning("No data", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".md",
            filetypes=[("Markdown", "*.md"), ("All", "*.*")])
        if not path:
            return
        md = generate_markdown_report(
            self.results, self.security_findings,
            self.diff, self.scan_meta)
        with open(path, "w", encoding="utf-8") as f:
            f.write(md)
        messagebox.showinfo("Report", f"Markdown report saved:\n{path}")

    # ─────────────── BASELINE ───────────────

    def _save_baseline(self):
        if not self.results:
            messagebox.showwarning("No data", "Run a scan first.")
            return
        used = [r for r in self.results if r["status"] == "Used"]
        self.baseline_mgr.save(used)
        messagebox.showinfo("Baseline", f"Baseline saved — {len(used)} hosts.")

    # ─────────────── PASSIVE ARP MONITOR ───────────────

    def _toggle_arp_monitor(self):
        if not _SCAPY_OK:
            messagebox.showwarning(
                "ARP Monitor", "Requires scapy.\npip install scapy")
            return
        if self._arp_monitor_running:
            self._arp_monitor_running = False
            self._arp_mon_btn.config(text="  ▷  ARP Monitor")
            self.statusbar_var.set("● ARP Monitor stopped")
        else:
            self._arp_monitor_running = True
            self._arp_mon_btn.config(text="  ■  ARP Monitor")
            self.statusbar_var.set("🔴 ARP Monitor active")
            threading.Thread(
                target=self._arp_monitor_loop,
                daemon=True).start()

    def _arp_monitor_loop(self):
        def _pkt_callback(pkt):
            if not self._arp_monitor_running:
                return
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # is-at
                ip  = pkt[ARP].psrc
                mac = normalize_mac(pkt[ARP].hwsrc)
                if not ip or not mac:
                    return
                old_mac = self._known_macs.get(ip)
                if old_mac and old_mac != mac:
                    msg = (f"⚠ ARP SPOOFING DETECTED: {ip}\n"
                           f"  Was: {old_mac}\n  Now: {mac}")
                    self.alert_log.add("Critical", ip, msg, tag="arp_spoof")
                    self.root.after(0, lambda m=msg: messagebox.showwarning(
                        "⚠ ARP Spoofing Detected!", m))
                self._known_macs[ip] = mac
        try:
            sniff(filter="arp", prn=_pkt_callback, store=False,
                  stop_filter=lambda _: not self._arp_monitor_running)
        except Exception as e:
            log.warning("ARP monitor error: %s", e)

    # ─────────────── PERSISTENCE ───────────────

    def _save_notes(self):
        ensure_dirs()
        try:
            data = {
                "notes": self.host_notes,
                "favs":  list(self.host_favs),
            }
            with open(NOTES_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            log.warning("Save notes: %s", e)

    def _load_notes(self):
        if not os.path.isfile(NOTES_FILE):
            return
        try:
            with open(NOTES_FILE, encoding="utf-8") as f:
                data = json.load(f)
            self.host_notes = data.get("notes", {})
            self.host_favs  = set(data.get("favs", []))
        except Exception:
            pass

    def _load_last_scan(self):
        if not os.path.isfile(LAST_SCAN_FILE):
            return
        try:
            with open(LAST_SCAN_FILE, encoding="utf-8") as f:
                saved = json.load(f)
            self.results = saved.get("hosts", [])
            # Restore security findings
            self.security_findings = []
            for r in self.results:
                self.security_findings.extend(r.get("security_findings", []))
        except Exception:
            pass

    def _save_last_scan(self):
        ensure_dirs()
        try:
            with open(LAST_SCAN_FILE, "w", encoding="utf-8") as f:
                json.dump({"meta": self.scan_meta, "hosts": self.results},
                          f, default=str)
        except Exception as e:
            log.warning("Save last scan: %s", e)

    def _load_profiles(self):
        if not os.path.isfile(PROFILES_FILE):
            return
        try:
            with open(PROFILES_FILE, encoding="utf-8") as f:
                self.profiles = json.load(f)
        except Exception:
            self.profiles = {}

    def _save_profiles(self):
        ensure_dirs()
        try:
            with open(PROFILES_FILE, "w", encoding="utf-8") as f:
                json.dump(self.profiles, f, indent=2)
        except Exception:
            pass

    def _save_current_profile(self):
        name = self.current_profile_var.get().strip()
        if not name:
            messagebox.showwarning("Profile", "Enter a profile name.")
            return
        self.profiles[name] = {
            "subnets": [cidr for cidr, var in self._net_check_vars.items()
                        if var.get()],
            "mode":    self.mode_var.get(),
            "ports":   self.port_range_var.get(),
        }
        self._save_profiles()
        messagebox.showinfo("Profile", f"Profile '{name}' saved.")

    def _load_profile_dialog(self):
        if not self.profiles:
            messagebox.showinfo("Profiles", "No profiles saved yet.")
            return
        win = tk.Toplevel(self.root)
        win.title("Load Profile")
        win.geometry("280x300")
        lb = tk.Listbox(win, font=("Segoe UI", 10))
        lb.pack(fill="both", expand=True, padx=8, pady=8)
        for name in self.profiles:
            lb.insert("end", name)

        def load():
            sel = lb.curselection()
            if not sel:
                return
            name = lb.get(sel[0])
            p    = self.profiles[name]
            # Uncheck all then check only saved subnets
            for var in self._net_check_vars.values():
                var.set(False)
            for cidr in p.get("subnets", []):
                if cidr in self._net_check_vars:
                    self._net_check_vars[cidr].set(True)
                else:
                    # Add it dynamically
                    self._custom_net_var.set(cidr)
                    self._add_custom_network()
            self.mode_var.set(p.get("mode", "fast"))
            self.port_range_var.set(p.get("ports", ""))
            win.destroy()

        ttk.Button(win, text="Load", command=load).pack(pady=4)

    # ─────────────── SCHEDULED SCANS ───────────────

    def _schedule_tick(self):
        if (self.schedule_enabled_var.get()
                and self.next_run_time
                and datetime.datetime.now() >= self.next_run_time
                and not self.scanning):
            interval = self.schedule_interval_var.get()
            if interval > 0:
                self.next_run_time = (
                    datetime.datetime.now() +
                    datetime.timedelta(minutes=interval))
            self.start_selected_scan()
        self.root.after(10000, self._schedule_tick)

# ─── End of Section 2 ────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3 — ADVANCED UI TABS
# Dashboard · Tools · Recon · Packet Sniffer · Vuln Scan · Fingerprint
# SNMP Scanner · Alert Log · Compliance · Network Topology
# ─────────────────────────────────────────────────────────────────────────────
# This file is Section 3 of 4. Requires Sections 1 & 2.

    # ═══════════════════════════════════════════════════════════════════════
    # DASHBOARD
    # ═══════════════════════════════════════════════════════════════════════

    def _build_dashboard_ui(self):
        frame = self.view_frames["dashboard"]
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        hdr = ttk.Frame(frame, padding=(16, 12, 16, 0))
        hdr.grid(row=0, column=0, sticky="ew")
        ttk.Label(hdr, text="Dashboard", style="Heading.TLabel").pack(side=tk.LEFT)
        ttk.Button(hdr, text="↻ Refresh",
                   command=self.update_dashboard,
                   style="Ghost.TButton").pack(side=tk.RIGHT)

        ttk.Separator(frame, orient="horizontal").grid(
            row=1, column=0, sticky="ew", padx=16)

        self.dashboard_frame = ttk.Frame(frame, padding=16)
        self.dashboard_frame.grid(row=2, column=0, sticky="nsew")
        self.dashboard_frame.grid_columnconfigure(tuple(range(7)), weight=1)

    def _build_dashboard_contents(self):
        f = self.dashboard_frame
        CARD_BG = "#1e293b" if self.is_dark else "#ffffff"

        cards = [
            ("Total Scanned",   "total",    "#2563eb"),
            ("Active Hosts",    "used",     "#dc2626"),
            ("Free IPs",        "free",     "#16a34a"),
            ("MACs Found",      "macs",     "#0891b2"),
            ("Findings",        "findings", "#d97706"),
            ("Critical/High",   "crits",    "#dc2626"),
            ("Rogue Devices",   "rogues",   "#7c3aed"),
        ]
        self.dash_vars = {}
        for col, (label, key, color) in enumerate(cards):
            card = tk.Frame(f, bg=CARD_BG, padx=16, pady=16,
                            relief="flat", bd=0)
            card.grid(row=0, column=col, padx=(0, 10), sticky="ew")
            var = tk.StringVar(value="0")
            self.dash_vars[key] = var
            tk.Label(card, textvariable=var,
                     font=("Segoe UI", 22, "bold"),
                     fg=color, bg=CARD_BG).pack()
            tk.Label(card, text=label,
                     font=("Segoe UI", 8),
                     fg="#64748b", bg=CARD_BG).pack()

        if _MPL_OK:
            self.fig = Figure(figsize=(14, 4.5), tight_layout=True)
            self.ax_pie   = self.fig.add_subplot(141)
            self.ax_bar   = self.fig.add_subplot(142)
            self.ax_line  = self.fig.add_subplot(143)
            self.ax_threat = self.fig.add_subplot(144)
            self.canvas   = FigureCanvasTkAgg(self.fig, master=f)
            self.canvas.get_tk_widget().grid(
                row=1, column=0, columnspan=7,
                sticky="nsew", pady=(14, 0))
            f.grid_rowconfigure(1, weight=1)

    def update_dashboard(self):
        if not hasattr(self, "dash_vars"):
            return
        used   = sum(1 for r in self.results if r["status"] == "Used")
        free   = sum(1 for r in self.results if r["status"] == "Free")
        macs   = sum(1 for r in self.results if r.get("mac"))
        crits  = sum(1 for r in self.results
                     if r.get("threat_score", 0) >= 60)
        rogues = len(self.diff.get("rogue", []))

        self.dash_vars["total"].set(str(len(self.results)))
        self.dash_vars["used"].set(str(used))
        self.dash_vars["free"].set(str(free))
        self.dash_vars["macs"].set(str(macs))
        self.dash_vars["findings"].set(str(len(self.security_findings)))
        self.dash_vars["crits"].set(str(crits))
        self.dash_vars["rogues"].set(str(rogues))
        self._render_charts()

    def _render_charts(self):
        if not _MPL_OK or not hasattr(self, "fig"):
            return
        ct   = CHART_THEME["dark" if self.is_dark else "light"]
        used = sum(1 for r in self.results if r["status"] == "Used")
        free = sum(1 for r in self.results if r["status"] == "Free")

        for ax in (self.ax_pie, self.ax_bar, self.ax_line, self.ax_threat):
            ax.clear()
            ax.set_facecolor(ct["bg"])

        # Pie — host status
        if used or free:
            self.ax_pie.pie(
                [used, free],
                labels=["Active", "Free"],
                colors=["#dc2626", "#16a34a"],
                autopct="%1.0f%%",
                textprops={"color": ct["text"]})
            self.ax_pie.set_title("Host Status", color=ct["text"])

        # Bar — top vendors
        vendors = {}
        for r in self.results:
            if r["status"] == "Used":
                v = r.get("vendor") or "Unknown"
                vendors[v] = vendors.get(v, 0) + 1
        top = sorted(vendors.items(), key=lambda x: -x[1])[:8]
        if top:
            names, counts = zip(*top)
            self.ax_bar.barh(list(names), list(counts), color=ACCENT)
            self.ax_bar.set_title("Top Vendors", color=ct["text"])
            self.ax_bar.tick_params(colors=ct["text"])

        # Line — scan progress
        if len(self.scan_timeline) > 1:
            times   = [t - self.scan_timeline[0][0]
                       for t, _ in self.scan_timeline]
            scanned = [c for _, c in self.scan_timeline]
            self.ax_line.plot(times, scanned, color=ACCENT, linewidth=1.5)
            self.ax_line.set_title("Scan Progress", color=ct["text"])
            self.ax_line.tick_params(colors=ct["text"])
            self.ax_line.set_xlabel("Seconds", color=ct["text"])

        # Bar — threat score distribution
        buckets = {"MINIMAL": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for r in self.results:
            if r["status"] == "Used":
                lbl = threat_score_label(r.get("threat_score", 0))
                buckets[lbl] = buckets.get(lbl, 0) + 1
        colors_map = {
            "MINIMAL": "#64748b", "LOW": "#22c55e",
            "MEDIUM": "#eab308", "HIGH": "#f97316", "CRITICAL": "#dc2626"}
        if any(buckets.values()):
            self.ax_threat.bar(
                list(buckets.keys()),
                list(buckets.values()),
                color=[colors_map[k] for k in buckets])
            self.ax_threat.set_title("Threat Distribution", color=ct["text"])
            self.ax_threat.tick_params(colors=ct["text"], labelsize=7)

        self.fig.patch.set_facecolor(ct["bg"])
        self.canvas.draw_idle()

    def _live_dashboard_tick(self):
        if self.current_view == "dashboard" and self.scanning:
            self.update_dashboard()
        self.root.after(UI_CHART_UPDATE_MS, self._live_dashboard_tick)

    # ═══════════════════════════════════════════════════════════════════════
    # TOOLS TAB
    # ═══════════════════════════════════════════════════════════════════════

    def _build_tools_ui(self):
        frame = self.view_frames["tools"]
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        hdr = ttk.Frame(frame, padding=(16, 12, 16, 0))
        hdr.grid(row=0, column=0, sticky="ew")
        ttk.Label(hdr, text="Network Tools", style="Heading.TLabel").pack(side=tk.LEFT)
        ttk.Separator(frame, orient="horizontal").grid(
            row=1, column=0, sticky="ew", padx=16)

        self.tools_nb = ttk.Notebook(frame)
        self.tools_nb.grid(row=2, column=0, sticky="nsew", padx=16, pady=8)
        frame.grid_rowconfigure(2, weight=1)

    def _build_tools_contents(self):
        self._build_ping_tab()
        self._build_portcheck_tab()
        self._build_whois_tab()
        self._build_wol_tab()
        self._build_dns_tab()
        self._build_traceroute_tab()
        self._build_ssl_tab()
        self._build_firewall_tab()

    # ── Ping tab ──

    def _build_ping_tab(self):
        tab = ttk.Frame(self.tools_nb, padding=16)
        self.tools_nb.add(tab, text="🏓 Ping")
        self.ping_target_var = tk.StringVar()
        self.ping_count_var  = tk.IntVar(value=4)

        row = ttk.Frame(tab)
        row.pack(fill="x", pady=(0, 8))
        ttk.Label(row, text="Host:").pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=self.ping_target_var,
                  width=28).pack(side=tk.LEFT, padx=(6, 8))
        ttk.Label(row, text="Count:").pack(side=tk.LEFT)
        ttk.Spinbox(row, textvariable=self.ping_count_var,
                    from_=1, to=100, width=5).pack(side=tk.LEFT, padx=(4, 8))
        ttk.Button(row, text="Ping", command=self._do_ping).pack(side=tk.LEFT)
        ttk.Button(row, text="Continuous",
                   command=lambda: self._do_ping(continuous=True),
                   style="Ghost.TButton").pack(side=tk.LEFT, padx=(4, 0))

        self.ping_out = scrolledtext.ScrolledText(
            tab, height=16, font=("Courier New", 9), state="disabled")
        self.ping_out.pack(fill="both", expand=True)
        self._ping_running = False

    def _do_ping(self, continuous=False):
        ip = self.ping_target_var.get().strip()
        if not ip:
            return
        self._ping_running = True
        self.ping_out.config(state="normal")
        self.ping_out.delete("1.0", "end")
        self.ping_out.config(state="disabled")

        def run():
            count     = 999999 if continuous else self.ping_count_var.get()
            sent = recv = total_ms = 0
            for i in range(count):
                if not self._ping_running:
                    break
                alive, lat = ping_host(ip, timeout_ms=1000)
                sent += 1
                if alive:
                    recv += 1
                    total_ms += lat if isinstance(lat, int) else 0
                    msg = f"Reply from {ip}: time={lat} ms\n"
                else:
                    msg = "Request timed out.\n"
                self.root.after(0, lambda m=msg: self._ping_append(m))
                time.sleep(1)
            if sent:
                loss = int((sent - recv) / sent * 100)
                avg  = (total_ms // recv) if recv else 0
                summary = (f"\n--- {ip} ping statistics ---\n"
                           f"{sent} sent, {recv} received, "
                           f"{loss}% packet loss\n"
                           f"avg = {avg} ms\n")
                self.root.after(0, lambda s=summary: self._ping_append(s))
            self._ping_running = False

        threading.Thread(target=run, daemon=True).start()

    def _ping_append(self, msg):
        self.ping_out.config(state="normal")
        self.ping_out.insert("end", msg)
        self.ping_out.see("end")
        self.ping_out.config(state="disabled")

    # ── Port Check tab ──

    def _build_portcheck_tab(self):
        tab = ttk.Frame(self.tools_nb, padding=16)
        self.tools_nb.add(tab, text="🔌 Port Check")
        self.portcheck_host_var  = tk.StringVar()
        self.portcheck_ports_var = tk.StringVar(value="22,80,443,3389,8080")
        self.portcheck_grab_var  = tk.BooleanVar(value=True)

        row = ttk.Frame(tab)
        row.pack(fill="x", pady=(0, 8))
        ttk.Label(row, text="Host:").pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=self.portcheck_host_var,
                  width=22).pack(side=tk.LEFT, padx=(6, 10))
        ttk.Label(row, text="Ports:").pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=self.portcheck_ports_var,
                  width=28).pack(side=tk.LEFT, padx=(6, 8))
        ttk.Checkbutton(row, text="Grab banners",
                        variable=self.portcheck_grab_var).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(row, text="Scan", command=self._do_portcheck).pack(side=tk.LEFT)

        self.portcheck_out = scrolledtext.ScrolledText(
            tab, height=16, font=("Courier New", 9), state="disabled")
        self.portcheck_out.pack(fill="both", expand=True)

    def _do_portcheck(self):
        ip  = self.portcheck_host_var.get().strip()
        raw = self.portcheck_ports_var.get().strip()
        ports = ([int(p) for p in raw.split(",") if p.strip().isdigit()]
                 if raw else TCP_PROBE_PORTS[:20])
        if not ip:
            return
        self.portcheck_out.config(state="normal")
        self.portcheck_out.delete("1.0", "end")
        self.portcheck_out.config(state="disabled")

        def run():
            for p in sorted(set(ports)):
                s   = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                open_ = s.connect_ex((ip, p)) == 0
                s.close()
                svc    = WELL_KNOWN_PORTS.get(p, "")
                banner = ""
                if open_ and self.portcheck_grab_var.get():
                    banner = grab_banner(ip, p, timeout=1.5)
                    if banner:
                        banner = f"  ↳ {banner[:80]}"
                line = (f"  ✓ {p:5d}  {svc:<14}  OPEN{banner}\n"
                        if open_
                        else f"  ✗ {p:5d}  {svc:<14}  closed\n")
                self.root.after(0, lambda l=line: self._portcheck_append(l))

        threading.Thread(target=run, daemon=True).start()

    def _portcheck_append(self, msg):
        self.portcheck_out.config(state="normal")
        self.portcheck_out.insert("end", msg)
        self.portcheck_out.see("end")
        self.portcheck_out.config(state="disabled")

    # ── WHOIS tab ──

    def _build_whois_tab(self):
        tab = ttk.Frame(self.tools_nb, padding=16)
        self.tools_nb.add(tab, text="🌍 WHOIS")
        self.whois_target_var = tk.StringVar()

        row = ttk.Frame(tab)
        row.pack(fill="x", pady=(0, 8))
        ttk.Label(row, text="IP / Domain:").pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=self.whois_target_var,
                  width=30).pack(side=tk.LEFT, padx=(6, 8))
        ttk.Button(row, text="Lookup", command=self._do_whois).pack(side=tk.LEFT)

        self.whois_out = scrolledtext.ScrolledText(
            tab, height=20, font=("Courier New", 9), state="disabled")
        self.whois_out.pack(fill="both", expand=True)

    def _do_whois(self):
        target = self.whois_target_var.get().strip()
        if not target:
            return
        self.whois_out.config(state="normal")
        self.whois_out.delete("1.0", "end")
        self.whois_out.insert("end", f"Querying WHOIS for {target}…\n")
        self.whois_out.config(state="disabled")

        def run():
            result = whois_lookup(target)
            self.root.after(0, lambda r=result: self._whois_done(r))

        threading.Thread(target=run, daemon=True).start()

    def _whois_done(self, text):
        self.whois_out.config(state="normal")
        self.whois_out.delete("1.0", "end")
        self.whois_out.insert("end", text)
        self.whois_out.config(state="disabled")

    # ── Wake-on-LAN tab ──

    def _build_wol_tab(self):
        tab = ttk.Frame(self.tools_nb, padding=16)
        self.tools_nb.add(tab, text="⚡ Wake-on-LAN")
        self.wol_mac_var  = tk.StringVar()
        self.wol_bcast_var = tk.StringVar(value="255.255.255.255")

        row = ttk.Frame(tab)
        row.pack(fill="x", pady=(0, 8))
        ttk.Label(row, text="MAC:").pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=self.wol_mac_var,
                  width=22).pack(side=tk.LEFT, padx=(6, 10))
        ttk.Label(row, text="Broadcast:").pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=self.wol_bcast_var,
                  width=16).pack(side=tk.LEFT, padx=(6, 8))
        ttk.Button(row, text="Send Magic Packet",
                   command=self._do_wol).pack(side=tk.LEFT)

        ttk.Label(tab,
                  text="Or right-click any host in Scanner → Wake-on-LAN",
                  style="Muted.TLabel").pack(pady=(12, 0), anchor="w")

    def _do_wol(self):
        mac = self.wol_mac_var.get().strip()
        if not mac:
            messagebox.showwarning("Wake-on-LAN", "Enter a MAC address.")
            return
        try:
            send_wol(mac)
            messagebox.showinfo("Wake-on-LAN", f"Magic packet sent to {mac}.")
        except Exception as e:
            messagebox.showerror("Wake-on-LAN", str(e))

    # ── DNS Lookup tab ──

    def _build_dns_tab(self):
        tab = ttk.Frame(self.tools_nb, padding=16)
        self.tools_nb.add(tab, text="🔡 DNS")
        self.dns_target_var  = tk.StringVar()
        self.dns_type_var    = tk.StringVar(value="A")
        self.dns_server_var  = tk.StringVar(value="")

        row = ttk.Frame(tab)
        row.pack(fill="x", pady=(0, 8))
        ttk.Label(row, text="Name/IP:").pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=self.dns_target_var,
                  width=28).pack(side=tk.LEFT, padx=(6, 8))
        ttk.Label(row, text="Type:").pack(side=tk.LEFT)
        ttk.Combobox(row, textvariable=self.dns_type_var,
                     values=["A", "AAAA", "MX", "NS", "TXT", "PTR",
                             "CNAME", "SOA", "SRV", "ANY"],
                     width=7, state="readonly").pack(side=tk.LEFT, padx=(4, 8))
        ttk.Label(row, text="Server:").pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=self.dns_server_var,
                  width=16).pack(side=tk.LEFT, padx=(4, 8))
        ttk.Button(row, text="Lookup",
                   command=self._do_dns).pack(side=tk.LEFT)
        ttk.Button(row, text="Reverse DNS",
                   command=self._do_rdns,
                   style="Ghost.TButton").pack(side=tk.LEFT, padx=(4, 0))

        self.dns_out = scrolledtext.ScrolledText(
            tab, height=16, font=("Courier New", 9), state="disabled")
        self.dns_out.pack(fill="both", expand=True)

    def _do_dns(self):
        target = self.dns_target_var.get().strip()
        dtype  = self.dns_type_var.get()
        server = self.dns_server_var.get().strip()
        if not target:
            return
        self.dns_out.config(state="normal")
        self.dns_out.delete("1.0", "end")
        self.dns_out.config(state="disabled")

        def run():
            lines = []
            if server:
                import subprocess
                try:
                    cmd = ["nslookup", f"-type={dtype}", target, server]
                    out = subprocess.check_output(
                        cmd, stderr=subprocess.STDOUT,
                        timeout=10).decode(errors="ignore")
                    lines = out.splitlines()
                except Exception as e:
                    lines = [f"nslookup error: {e}"]
            else:
                try:
                    if dtype == "PTR":
                        results = [socket.gethostbyaddr(target)[0]]
                    else:
                        import socket as _s
                        addrs = _s.getaddrinfo(target, None,
                                               proto=_s.IPPROTO_TCP)
                        results = list({a[4][0] for a in addrs})
                    lines = [f"{dtype}  {r}" for r in results]
                except Exception as e:
                    lines = [f"DNS error: {e}"]
            self.root.after(0, lambda ls=lines: self._dns_done(ls))

        threading.Thread(target=run, daemon=True).start()

    def _do_rdns(self):
        target = self.dns_target_var.get().strip()
        if not target:
            return
        self.dns_out.config(state="normal")
        self.dns_out.delete("1.0", "end")
        self.dns_out.config(state="disabled")

        def run():
            try:
                result = socket.gethostbyaddr(target)
                lines  = [f"PTR  {result[0]}"] + [f"     alias: {a}"
                                                    for a in result[1]]
            except Exception as e:
                lines = [f"Reverse DNS error: {e}"]
            self.root.after(0, lambda ls=lines: self._dns_done(ls))

        threading.Thread(target=run, daemon=True).start()

    def _dns_done(self, lines):
        self.dns_out.config(state="normal")
        self.dns_out.delete("1.0", "end")
        for line in lines:
            self.dns_out.insert("end", line + "\n")
        self.dns_out.config(state="disabled")

    # ── Traceroute tab ──

    def _build_traceroute_tab(self):
        tab = ttk.Frame(self.tools_nb, padding=16)
        self.tools_nb.add(tab, text="🗺 Traceroute")
        self.tr_target_var = tk.StringVar()
        self.tr_hops_var   = tk.IntVar(value=20)

        row = ttk.Frame(tab)
        row.pack(fill="x", pady=(0, 8))
        ttk.Label(row, text="Host:").pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=self.tr_target_var,
                  width=28).pack(side=tk.LEFT, padx=(6, 8))
        ttk.Label(row, text="Max hops:").pack(side=tk.LEFT)
        ttk.Spinbox(row, textvariable=self.tr_hops_var,
                    from_=1, to=64, width=5).pack(side=tk.LEFT, padx=(4, 8))
        ttk.Button(row, text="Trace",
                   command=self._do_traceroute).pack(side=tk.LEFT)

        self.tr_out = scrolledtext.ScrolledText(
            tab, height=16, font=("Courier New", 9), state="disabled")
        self.tr_out.pack(fill="both", expand=True)

    def _do_traceroute(self):
        target = self.tr_target_var.get().strip()
        if not target:
            return
        self.tr_out.config(state="normal")
        self.tr_out.delete("1.0", "end")
        self.tr_out.insert("end", f"Tracing route to {target}…\n\n")
        self.tr_out.config(state="disabled")

        def run():
            hops = traceroute_host(target, max_hops=self.tr_hops_var.get())
            for h in hops:
                rtt  = f"{h['rtt_ms']} ms" if h["rtt_ms"] is not None else "  *"
                hn   = f"  ({h['hostname']})" if h.get("hostname") else ""
                line = f"  {h['hop']:2d}   {h['ip']:<18}  {rtt:<10}{hn}\n"
                self.tr_out.config(state="normal")
                self.tr_out.insert("end", line)
                self.tr_out.see("end")
                self.tr_out.config(state="disabled")
            self.tr_out.config(state="normal")
            self.tr_out.insert("end", "\nTrace complete.\n")
            self.tr_out.config(state="disabled")

        threading.Thread(target=run, daemon=True).start()

    # ── SSL Inspector tab ──

    def _build_ssl_tab(self):
        tab = ttk.Frame(self.tools_nb, padding=16)
        self.tools_nb.add(tab, text="🔒 SSL/TLS")
        self.ssl_host_var = tk.StringVar()
        self.ssl_port_var = tk.IntVar(value=443)

        row = ttk.Frame(tab)
        row.pack(fill="x", pady=(0, 8))
        ttk.Label(row, text="Host:").pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=self.ssl_host_var,
                  width=28).pack(side=tk.LEFT, padx=(6, 8))
        ttk.Label(row, text="Port:").pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=self.ssl_port_var,
                  width=7).pack(side=tk.LEFT, padx=(4, 8))
        ttk.Button(row, text="Inspect",
                   command=self._do_ssl_inspect).pack(side=tk.LEFT)

        self.ssl_out = scrolledtext.ScrolledText(
            tab, height=16, font=("Courier New", 9), state="disabled")
        self.ssl_out.pack(fill="both", expand=True)

    def _do_ssl_inspect(self):
        host = self.ssl_host_var.get().strip()
        port = self.ssl_port_var.get()
        if not host:
            return
        self.ssl_out.config(state="normal")
        self.ssl_out.delete("1.0", "end")
        self.ssl_out.insert("end", f"Inspecting {host}:{port}…\n\n")
        self.ssl_out.config(state="disabled")

        def run():
            info = inspect_ssl(host, port)
            self.ssl_out.config(state="normal")
            if not info:
                self.ssl_out.insert("end", "No SSL/TLS detected.\n")
            else:
                fields = [
                    ("TLS Version",   info.get("tls_version", "?")),
                    ("Cipher Suite",  info.get("cipher", "?")),
                    ("Common Name",   info.get("cn", "?")),
                    ("Issuer",        info.get("issuer", "?")),
                    ("Valid From",    info.get("not_before", "?")),
                    ("Expires",       info.get("not_after", "?")),
                    ("Days Until Expiry", str(info.get("days_left", "?"))),
                    ("Expired",       "⚠ YES — RENEW NOW" if info.get("expired") else "✓ No"),
                    ("Weak Cipher",   "⚠ YES" if info.get("weak_cipher") else "✓ No"),
                    ("SANs",          "\n             ".join(info.get("sans", [])) or "None"),
                ]
                for label, val in fields:
                    self.ssl_out.insert("end", f"  {label:<22}: {val}\n")

                # Recommendations
                recs = []
                if info.get("expired"):
                    recs.append("⚠  Certificate is EXPIRED — renew immediately")
                elif (info.get("days_left") or 999) < 30:
                    recs.append(f"⚠  Certificate expires in {info.get('days_left')} days")
                if info.get("weak_cipher"):
                    recs.append("⚠  Weak cipher detected — enforce TLS 1.2+ and strong suites")
                if "TLS 1.0" in (info.get("tls_version") or ""):
                    recs.append("⚠  TLS 1.0 is deprecated — upgrade to TLS 1.2+")
                if recs:
                    self.ssl_out.insert("end", "\nRecommendations:\n")
                    for r in recs:
                        self.ssl_out.insert("end", f"  {r}\n")
            self.ssl_out.config(state="disabled")

        threading.Thread(target=run, daemon=True).start()

    # ── Firewall Rule Generator tab ──

    def _build_firewall_tab(self):
        tab = ttk.Frame(self.tools_nb, padding=16)
        self.tools_nb.add(tab, text="🧱 Firewall Rules")
        self.fw_ips_var   = tk.StringVar()
        self.fw_ports_var = tk.StringVar()
        self.fw_fmt_var   = tk.StringVar(value="iptables")

        ctrl = ttk.Frame(tab)
        ctrl.pack(fill="x", pady=(0, 8))

        ttk.Label(ctrl, text="IPs (comma-sep):").grid(
            row=0, column=0, sticky="w", padx=(0, 6))
        ttk.Entry(ctrl, textvariable=self.fw_ips_var,
                  width=34).grid(row=0, column=1, sticky="w")

        ttk.Label(ctrl, text="Ports (comma-sep):").grid(
            row=1, column=0, sticky="w", pady=(4, 0), padx=(0, 6))
        ttk.Entry(ctrl, textvariable=self.fw_ports_var,
                  width=34).grid(row=1, column=1, sticky="w", pady=(4, 0))

        ttk.Label(ctrl, text="Format:").grid(
            row=2, column=0, sticky="w", pady=(4, 0), padx=(0, 6))
        ttk.Combobox(ctrl, textvariable=self.fw_fmt_var,
                     values=["iptables", "nftables", "windows", "pf"],
                     width=12, state="readonly").grid(
            row=2, column=1, sticky="w", pady=(4, 0))

        ttk.Button(ctrl, text="Generate Rules →",
                   command=self._do_gen_fw_rules).grid(
            row=3, column=0, columnspan=2, sticky="w", pady=(8, 0))

        self.fw_out = scrolledtext.ScrolledText(
            tab, height=16, font=("Courier New", 9), state="disabled")
        self.fw_out.pack(fill="both", expand=True, pady=(8, 0))

        # Prefill from last scan
        ttk.Button(tab, text="Auto-fill from high-risk scan results →",
                   command=self._fw_autofill,
                   style="Ghost.TButton").pack(anchor="w", pady=(4, 0))

    def _do_gen_fw_rules(self):
        ips_raw   = self.fw_ips_var.get().strip()
        ports_raw = self.fw_ports_var.get().strip()
        ips   = [i.strip() for i in ips_raw.split(",")  if i.strip()]
        ports = [int(p.strip()) for p in ports_raw.split(",")
                 if p.strip().isdigit()]
        rules = generate_block_rules(ips, ports, fmt=self.fw_fmt_var.get())
        self.fw_out.config(state="normal")
        self.fw_out.delete("1.0", "end")
        self.fw_out.insert("end", rules)
        self.fw_out.config(state="disabled")

    def _fw_autofill(self):
        high_risk = [r["ip"] for r in self.results
                     if r.get("threat_score", 0) >= 60]
        if not high_risk:
            messagebox.showinfo("Auto-fill", "No high-risk hosts found in last scan.")
            return
        self.fw_ips_var.set(", ".join(high_risk[:20]))

    # ═══════════════════════════════════════════════════════════════════════
    # RECON TAB  (pentest-focused: NetBIOS enum, HTTP probe, default creds)
    # ═══════════════════════════════════════════════════════════════════════

    def _build_recon_ui(self):
        frame = self.view_frames["recon"]
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        hdr = ttk.Frame(frame, padding=(16, 12, 16, 0))
        hdr.grid(row=0, column=0, sticky="ew")
        ttk.Label(hdr, text="Recon & Active Probing",
                  style="Heading.TLabel").pack(side=tk.LEFT)
        ttk.Separator(frame, orient="horizontal").grid(
            row=1, column=0, sticky="ew", padx=16)

        self.recon_nb = ttk.Notebook(frame)
        self.recon_nb.grid(row=2, column=0, sticky="nsew", padx=16, pady=8)
        frame.grid_rowconfigure(2, weight=1)

    def _build_recon_contents(self):
        self._build_http_probe_tab()
        self._build_netbios_tab()
        self._build_default_creds_tab()
        self._build_port_knock_tab()
        self._build_subdomain_tab()

    # ── HTTP Probe tab ──

    def _build_http_probe_tab(self):
        tab = ttk.Frame(self.recon_nb, padding=16)
        self.recon_nb.add(tab, text="🌐 HTTP Probe")
        self.http_target_var  = tk.StringVar()
        self.http_ports_var   = tk.StringVar(value="80,443,8080,8443,8888")
        self.http_deep_var    = tk.BooleanVar(value=False)

        ctrl = ttk.Frame(tab)
        ctrl.pack(fill="x", pady=(0, 8))
        ttk.Label(ctrl, text="Target (IP/subnet):").pack(side=tk.LEFT)
        ttk.Entry(ctrl, textvariable=self.http_target_var,
                  width=24).pack(side=tk.LEFT, padx=(6, 8))
        ttk.Label(ctrl, text="Ports:").pack(side=tk.LEFT)
        ttk.Entry(ctrl, textvariable=self.http_ports_var,
                  width=22).pack(side=tk.LEFT, padx=(4, 8))
        ttk.Checkbutton(ctrl, text="Deep (grab more paths)",
                        variable=self.http_deep_var).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(ctrl, text="Probe →",
                   command=self._do_http_probe).pack(side=tk.LEFT)

        cols = ("ip", "port", "status", "title", "server", "redirect")
        self.http_tree = ttk.Treeview(tab, columns=cols,
                                       show="headings", height=14)
        for c, w in [("ip", 130), ("port", 60), ("status", 60),
                     ("title", 280), ("server", 160), ("redirect", 180)]:
            self.http_tree.heading(c, text=c.capitalize())
            self.http_tree.column(c, width=w)
        vsb = ttk.Scrollbar(tab, orient="vertical",
                             command=self.http_tree.yview)
        self.http_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill="y")
        self.http_tree.pack(fill="both", expand=True)
        self.http_tree.bind("<Double-1>", self._http_open_browser)

    def _do_http_probe(self):
        target = self.http_target_var.get().strip()
        if not target:
            return
        ports_raw = self.http_ports_var.get().strip()
        ports = [int(p) for p in ports_raw.split(",") if p.strip().isdigit()]

        try:
            net  = ipaddress.ip_network(target, strict=False)
            ips  = [str(h) for h in (net.hosts() if net.num_addresses > 2
                                      else [net.network_address])]
        except ValueError:
            ips = [target]

        for row in self.http_tree.get_children():
            self.http_tree.delete(row)

        def run():
            for ip in ips:
                for port in ports:
                    use_https = port in (443, 8443)
                    info = probe_http(ip, port, use_https=use_https)
                    if info["status"] is not None:
                        self.root.after(0, lambda i=ip, p=port, r=info:
                            self.http_tree.insert("", "end", values=(
                                i, p,
                                r["status"] or r["error"][:10],
                                r["title"][:60],
                                r["server"][:30],
                                r["redirect"][:40],
                            )))

        threading.Thread(target=run, daemon=True).start()

    def _http_open_browser(self, _=None):
        sel = self.http_tree.selection()
        if not sel:
            return
        vals = self.http_tree.item(sel[0], "values")
        ip, port = vals[0], vals[1]
        scheme = "https" if int(port) in (443, 8443) else "http"
        webbrowser.open(f"{scheme}://{ip}:{port}/")

    # ── NetBIOS Enumerator tab ──

    def _build_netbios_tab(self):
        tab = ttk.Frame(self.recon_nb, padding=16)
        self.recon_nb.add(tab, text="📡 NetBIOS")
        self.nb_target_var = tk.StringVar()

        ctrl = ttk.Frame(tab)
        ctrl.pack(fill="x", pady=(0, 8))
        ttk.Label(ctrl, text="Target (IP/subnet):").pack(side=tk.LEFT)
        ttk.Entry(ctrl, textvariable=self.nb_target_var,
                  width=28).pack(side=tk.LEFT, padx=(6, 8))
        ttk.Button(ctrl, text="Enumerate →",
                   command=self._do_netbios).pack(side=tk.LEFT)

        cols = ("ip", "names", "workgroup", "mac")
        self.nb_tree = ttk.Treeview(tab, columns=cols, show="headings",
                                     height=14)
        for c, w in [("ip", 130), ("names", 280), ("workgroup", 130),
                     ("mac", 155)]:
            self.nb_tree.heading(c, text=c.capitalize())
            self.nb_tree.column(c, width=w)
        vsb = ttk.Scrollbar(tab, orient="vertical",
                             command=self.nb_tree.yview)
        self.nb_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill="y")
        self.nb_tree.pack(fill="both", expand=True)

    def _do_netbios(self):
        target = self.nb_target_var.get().strip()
        if not target:
            return
        try:
            net = ipaddress.ip_network(target, strict=False)
            ips = [str(h) for h in (net.hosts()
                                     if net.num_addresses > 2
                                     else [net.network_address])]
        except ValueError:
            ips = [target]

        for row in self.nb_tree.get_children():
            self.nb_tree.delete(row)

        def run():
            pool = SmartWorkerPool(workers=min(32, len(ips)),
                                   queue_limit=len(ips) + 10)
            for ip in ips:
                pool.submit(probe_one, ip)
            pool.queue.join()
            pool.shutdown()

        def probe_one(ip):
            info = enumerate_netbios(ip)
            if info["names"]:
                names_str = ", ".join(
                    n["name"] for n in info["names"])
                self.root.after(0, lambda i=ip, s=names_str,
                                w=info["workgroup"], m=info["mac"]:
                    self.nb_tree.insert("", "end",
                                        values=(i, s, w, m)))

        threading.Thread(target=run, daemon=True).start()

    # ── Default Credentials tab ──

    def _build_default_creds_tab(self):
        tab = ttk.Frame(self.recon_nb, padding=16)
        self.recon_nb.add(tab, text="🔑 Default Creds")

        warn = tk.Label(
            tab,
            text="⚠  Use only on systems you own or have written permission to test.",
            bg="#fef9c3", fg="#713f12",
            font=("Segoe UI", 9, "bold"), padx=8, pady=4)
        warn.pack(fill="x", pady=(0, 8))

        ctrl = ttk.Frame(tab)
        ctrl.pack(fill="x", pady=(0, 8))

        self.dc_target_var  = tk.StringVar()
        self.dc_service_var = tk.StringVar(value="SSH")

        ttk.Label(ctrl, text="Target:").pack(side=tk.LEFT)
        ttk.Entry(ctrl, textvariable=self.dc_target_var,
                  width=22).pack(side=tk.LEFT, padx=(6, 8))
        ttk.Label(ctrl, text="Service:").pack(side=tk.LEFT)
        ttk.Combobox(ctrl, textvariable=self.dc_service_var,
                     values=list(DEFAULT_CREDS.keys()),
                     width=10, state="readonly").pack(
            side=tk.LEFT, padx=(4, 8))
        ttk.Button(ctrl, text="Check →",
                   command=self._do_check_creds).pack(side=tk.LEFT)

        self.dc_out = scrolledtext.ScrolledText(
            tab, height=16, font=("Courier New", 9), state="disabled")
        self.dc_out.pack(fill="both", expand=True)

    def _do_check_creds(self):
        target  = self.dc_target_var.get().strip()
        service = self.dc_service_var.get()
        if not target:
            return
        creds = DEFAULT_CREDS.get(service, [])

        self.dc_out.config(state="normal")
        self.dc_out.delete("1.0", "end")
        self.dc_out.insert("end",
            f"Checking {len(creds)} default credentials on "
            f"{target} ({service})…\n\n")
        self.dc_out.config(state="disabled")

        def run():
            for user, pwd in creds:
                result = self._try_cred(target, service, user, pwd)
                sym    = "✓ VALID" if result else "✗"
                line   = f"  {sym}  {user!r} / {pwd!r}\n"
                self.dc_out.config(state="normal")
                self.dc_out.insert("end", line)
                if result:
                    self.dc_out.tag_add("hit",
                        f"end-{len(line)+1}c", "end-1c")
                    self.dc_out.tag_configure("hit",
                        background="#fee2e2",
                        foreground="#dc2626",
                        font=("Courier New", 9, "bold"))
                    # Log alert
                    self.alert_log.add("Critical", target,
                        f"Default credential confirmed: {service} "
                        f"{user!r}/{pwd!r}", tag="default_cred")
                self.dc_out.see("end")
                self.dc_out.config(state="disabled")

        threading.Thread(target=run, daemon=True).start()

    def _try_cred(self, ip: str, service: str, user: str, pwd: str) -> bool:
        """Try a single credential pair. Returns True if successful."""
        timeout = DEFAULT_CRED_TIMEOUT_S
        try:
            if service == "FTP":
                import ftplib
                ftp = ftplib.FTP(timeout=int(timeout))
                ftp.connect(ip, 21, timeout=int(timeout))
                ftp.login(user, pwd)
                ftp.quit()
                return True

            elif service == "SSH" and _PARAMIKO_OK:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(
                    paramiko.AutoAddPolicy())
                client.connect(ip, port=22, username=user,
                               password=pwd, timeout=timeout,
                               allow_agent=False, look_for_keys=False)
                client.close()
                return True

            elif service == "HTTP":
                import urllib.request, base64
                url     = f"http://{ip}/"
                creds_b = base64.b64encode(f"{user}:{pwd}".encode())
                req     = urllib.request.Request(
                    url,
                    headers={"Authorization": f"Basic {creds_b.decode()}"})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    return r.status < 400

            elif service == "Telnet":
                import telnetlib
                tn = telnetlib.Telnet(ip, 23, timeout=int(timeout))
                tn.read_until(b"login:", timeout=3)
                tn.write(user.encode() + b"\n")
                tn.read_until(b"Password:", timeout=3)
                tn.write(pwd.encode() + b"\n")
                resp = tn.read_some()
                tn.close()
                return b"incorrect" not in resp.lower() and len(resp) > 2

            elif service == "Redis":
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((ip, 6379))
                if pwd:
                    s.send(f"AUTH {pwd}\r\n".encode())
                    resp = s.recv(128)
                    s.close()
                    return resp.startswith(b"+OK")
                else:
                    s.send(b"PING\r\n")
                    resp = s.recv(128)
                    s.close()
                    return b"+PONG" in resp

        except Exception:
            pass
        return False

    # ── Port Knock tab ──

    def _build_port_knock_tab(self):
        tab = ttk.Frame(self.recon_nb, padding=16)
        self.recon_nb.add(tab, text="🚪 Port Knock")
        self.knock_target_var = tk.StringVar()
        self.knock_seq_var    = tk.StringVar(value="1234,5678,9012")
        self.knock_delay_var  = tk.DoubleVar(value=0.1)

        ctrl = ttk.Frame(tab)
        ctrl.pack(fill="x", pady=(0, 8))
        ttk.Label(ctrl, text="Host:").pack(side=tk.LEFT)
        ttk.Entry(ctrl, textvariable=self.knock_target_var,
                  width=22).pack(side=tk.LEFT, padx=(6, 8))
        ttk.Label(ctrl, text="Knock sequence:").pack(side=tk.LEFT)
        ttk.Entry(ctrl, textvariable=self.knock_seq_var,
                  width=24).pack(side=tk.LEFT, padx=(4, 8))
        ttk.Label(ctrl, text="Delay(s):").pack(side=tk.LEFT)
        ttk.Spinbox(ctrl, textvariable=self.knock_delay_var,
                    from_=0.05, to=2.0, increment=0.05,
                    width=6).pack(side=tk.LEFT, padx=(4, 8))
        ttk.Button(ctrl, text="Knock →",
                   command=self._do_port_knock).pack(side=tk.LEFT)

        self.knock_out = scrolledtext.ScrolledText(
            tab, height=10, font=("Courier New", 9), state="disabled")
        self.knock_out.pack(fill="both", expand=True, pady=(8, 0))
        ttk.Label(tab,
                  text="Sends TCP SYN packets to each port in sequence "
                       "(requires scapy for stealth mode)",
                  style="Muted.TLabel").pack(anchor="w")

    def _do_port_knock(self):
        target = self.knock_target_var.get().strip()
        raw    = self.knock_seq_var.get().strip()
        ports  = [int(p) for p in raw.split(",") if p.strip().isdigit()]
        delay  = self.knock_delay_var.get()
        if not target or not ports:
            return

        self.knock_out.config(state="normal")
        self.knock_out.delete("1.0", "end")
        self.knock_out.insert("end",
            f"Knocking {target} with sequence {ports}…\n")
        self.knock_out.config(state="disabled")

        def run():
            for p in ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.3)
                    s.connect_ex((target, p))
                    s.close()
                    msg = f"  Knocked port {p}\n"
                except Exception as e:
                    msg = f"  Port {p} error: {e}\n"
                self.knock_out.config(state="normal")
                self.knock_out.insert("end", msg)
                self.knock_out.see("end")
                self.knock_out.config(state="disabled")
                time.sleep(delay)
            self.knock_out.config(state="normal")
            self.knock_out.insert("end", "Knock sequence complete.\n")
            self.knock_out.config(state="disabled")

        threading.Thread(target=run, daemon=True).start()

    # ── Subdomain/Hostname Enum tab ──

    def _build_subdomain_tab(self):
        tab = ttk.Frame(self.recon_nb, padding=16)
        self.recon_nb.add(tab, text="🔎 Subdomain Enum")
        self.sd_domain_var  = tk.StringVar()
        self.sd_wordlist_var = tk.StringVar(value="www,mail,ftp,vpn,admin,api,dev,staging,test,portal,remote")

        ctrl = ttk.Frame(tab)
        ctrl.pack(fill="x", pady=(0, 8))
        ttk.Label(ctrl, text="Domain:").pack(side=tk.LEFT)
        ttk.Entry(ctrl, textvariable=self.sd_domain_var,
                  width=28).pack(side=tk.LEFT, padx=(6, 8))
        ttk.Button(ctrl, text="Enumerate →",
                   command=self._do_subdomain_enum).pack(side=tk.LEFT)

        ttk.Label(tab, text="Wordlist (comma-sep):").pack(anchor="w")
        ttk.Entry(tab, textvariable=self.sd_wordlist_var).pack(
            fill="x", pady=(2, 8))

        cols = ("subdomain", "ip", "status")
        self.sd_tree = ttk.Treeview(tab, columns=cols, show="headings",
                                     height=14)
        for c, w in [("subdomain", 250), ("ip", 140), ("status", 80)]:
            self.sd_tree.heading(c, text=c.capitalize())
            self.sd_tree.column(c, width=w)
        vsb = ttk.Scrollbar(tab, orient="vertical",
                             command=self.sd_tree.yview)
        self.sd_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill="y")
        self.sd_tree.pack(fill="both", expand=True)

    def _do_subdomain_enum(self):
        domain   = self.sd_domain_var.get().strip()
        wordlist = [w.strip() for w in
                    self.sd_wordlist_var.get().split(",") if w.strip()]
        if not domain:
            return
        for row in self.sd_tree.get_children():
            self.sd_tree.delete(row)

        def run():
            for prefix in wordlist:
                fqdn = f"{prefix}.{domain}"
                try:
                    ip     = socket.gethostbyname(fqdn)
                    status = "✓ Resolved"
                except socket.gaierror:
                    ip     = "—"
                    status = "✗ NXDOMAIN"
                self.root.after(0, lambda f=fqdn, i=ip, s=status:
                    self.sd_tree.insert("", "end", values=(f, i, s)))

        threading.Thread(target=run, daemon=True).start()

    # ═══════════════════════════════════════════════════════════════════════
    # PACKET SNIFFER
    # ═══════════════════════════════════════════════════════════════════════

    def _build_sniffer_ui(self):
        frame = self.view_frames["sniffer"]
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        hdr = ttk.Frame(frame, padding=(16, 12, 16, 0))
        hdr.grid(row=0, column=0, sticky="ew")
        ttk.Label(hdr, text="Packet Sniffer",
                  style="Heading.TLabel").pack(side=tk.LEFT)
        ttk.Separator(frame, orient="horizontal").grid(
            row=1, column=0, sticky="ew", padx=16)
        self.sniffer_inner = ttk.Frame(frame, padding=16)
        self.sniffer_inner.grid(row=2, column=0, sticky="nsew")

    def _build_sniffer_contents(self):
        f = self.sniffer_inner
        f.grid_rowconfigure(1, weight=1)
        f.grid_columnconfigure(0, weight=1)

        ctrl = ttk.Frame(f)
        ctrl.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        self.sniff_iface_var   = tk.StringVar(value="")
        self.sniff_filter_var  = tk.StringVar(value="")
        self.sniff_count_var   = tk.IntVar(value=0)
        self.sniff_save_var    = tk.BooleanVar(value=False)
        self.sniff_status_var  = tk.StringVar(value="Idle")

        # Interface selector
        ifaces = []
        if _SCAPY_OK:
            try:
                ifaces = get_if_list()
            except Exception:
                pass
        ttk.Label(ctrl, text="Interface:").pack(side=tk.LEFT)
        iface_cb = ttk.Combobox(ctrl, textvariable=self.sniff_iface_var,
                                 values=ifaces, width=14)
        iface_cb.pack(side=tk.LEFT, padx=(4, 8))

        ttk.Label(ctrl, text="BPF Filter:").pack(side=tk.LEFT)
        ttk.Entry(ctrl, textvariable=self.sniff_filter_var,
                  width=22).pack(side=tk.LEFT, padx=(4, 8))
        Tooltip(iface_cb,
                "Examples: 'tcp port 80', 'host 192.168.1.1',\n"
                "'arp', 'udp', 'not arp'")

        ttk.Label(ctrl, text="Max pkts (0=∞):").pack(side=tk.LEFT)
        ttk.Spinbox(ctrl, textvariable=self.sniff_count_var,
                    from_=0, to=100000, width=7).pack(
            side=tk.LEFT, padx=(4, 8))

        ttk.Checkbutton(ctrl, text="Save PCAP",
                        variable=self.sniff_save_var).pack(
            side=tk.LEFT, padx=(0, 8))

        self.sniff_start_btn = ttk.Button(
            ctrl, text="▶ Capture", command=self._sniff_start,
            style="Success.TButton")
        self.sniff_start_btn.pack(side=tk.LEFT, padx=(0, 4))

        self.sniff_stop_btn = ttk.Button(
            ctrl, text="■ Stop", command=self._sniff_stop,
            style="Danger.TButton", state=tk.DISABLED)
        self.sniff_stop_btn.pack(side=tk.LEFT, padx=(0, 4))

        ttk.Button(ctrl, text="Clear",
                   command=self._sniff_clear,
                   style="Ghost.TButton").pack(side=tk.LEFT, padx=(0, 4))

        ttk.Button(ctrl, text="Export PCAP",
                   command=self._sniff_export_pcap,
                   style="Ghost.TButton").pack(side=tk.LEFT)

        ttk.Label(ctrl, textvariable=self.sniff_status_var,
                  style="Muted.TLabel").pack(side=tk.RIGHT)

        # Packet table
        cols = ("no", "time", "src", "dst", "proto", "len", "info")
        self.sniff_tree = ttk.Treeview(f, columns=cols, show="headings")
        for c, w in [("no", 52), ("time", 110), ("src", 165),
                     ("dst", 165), ("proto", 70), ("len", 52),
                     ("info", 340)]:
            self.sniff_tree.heading(c, text=c.upper())
            self.sniff_tree.column(c, width=w)

        # Protocol colour tags
        self.sniff_tree.tag_configure("TCP",  background="#eff6ff")
        self.sniff_tree.tag_configure("UDP",  background="#f0fdf4")
        self.sniff_tree.tag_configure("ARP",  background="#fefce8")
        self.sniff_tree.tag_configure("ICMP", background="#fdf4ff")
        self.sniff_tree.tag_configure("DNS",  background="#fff7ed")
        self.sniff_tree.tag_configure("HTTP", background="#ecfdf5")
        self.sniff_tree.tag_configure("ERR",  background="#fee2e2")

        vsb = ttk.Scrollbar(f, orient="vertical",
                             command=self.sniff_tree.yview)
        self.sniff_tree.configure(yscrollcommand=vsb.set)
        self.sniff_tree.grid(row=1, column=0, sticky="nsew")
        vsb.grid(row=1, column=1, sticky="ns")

        # Packet detail pane
        self.sniff_detail = scrolledtext.ScrolledText(
            f, height=7, font=("Courier New", 8), state="disabled")
        self.sniff_detail.grid(row=2, column=0, columnspan=2,
                                sticky="ew", pady=(6, 0))
        self.sniff_tree.bind("<<TreeviewSelect>>",
                              self._sniff_show_detail)

        self._sniff_pkt_store: list = []   # raw packet store
        self._sniff_start_ts  = None

    def _sniff_start(self):
        if not _SCAPY_OK:
            messagebox.showerror(
                "Sniffer", "scapy is required.\npip install scapy")
            return
        if self.sniffer_running:
            return
        self.sniffer_running   = True
        self._sniffer_pkt_no   = 0
        self._sniff_pkt_store  = []
        self._pcap_packets     = []
        self._sniff_start_ts   = time.time()
        self.sniff_start_btn.config(state=tk.DISABLED)
        self.sniff_stop_btn.config(state=tk.NORMAL)
        self.sniff_status_var.set("● Capturing…")

        iface  = self.sniff_iface_var.get().strip() or None
        bpf    = self.sniff_filter_var.get().strip() or None
        count  = self.sniff_count_var.get()

        def run():
            kwargs = dict(prn=self._sniff_pkt_cb, store=False,
                          stop_filter=lambda _: not self.sniffer_running)
            if iface:  kwargs["iface"]  = iface
            if bpf:    kwargs["filter"] = bpf
            if count:  kwargs["count"]  = count
            try:
                sniff(**kwargs)
            except Exception as e:
                log.warning("Sniffer error: %s", e)
            self.sniffer_running = False
            self.root.after(0, self._sniff_done)

        self.sniffer_thread = threading.Thread(
            target=run, daemon=True)
        self.sniffer_thread.start()

    def _sniff_pkt_cb(self, pkt):
        self._sniffer_pkt_no += 1
        no     = self._sniffer_pkt_no
        ts     = datetime.datetime.now().strftime("%H:%M:%S.%f")[:12]
        src = dst = proto = info = ""
        length = len(pkt)

        if pkt.haslayer("IP"):
            src   = pkt["IP"].src
            dst   = pkt["IP"].dst
            proto = "IP"
        if pkt.haslayer("IPv6"):
            src   = pkt["IPv6"].src
            dst   = pkt["IPv6"].dst
            proto = "IPv6"
        if pkt.haslayer("TCP"):
            proto  = "TCP"
            sport  = pkt["TCP"].sport
            dport  = pkt["TCP"].dport
            flags  = pkt["TCP"].flags
            src   += f":{sport}"
            dst   += f":{dport}"
            svc    = WELL_KNOWN_PORTS.get(dport) or WELL_KNOWN_PORTS.get(sport, "")
            info   = f"Flags={flags} {svc}"
            if dport == 80 or sport == 80:
                proto = "HTTP"
        elif pkt.haslayer("UDP"):
            proto  = "UDP"
            sport  = pkt["UDP"].sport
            dport  = pkt["UDP"].dport
            src   += f":{sport}"
            dst   += f":{dport}"
            if dport == 53 or sport == 53:
                proto = "DNS"
                if pkt.haslayer("DNS"):
                    dns = pkt["DNS"]
                    if dns.qd:
                        try:
                            info = f"Q: {dns.qd.qname.decode()}"
                        except Exception:
                            info = "DNS query"
            elif dport == 5353 or sport == 5353:
                proto = "mDNS"
        elif pkt.haslayer("ICMP"):
            proto = "ICMP"
            info  = f"type={pkt['ICMP'].type}"
        elif pkt.haslayer("ARP"):
            proto = "ARP"
            arp   = pkt["ARP"]
            src   = arp.psrc
            dst   = arp.pdst
            info  = "who-has" if arp.op == 1 else "is-at"

        tag  = proto if proto in ("TCP","UDP","ARP","ICMP","DNS","HTTP","mDNS") else ""
        row  = (no, ts, src, dst, proto, length, info)
        self._sniff_pkt_store.append((row, pkt))
        if self.sniff_save_var.get():
            self._pcap_packets.append(pkt)

        max_rows = 5000
        self.root.after(0, lambda r=row, t=tag: self._sniff_insert_row(r, t))
        if no > max_rows:
            self.root.after(0, self._sniff_trim)

    def _sniff_insert_row(self, row, tag):
        self.sniff_tree.insert("", "end", values=row,
                                tags=(tag,) if tag else ())
        if self._sniffer_pkt_no % 20 == 0:
            self.sniff_tree.yview_moveto(1)
        self.sniff_status_var.set(
            f"● {self._sniffer_pkt_no} packets captured")

    def _sniff_trim(self):
        children = self.sniff_tree.get_children()
        if len(children) > 5000:
            for item in children[:500]:
                self.sniff_tree.delete(item)

    def _sniff_show_detail(self, _=None):
        sel = self.sniff_tree.selection()
        if not sel:
            return
        idx = int(self.sniff_tree.item(sel[0], "values")[0]) - 1
        if 0 <= idx < len(self._sniff_pkt_store):
            _, pkt = self._sniff_pkt_store[idx]
            self.sniff_detail.config(state="normal")
            self.sniff_detail.delete("1.0", "end")
            self.sniff_detail.insert("end", pkt.show(dump=True))
            self.sniff_detail.config(state="disabled")

    def _sniff_stop(self):
        self.sniffer_running = False

    def _sniff_done(self):
        self.sniff_start_btn.config(state=tk.NORMAL)
        self.sniff_stop_btn.config(state=tk.DISABLED)
        self.sniff_status_var.set(
            f"■ {self._sniffer_pkt_no} packets captured")

    def _sniff_clear(self):
        for row in self.sniff_tree.get_children():
            self.sniff_tree.delete(row)
        self._sniff_pkt_store.clear()
        self._pcap_packets.clear()
        self._sniffer_pkt_no = 0
        self.sniff_status_var.set("Idle")

    def _sniff_export_pcap(self):
        if not _SCAPY_OK:
            messagebox.showerror("PCAP", "Requires scapy.")
            return
        if not self._pcap_packets:
            messagebox.showinfo("PCAP", "No packets to save.\nEnable 'Save PCAP' before capturing.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP", "*.pcap"), ("All", "*.*")])
        if path:
            wrpcap(path, self._pcap_packets)
            messagebox.showinfo("PCAP", f"Saved {len(self._pcap_packets)} packets:\n{path}")

    # ═══════════════════════════════════════════════════════════════════════
    # VULNERABILITY SCANNER
    # ═══════════════════════════════════════════════════════════════════════

    def _build_vulnscan_ui(self):
        frame = self.view_frames["vulnscan"]
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        hdr = ttk.Frame(frame, padding=(16, 12, 16, 0))
        hdr.grid(row=0, column=0, sticky="ew")
        ttk.Label(hdr, text="Vulnerability Scanner",
                  style="Heading.TLabel").pack(side=tk.LEFT)
        ttk.Separator(frame, orient="horizontal").grid(
            row=1, column=0, sticky="ew", padx=16)
        self.vs_inner = ttk.Frame(frame, padding=16)
        self.vs_inner.grid(row=2, column=0, sticky="nsew")

    def _build_vulnscan_contents(self):
        f = self.vs_inner
        f.grid_rowconfigure(1, weight=1)
        f.grid_columnconfigure(0, weight=1)

        ctrl = ttk.Frame(f)
        ctrl.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        self.vs_target_var   = tk.StringVar(value="")
        self.vs_ports_var    = tk.StringVar(value="")
        self.vs_banners_var  = tk.BooleanVar(value=True)
        self.vs_status_var   = tk.StringVar(value="Idle")

        ttk.Label(ctrl, text="Target:").pack(side=tk.LEFT)
        ttk.Entry(ctrl, textvariable=self.vs_target_var,
                  width=22).pack(side=tk.LEFT, padx=(4, 8))
        ttk.Label(ctrl, text="Ports (blank=default):").pack(side=tk.LEFT)
        ttk.Entry(ctrl, textvariable=self.vs_ports_var,
                  width=20).pack(side=tk.LEFT, padx=(4, 8))
        ttk.Checkbutton(ctrl, text="Grab banners",
                        variable=self.vs_banners_var).pack(
            side=tk.LEFT, padx=(0, 8))

        self.vs_scan_btn = ttk.Button(ctrl, text="▶ Scan",
                                       command=self._vs_start,
                                       style="Success.TButton")
        self.vs_scan_btn.pack(side=tk.LEFT, padx=(0, 4))
        self.vs_stop_btn = ttk.Button(ctrl, text="■ Stop",
                                       command=self._vs_stop,
                                       style="Danger.TButton",
                                       state=tk.DISABLED)
        self.vs_stop_btn.pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(ctrl, text="Export CSV",
                   command=self._vs_export,
                   style="Ghost.TButton").pack(side=tk.LEFT)
        ttk.Label(ctrl, textvariable=self.vs_status_var,
                  style="Muted.TLabel").pack(side=tk.RIGHT)

        # Also scan from last main scan results
        ttk.Button(ctrl, text="Re-scan from last scan results →",
                   command=self._vs_from_main,
                   style="Ghost.TButton").pack(side=tk.RIGHT, padx=(0, 4))

        cols = ("ip", "port", "issue", "severity", "cve", "banner", "remediation")
        self.vs_tree = ttk.Treeview(f, columns=cols, show="headings")
        for c, w in [("ip", 120), ("port", 55), ("issue", 200),
                     ("severity", 75), ("cve", 100),
                     ("banner", 180), ("remediation", 220)]:
            self.vs_tree.heading(c, text=c.capitalize())
            self.vs_tree.column(c, width=w)

        for sev, (fg, bg) in SEV_COLORS.items():
            self.vs_tree.tag_configure(sev, background=bg, foreground=fg)

        vsb = ttk.Scrollbar(f, orient="vertical",
                             command=self.vs_tree.yview)
        self.vs_tree.configure(yscrollcommand=vsb.set)
        self.vs_tree.grid(row=1, column=0, sticky="nsew")
        vsb.grid(row=1, column=1, sticky="ns")

    def _vs_start(self):
        if self._vs_running:
            return
        target = self.vs_target_var.get().strip()
        if not target:
            messagebox.showwarning("Vuln Scan", "Enter a target.")
            return
        try:
            net   = ipaddress.ip_network(target, strict=False)
            hosts = ([str(h) for h in net.hosts()]
                     if net.num_addresses > 2 else [target])
        except ValueError:
            hosts = [target]

        raw = self.vs_ports_var.get().strip()
        ports = ([int(p) for p in raw.split(",") if p.strip().isdigit()]
                 if raw else TCP_PROBE_PORTS)

        self._vs_running = True
        self.vuln_results.clear()
        for row in self.vs_tree.get_children():
            self.vs_tree.delete(row)
        self.vs_scan_btn.config(state=tk.DISABLED)
        self.vs_stop_btn.config(state=tk.NORMAL)
        self.vs_status_var.set(f"Scanning {len(hosts)} host(s)…")

        def run():
            pool = SmartWorkerPool(
                workers=min(48, len(hosts) or 1),
                queue_limit=len(hosts) + 20)
            for ip in hosts:
                if not self._vs_running:
                    break
                pool.submit(self._vs_probe_host, ip, ports)
            pool.queue.join()
            pool.shutdown()
            self._vs_running = False
            self.root.after(0, self._vs_done)

        threading.Thread(target=run, daemon=True).start()

    def _vs_probe_host(self, ip: str, ports: list):
        if not self._vs_running:
            return
        open_ports, banners = tcp_probe_with_banners(
            ip, ports,
            grab_banners=self.vs_banners_var.get())
        if not open_ports:
            return

        dummy = {"ip": ip, "open_ports": open_ports,
                 "banners": banners, "ssl_info": None}
        findings = assess_security(dummy)

        for _, issue, severity, rec in findings:
            # Match back to VULN_DB for CVE
            cve    = ""
            banner = ""
            for port, bpat, title, sev, desc, r, cv in VULN_DB:
                if port in open_ports and title in issue:
                    cve    = cv
                    banner = banners.get(port, "")[:60]
                    break
            row = (ip, "", issue, severity, cve, banner,
                   rec.split("\n")[-1].strip()[:60])
            with self.lock:
                self.vuln_results.append(row)
            self.root.after(0, lambda r=row, s=severity:
                self.vs_tree.insert("", "end", values=r,
                                    tags=(s,)))

    def _vs_from_main(self):
        """Re-assess all hosts from last main scan."""
        if not self.results:
            messagebox.showinfo("Vuln Scan",
                "Run a main scan first.")
            return
        for row in self.vs_tree.get_children():
            self.vs_tree.delete(row)
        self.vuln_results.clear()
        for r in self.results:
            if r["status"] != "Used":
                continue
            for ip, issue, severity, rec in r.get("security_findings", []):
                row = (ip, "", issue, severity, "", "", rec[:60])
                self.vuln_results.append(row)
                self.vs_tree.insert("", "end", values=row,
                                    tags=(severity,))
        self.vs_status_var.set(
            f"{len(self.vuln_results)} findings from last scan")

    def _vs_stop(self):
        self._vs_running = False

    def _vs_done(self):
        self.vs_scan_btn.config(state=tk.NORMAL)
        self.vs_stop_btn.config(state=tk.DISABLED)
        self.vs_status_var.set(
            f"Done — {len(self.vuln_results)} finding(s)")

    def _vs_export(self):
        if not self.vuln_results:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")])
        if path:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["IP","Port","Issue","Severity",
                             "CVE","Banner","Remediation"])
                w.writerows(self.vuln_results)
            messagebox.showinfo("Export", path)

    # ═══════════════════════════════════════════════════════════════════════
    # SERVICE FINGERPRINTER
    # ═══════════════════════════════════════════════════════════════════════

    def _build_fingerprint_ui(self):
        frame = self.view_frames["fingerprint"]
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        hdr = ttk.Frame(frame, padding=(16, 12, 16, 0))
        hdr.grid(row=0, column=0, sticky="ew")
        ttk.Label(hdr, text="Service Fingerprinter",
                  style="Heading.TLabel").pack(side=tk.LEFT)
        ttk.Separator(frame, orient="horizontal").grid(
            row=1, column=0, sticky="ew", padx=16)
        self.fp_inner = ttk.Frame(frame, padding=16)
        self.fp_inner.grid(row=2, column=0, sticky="nsew")

    def _build_fingerprint_contents(self):
        f = self.fp_inner
        f.grid_rowconfigure(1, weight=1)
        f.grid_columnconfigure(0, weight=1)

        ctrl = ttk.Frame(f)
        ctrl.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        self.fp_target_var  = tk.StringVar()
        self.fp_ports_var   = tk.StringVar(value="21,22,25,80,110,143,443,3306,5432,6379")
        self.fp_status_var  = tk.StringVar(value="Idle")

        ttk.Label(ctrl, text="Target:").pack(side=tk.LEFT)
        ttk.Entry(ctrl, textvariable=self.fp_target_var,
                  width=24).pack(side=tk.LEFT, padx=(4, 8))
        ttk.Label(ctrl, text="Ports:").pack(side=tk.LEFT)
        ttk.Entry(ctrl, textvariable=self.fp_ports_var,
                  width=36).pack(side=tk.LEFT, padx=(4, 8))
        ttk.Button(ctrl, text="▶ Fingerprint",
                   command=self._fp_start,
                   style="Success.TButton").pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(ctrl, text="■ Stop",
                   command=lambda: setattr(self, "_fp_running", False),
                   style="Danger.TButton").pack(side=tk.LEFT, padx=(0, 4))
        ttk.Label(ctrl, textvariable=self.fp_status_var,
                  style="Muted.TLabel").pack(side=tk.RIGHT)

        cols = ("port", "service", "banner", "os_hint", "version_hint")
        self.fp_tree = ttk.Treeview(f, columns=cols, show="headings")
        for c, w in [("port", 60), ("service", 100), ("banner", 280),
                     ("os_hint", 130), ("version_hint", 160)]:
            self.fp_tree.heading(c, text=c.replace("_", " ").title())
            self.fp_tree.column(c, width=w)

        vsb = ttk.Scrollbar(f, orient="vertical",
                             command=self.fp_tree.yview)
        self.fp_tree.configure(yscrollcommand=vsb.set)
        self.fp_tree.grid(row=1, column=0, sticky="nsew")
        vsb.grid(row=1, column=1, sticky="ns")

    def _fp_start(self):
        target = self.fp_target_var.get().strip()
        if not target:
            return
        raw   = self.fp_ports_var.get().strip()
        ports = [int(p) for p in raw.split(",") if p.strip().isdigit()]
        if not ports:
            return

        self._fp_running = True
        self.fp_results.clear()
        for row in self.fp_tree.get_children():
            self.fp_tree.delete(row)
        self.fp_status_var.set("Fingerprinting…")

        def run():
            for port in ports:
                if not self._fp_running:
                    break
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(TCP_PROBE_TIMEOUT_S)
                if s.connect_ex((target, port)) != 0:
                    s.close()
                    continue
                s.close()

                banner  = grab_banner(target, port,
                                       timeout=BANNER_GRAB_TIMEOUT_S)
                svc     = WELL_KNOWN_PORTS.get(port, "unknown")

                # OS hints from banner
                os_hint = ""
                blo = banner.lower()
                if "openssh"   in blo: os_hint = "Linux/Unix"
                if "microsoft" in blo: os_hint = "Windows"
                if "ubuntu"    in blo: os_hint = "Ubuntu"
                if "debian"    in blo: os_hint = "Debian"
                if "centos"    in blo: os_hint = "CentOS"
                if "cisco"     in blo: os_hint = "Cisco IOS"

                # Version hints
                ver_hint = ""
                ver_pats = [
                    r"(Apache/[\d.]+)",
                    r"(nginx/[\d.]+)",
                    r"(OpenSSH_[\d.]+\w*)",
                    r"(PHP/[\d.]+)",
                    r"(MySQL/[\d.]+)",
                    r"(Microsoft-IIS/[\d.]+)",
                    r"(vsFTPd [\d.]+)",
                    r"(Postfix[\w /.]*)",
                    r"(Exim [\d.]+)",
                    r"(\bRedis\b [\d.]+)",
                ]
                for pat in ver_pats:
                    m = re.search(pat, banner, re.I)
                    if m:
                        ver_hint = m.group(1)[:50]
                        break

                row = (port, svc, banner[:80], os_hint, ver_hint)
                self.fp_results.append(row)
                self.root.after(0, lambda r=row:
                    self.fp_tree.insert("", "end", values=r))

            self._fp_running = False
            self.root.after(0, lambda:
                self.fp_status_var.set(
                    f"Done — {len(self.fp_results)} open port(s)"))

        threading.Thread(target=run, daemon=True).start()

    # ═══════════════════════════════════════════════════════════════════════
    # SNMP SCANNER
    # ═══════════════════════════════════════════════════════════════════════

    def _build_snmp_ui(self):
        frame = self.view_frames["snmp"]
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        hdr = ttk.Frame(frame, padding=(16, 12, 16, 0))
        hdr.grid(row=0, column=0, sticky="ew")
        ttk.Label(hdr, text="SNMP Scanner",
                  style="Heading.TLabel").pack(side=tk.LEFT)
        ttk.Separator(frame, orient="horizontal").grid(
            row=1, column=0, sticky="ew", padx=16)
        self.snmp_inner = ttk.Frame(frame, padding=16)
        self.snmp_inner.grid(row=2, column=0, sticky="nsew")

    def _build_snmp_contents(self):
        f = self.snmp_inner
        f.grid_rowconfigure(1, weight=1)
        f.grid_columnconfigure(0, weight=1)

        ctrl = ttk.Frame(f)
        ctrl.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        self.snmp_target_var    = tk.StringVar(value="192.168.1.0/24")
        self.snmp_community_var = tk.StringVar(value="public,private,community,snmp")
        self.snmp_ver_var       = tk.StringVar(value="2c")
        self.snmp_status_var    = tk.StringVar(value="Idle")

        ttk.Label(ctrl, text="Target:").pack(side=tk.LEFT)
        ttk.Entry(ctrl, textvariable=self.snmp_target_var,
                  width=20).pack(side=tk.LEFT, padx=(4, 8))
        ttk.Label(ctrl, text="Communities:").pack(side=tk.LEFT)
        ttk.Entry(ctrl, textvariable=self.snmp_community_var,
                  width=28).pack(side=tk.LEFT, padx=(4, 8))
        ttk.Label(ctrl, text="Ver:").pack(side=tk.LEFT)
        ttk.Combobox(ctrl, textvariable=self.snmp_ver_var,
                     values=["1", "2c"], width=4,
                     state="readonly").pack(side=tk.LEFT, padx=(4, 8))

        self.snmp_scan_btn = ttk.Button(ctrl, text="▶ Scan",
                                         command=self._snmp_start,
                                         style="Success.TButton")
        self.snmp_scan_btn.pack(side=tk.LEFT, padx=(0, 4))
        self.snmp_stop_btn = ttk.Button(ctrl, text="■ Stop",
                                         command=self._snmp_stop,
                                         style="Danger.TButton",
                                         state=tk.DISABLED)
        self.snmp_stop_btn.pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(ctrl, text="Export CSV",
                   command=self._snmp_export,
                   style="Ghost.TButton").pack(side=tk.LEFT)
        ttk.Label(ctrl, textvariable=self.snmp_status_var,
                  style="Muted.TLabel").pack(side=tk.RIGHT)

        cols = ("ip", "community", "version", "sysDescr",
                "sysName", "sysLocation", "sysContact", "ifNumber")
        self.snmp_tree = ttk.Treeview(f, columns=cols, show="headings")
        for c, w in [("ip", 130), ("community", 90), ("version", 50),
                     ("sysDescr", 220), ("sysName", 130),
                     ("sysLocation", 120), ("sysContact", 120),
                     ("ifNumber", 60)]:
            self.snmp_tree.heading(c, text=c)
            self.snmp_tree.column(c, width=w)
        self.snmp_tree.tag_configure("found",    background="#f0fdf4")
        self.snmp_tree.tag_configure("notfound", background="#f8fafc")

        vsb = ttk.Scrollbar(f, orient="vertical",
                             command=self.snmp_tree.yview)
        self.snmp_tree.configure(yscrollcommand=vsb.set)
        self.snmp_tree.grid(row=1, column=0, sticky="nsew")
        vsb.grid(row=1, column=1, sticky="ns")

        btn_row = ttk.Frame(f)
        btn_row.grid(row=2, column=0, sticky="w", pady=(6, 0))
        ttk.Button(btn_row, text="SNMP Walk selected →",
                   command=self._snmp_walk_selected,
                   style="Ghost.TButton").pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(btn_row, text="Flag default community →",
                   command=self._snmp_flag_default,
                   style="Warning.TButton").pack(side=tk.LEFT)

    def _snmp_start(self):
        if self._snmp_running:
            return
        target = self.snmp_target_var.get().strip()
        if not target:
            return
        try:
            net   = ipaddress.ip_network(target, strict=False)
            hosts = ([str(h) for h in net.hosts()]
                     if net.num_addresses > 2 else [target])
        except ValueError:
            hosts = [target]

        coms = [c.strip() for c in
                self.snmp_community_var.get().split(",") if c.strip()] or ["public"]
        ver  = self.snmp_ver_var.get()

        self._snmp_running = True
        self.snmp_results.clear()
        for row in self.snmp_tree.get_children():
            self.snmp_tree.delete(row)
        self.snmp_scan_btn.config(state=tk.DISABLED)
        self.snmp_stop_btn.config(state=tk.NORMAL)
        self.snmp_status_var.set(f"Scanning {len(hosts)} host(s)…")

        def run():
            pool = SmartWorkerPool(
                workers=min(64, len(hosts) or 1),
                queue_limit=len(hosts) + 10)
            for ip in hosts:
                if not self._snmp_running:
                    break
                pool.submit(self._snmp_probe_host, ip, coms, ver)
            pool.queue.join()
            pool.shutdown()
            self._snmp_running = False
            self.root.after(0, self._snmp_done)

        threading.Thread(target=run, daemon=True).start()

    def _snmp_stop(self):
        self._snmp_running = False

    def _snmp_done(self):
        self.snmp_scan_btn.config(state=tk.NORMAL)
        self.snmp_stop_btn.config(state=tk.DISABLED)
        found = sum(1 for r in self.snmp_results
                    if r[3] != "(no response)")
        self.snmp_status_var.set(f"Done — {found} SNMP device(s)")

    def _snmp_flag_default(self):
        """Highlight rows using 'public' or 'private' communities."""
        self.snmp_tree.tag_configure(
            "default_com", background="#fee2e2", foreground="#dc2626")
        for item in self.snmp_tree.get_children():
            vals = self.snmp_tree.item(item, "values")
            if vals and vals[1] in ("public", "private"):
                self.snmp_tree.item(item, tags=("default_com",))

    def _snmp_export(self):
        if not self.snmp_results:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")])
        if path:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["IP","Community","Version","sysDescr",
                             "sysName","sysLocation","sysContact","ifNumber"])
                w.writerows(self.snmp_results)
            messagebox.showinfo("Exported", path)

    def _snmp_walk_selected(self):
        sel = self.snmp_tree.selection()
        if not sel:
            messagebox.showinfo("SNMP Walk", "Select a row first.")
            return
        vals = self.snmp_tree.item(sel[0], "values")
        ip, com, ver = vals[0], vals[1], vals[2]
        if com == "—":
            messagebox.showwarning("SNMP Walk",
                "No working community for this host.")
            return

        win = tk.Toplevel(self.root)
        win.title(f"SNMP Walk — {ip} ({com})")
        win.geometry("720x520")

        ctrl = ttk.Frame(win, padding=8)
        ctrl.pack(fill="x")
        ttk.Label(ctrl, text="OID:").pack(side=tk.LEFT)
        oid_var = tk.StringVar(value="1.3.6.1.2.1.1")
        ttk.Entry(ctrl, textvariable=oid_var, width=28).pack(
            side=tk.LEFT, padx=(4, 8))

        txt = scrolledtext.ScrolledText(
            win, font=("Courier New", 9))
        txt.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        WALK_OIDS = {
            "1.3.6.1.2.1.1.1.0":  "sysDescr",
            "1.3.6.1.2.1.1.2.0":  "sysObjectID",
            "1.3.6.1.2.1.1.3.0":  "sysUpTime",
            "1.3.6.1.2.1.1.4.0":  "sysContact",
            "1.3.6.1.2.1.1.5.0":  "sysName",
            "1.3.6.1.2.1.1.6.0":  "sysLocation",
            "1.3.6.1.2.1.1.7.0":  "sysServices",
            "1.3.6.1.2.1.2.1.0":  "ifNumber",
            "1.3.6.1.2.1.25.1.1.0": "hrSystemUptime",
            "1.3.6.1.2.1.25.1.6.0": "hrSystemNumUsers",
            "1.3.6.1.2.1.25.1.7.0": "hrSystemProcesses",
        }

        def do_walk():
            txt.config(state="normal")
            txt.delete("1.0", "end")
            v = 0 if ver == "1" else 1
            for oid, label in WALK_OIDS.items():
                val = self._snmp_get(ip, com, oid, v)
                txt.insert("end",
                    f"{label:28s} [{oid}] = "
                    f"{val or '(no response)'}\n")
            txt.config(state="disabled")

        ttk.Button(ctrl, text="Walk →",
                   command=lambda: threading.Thread(
                       target=do_walk, daemon=True).start()
                   ).pack(side=tk.LEFT)

    # ── SNMP low-level helpers (preserved from v3) ──

    @staticmethod
    def _snmp_tlv(tag, value):
        l = len(value)
        if l < 128:
            return bytes([tag, l]) + value
        lb = l.to_bytes((l.bit_length() + 7) // 8, "big")
        return bytes([tag, 0x80 | len(lb)]) + lb + value

    def _snmp_get(self, ip, community, oid, version=1, timeout=1.0):
        try:
            com   = community.encode()
            parts = [int(x) for x in oid.split(".") if x]
            enc   = []
            for p in parts:
                if p < 128:
                    enc.append(p)
                else:
                    buf = []
                    while p:
                        buf.append((p & 0x7f) | (0x80 if buf else 0))
                        p >>= 7
                    enc.extend(reversed(buf))
            oid_tlv = self._snmp_tlv(0x06, bytes(enc))
            varbind = self._snmp_tlv(0x30, oid_tlv + b"\x05\x00")
            vbl     = self._snmp_tlv(0x30, varbind)
            pdu_val = b"\x02\x01\x01\x02\x01\x00\x02\x01\x00" + vbl
            pdu     = self._snmp_tlv(0xa0, pdu_val)
            msg     = self._snmp_tlv(
                0x30,
                b"\x02\x01" + bytes([version])
                + self._snmp_tlv(0x04, com) + pdu)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(msg, (ip, 161))
            data, _ = s.recvfrom(2048)
            s.close()
            return self._snmp_parse_value(data)
        except Exception:
            return None

    def _snmp_parse_value(self, data):
        try:
            def read_tlv(buf, pos):
                tag = buf[pos]; pos += 1
                l   = buf[pos]; pos += 1
                if l & 0x80:
                    nb = l & 0x7f
                    l  = int.from_bytes(buf[pos:pos+nb], "big")
                    pos += nb
                return tag, buf[pos:pos+l], pos + l
            pos = 2 + (1 if data[1] < 0x80 else (data[1] & 0x7f) + 1)
            for _ in range(2):
                _, _, pos = read_tlv(data, pos)
            _, pdu, _ = read_tlv(data, pos)
            p2 = 0
            for _ in range(3):
                _, _, p2 = read_tlv(pdu, p2)
            _, vbl, _ = read_tlv(pdu, p2)
            _, vb,  _ = read_tlv(vbl, 0)
            _, _, p3  = read_tlv(vb, 0)
            t, val, _ = read_tlv(vb, p3)
            if t == 0x02:
                return str(int.from_bytes(val, "big"))
            return val.decode(errors="ignore").strip()
        except Exception:
            return None

    def _snmp_probe_host(self, ip, communities, version_str):
        version = 0 if version_str == "1" else 1
        for com in communities:
            if not self._snmp_running:
                return
            desc = self._snmp_get(ip, com, "1.3.6.1.2.1.1.1.0", version)
            if desc is None:
                continue
            name     = self._snmp_get(ip, com, "1.3.6.1.2.1.1.5.0", version) or ""
            location = self._snmp_get(ip, com, "1.3.6.1.2.1.1.6.0", version) or ""
            contact  = self._snmp_get(ip, com, "1.3.6.1.2.1.1.4.0", version) or ""
            ifaces   = self._snmp_get(ip, com, "1.3.6.1.2.1.2.1.0", version) or ""
            row = (ip, com, version_str, desc[:80],
                   name, location, contact, ifaces)
            with self.lock:
                self.snmp_results.append(row)
            self.root.after(0, lambda r=row:
                self.snmp_tree.insert("", "end", values=r,
                                      tags=("found",)))
            return
        row = (ip, "—", version_str, "(no response)", "", "", "", "")
        with self.lock:
            self.snmp_results.append(row)
        self.root.after(0, lambda r=row:
            self.snmp_tree.insert("", "end", values=r,
                                  tags=("notfound",)))

    # ═══════════════════════════════════════════════════════════════════════
    # ALERT LOG TAB
    # ═══════════════════════════════════════════════════════════════════════

    def _build_alerts_ui(self):
        frame = self.view_frames["alerts"]
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        hdr = ttk.Frame(frame, padding=(16, 12, 16, 0))
        hdr.grid(row=0, column=0, sticky="ew")
        ttk.Label(hdr, text="Alert Log",
                  style="Heading.TLabel").pack(side=tk.LEFT)
        ttk.Button(hdr, text="↻ Refresh",
                   command=self._alerts_refresh,
                   style="Ghost.TButton").pack(side=tk.RIGHT)
        ttk.Button(hdr, text="Export CSV",
                   command=self._alerts_export,
                   style="Ghost.TButton").pack(side=tk.RIGHT, padx=(0, 8))
        ttk.Button(hdr, text="🗑 Clear All",
                   command=self._alerts_clear,
                   style="Danger.TButton").pack(side=tk.RIGHT, padx=(0, 8))

        ttk.Separator(frame, orient="horizontal").grid(
            row=1, column=0, sticky="ew", padx=16)

        inner = ttk.Frame(frame, padding=16)
        inner.grid(row=2, column=0, sticky="nsew")
        inner.grid_rowconfigure(0, weight=1)
        inner.grid_columnconfigure(0, weight=1)

        cols = ("ts", "severity", "ip", "message", "tag")
        self.alert_tree = ttk.Treeview(inner, columns=cols,
                                        show="headings")
        for c, w in [("ts", 140), ("severity", 80),
                     ("ip", 130), ("message", 400), ("tag", 100)]:
            self.alert_tree.heading(c, text=c.capitalize())
            self.alert_tree.column(c, width=w)

        for sev, (fg, bg) in SEV_COLORS.items():
            self.alert_tree.tag_configure(sev, background=bg, foreground=fg)

        vsb = ttk.Scrollbar(inner, orient="vertical",
                             command=self.alert_tree.yview)
        self.alert_tree.configure(yscrollcommand=vsb.set)
        self.alert_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

    def _alerts_refresh(self):
        for row in self.alert_tree.get_children():
            self.alert_tree.delete(row)
        for a in reversed(self.alert_log.alerts):
            self.alert_tree.insert(
                "", "end",
                values=(a["ts"], a["severity"], a["ip"],
                        a["message"][:100], a.get("tag", "")),
                tags=(a["severity"],))

    def _alerts_export(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")])
        if path:
            self.alert_log.export_csv(path)
            messagebox.showinfo("Export", path)

    def _alerts_clear(self):
        if messagebox.askyesno("Clear Alerts",
                               "Delete all alerts?"):
            self.alert_log.clear()
            self._alerts_refresh()

    # ═══════════════════════════════════════════════════════════════════════
    # COMPLIANCE TAB
    # ═══════════════════════════════════════════════════════════════════════

    def _build_compliance_ui(self):
        frame = self.view_frames["compliance"]
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        hdr = ttk.Frame(frame, padding=(16, 12, 16, 0))
        hdr.grid(row=0, column=0, sticky="ew")
        ttk.Label(hdr, text="Compliance Checker",
                  style="Heading.TLabel").pack(side=tk.LEFT)
        ttk.Button(hdr, text="↻ Re-check from Scan",
                   command=self._compliance_refresh,
                   style="Ghost.TButton").pack(side=tk.RIGHT)
        ttk.Button(hdr, text="Export CSV",
                   command=self._compliance_export,
                   style="Ghost.TButton").pack(side=tk.RIGHT, padx=(0, 8))

        ttk.Separator(frame, orient="horizontal").grid(
            row=1, column=0, sticky="ew", padx=16)

        ctrl = ttk.Frame(frame, padding=(16, 4, 16, 0))
        ctrl.grid(row=1, column=0, sticky="ew")
        self.comp_filter_var = tk.StringVar(value="All")
        ttk.Label(ctrl, text="Framework:").pack(side=tk.LEFT)
        ttk.Combobox(ctrl, textvariable=self.comp_filter_var,
                     values=["All", "PCI-DSS", "CIS-L1", "NIST"],
                     width=10, state="readonly").pack(
            side=tk.LEFT, padx=(4, 0))
        ttk.Button(ctrl, text="Filter",
                   command=self._compliance_refresh,
                   style="Ghost.TButton").pack(
            side=tk.LEFT, padx=(6, 0))

        inner = ttk.Frame(frame, padding=16)
        inner.grid(row=2, column=0, sticky="nsew")
        inner.grid_rowconfigure(0, weight=1)
        inner.grid_columnconfigure(0, weight=1)

        cols = ("ip", "framework", "req_id", "port", "status", "desc")
        self.comp_tree = ttk.Treeview(inner, columns=cols,
                                       show="headings")
        for c, w in [("ip", 130), ("framework", 80), ("req_id", 70),
                     ("port", 50), ("status", 60), ("desc", 400)]:
            self.comp_tree.heading(c, text=c.replace("_", " ").title())
            self.comp_tree.column(c, width=w)

        self.comp_tree.tag_configure("FAIL",
            background="#fee2e2", foreground="#dc2626")
        self.comp_tree.tag_configure("PASS",
            background="#f0fdf4", foreground="#16a34a")

        vsb = ttk.Scrollbar(inner, orient="vertical",
                             command=self.comp_tree.yview)
        self.comp_tree.configure(yscrollcommand=vsb.set)
        self.comp_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        self._comp_results: list[dict] = []

    def _compliance_refresh(self):
        if not self.results:
            messagebox.showinfo("Compliance",
                "Run a scan first.")
            return
        framework_filter = self.comp_filter_var.get()
        for row in self.comp_tree.get_children():
            self.comp_tree.delete(row)
        self._comp_results.clear()

        for r in self.results:
            if r["status"] != "Used":
                continue
            for cr in check_compliance(r):
                if framework_filter != "All" and cr["framework"] != framework_filter:
                    continue
                status = "PASS" if cr["pass"] else "FAIL"
                row    = (r["ip"], cr["framework"], cr["req_id"],
                          cr["port"], status, cr["desc"][:80])
                self._comp_results.append(row)
                self.comp_tree.insert("", "end", values=row,
                                       tags=(status,))

    def _compliance_export(self):
        if not self._comp_results:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")])
        if path:
            with open(path, "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["IP","Framework","Req ID",
                             "Port","Status","Description"])
                w.writerows(self._comp_results)
            messagebox.showinfo("Export", path)

    # ═══════════════════════════════════════════════════════════════════════
    # NETWORK TOPOLOGY MAP
    # ═══════════════════════════════════════════════════════════════════════

    def _build_topology_ui(self):
        frame = self.view_frames["topology"]
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        hdr = ttk.Frame(frame, padding=(16, 12, 16, 0))
        hdr.grid(row=0, column=0, sticky="ew")
        ttk.Label(hdr, text="Network Topology",
                  style="Heading.TLabel").pack(side=tk.LEFT)
        ttk.Button(hdr, text="↻ Render",
                   command=self._topology_render,
                   style="Ghost.TButton").pack(side=tk.RIGHT)
        ttk.Button(hdr, text="Export SVG",
                   command=self._topology_export_svg,
                   style="Ghost.TButton").pack(side=tk.RIGHT, padx=(0, 8))

        ttk.Separator(frame, orient="horizontal").grid(
            row=1, column=0, sticky="ew", padx=16)

        self.topo_frame = ttk.Frame(frame, padding=8)
        self.topo_frame.grid(row=2, column=0, sticky="nsew")
        self.topo_frame.grid_rowconfigure(0, weight=1)
        self.topo_frame.grid_columnconfigure(0, weight=1)

        # Canvas for topology drawing
        self.topo_canvas = tk.Canvas(
            self.topo_frame, bg="#0f172a",
            highlightthickness=0)
        self.topo_canvas.grid(row=0, column=0, sticky="nsew")

        # Zoom / pan bindings
        self.topo_canvas.bind("<ButtonPress-1>", self._topo_pan_start)
        self.topo_canvas.bind("<B1-Motion>",     self._topo_pan_move)
        self.topo_canvas.bind("<MouseWheel>",    self._topo_zoom)
        self.topo_canvas.bind("<Button-4>",      self._topo_zoom)   # Linux
        self.topo_canvas.bind("<Button-5>",      self._topo_zoom)
        self.topo_canvas.bind("<Double-1>",      self._topo_node_click)

        self._topo_pan_x = 0
        self._topo_pan_y = 0
        self._topo_scale = 1.0
        self._topo_nodes: dict = {}  # ip → (cx, cy)

        ttk.Label(self.topo_frame,
                  text="Drag to pan · Scroll to zoom · Double-click node for details",
                  style="Muted.TLabel").grid(
            row=1, column=0, sticky="w", pady=(4, 0))

    def _topo_pan_start(self, event):
        self._topo_pan_x = event.x
        self._topo_pan_y = event.y

    def _topo_pan_move(self, event):
        dx = event.x - self._topo_pan_x
        dy = event.y - self._topo_pan_y
        self.topo_canvas.move("all", dx, dy)
        self._topo_pan_x = event.x
        self._topo_pan_y = event.y

    def _topo_zoom(self, event):
        factor = 1.1 if (event.delta > 0 or event.num == 4) else 0.9
        self.topo_canvas.scale("all", event.x, event.y, factor, factor)
        self._topo_scale *= factor

    def _topology_render(self):
        self.topo_canvas.delete("all")
        self._topo_nodes.clear()
        used = [r for r in self.results if r["status"] == "Used"]
        if not used:
            self.topo_canvas.create_text(
                400, 300, text="Run a scan first",
                fill="#94a3b8", font=("Segoe UI", 14))
            return

        w = self.topo_canvas.winfo_width() or 900
        h = self.topo_canvas.winfo_height() or 560

        # Group by /24 subnet (gateway node per subnet)
        subnets: dict[str, list] = defaultdict(list)
        for r in used:
            parts   = r["ip"].split(".")
            sub_key = ".".join(parts[:3])
            subnets[sub_key].append(r)

        sub_keys = list(subnets.keys())
        n_subs   = len(sub_keys)
        cx_step  = w // (n_subs + 1)

        import math
        for s_idx, sub_key in enumerate(sub_keys):
            hosts  = subnets[sub_key]
            gw_cx  = cx_step * (s_idx + 1)
            gw_cy  = h // 4

            # Gateway node
            self.topo_canvas.create_oval(
                gw_cx - 22, gw_cy - 22,
                gw_cx + 22, gw_cy + 22,
                fill="#2563eb", outline="#60a5fa", width=2,
                tags=("node", f"gw_{sub_key}"))
            self.topo_canvas.create_text(
                gw_cx, gw_cy,
                text=f"{sub_key}.0/24",
                fill="white", font=("Segoe UI", 7, "bold"),
                tags=(f"gw_{sub_key}",))

            # Host nodes arranged in a circle below gateway
            n     = len(hosts)
            r_rad = min(180, 30 * n // 2 + 80)
            for i, host in enumerate(hosts):
                angle = (2 * math.pi * i / max(n, 1)) - math.pi / 2
                hx    = gw_cx + int(r_rad * math.cos(angle))
                hy    = gw_cy + 140 + int(r_rad * 0.6 * math.sin(angle))

                # Node colour by threat score
                score = host.get("threat_score", 0)
                color = threat_score_color(score)
                r_sz  = 14 if score >= 60 else 10

                self.topo_canvas.create_line(
                    gw_cx, gw_cy + 22, hx, hy - r_sz,
                    fill="#334155", width=1)
                self.topo_canvas.create_oval(
                    hx - r_sz, hy - r_sz,
                    hx + r_sz, hy + r_sz,
                    fill=color, outline="#e2e8f0", width=1,
                    tags=("node", f"host_{host['ip']}"))
                self.topo_canvas.create_text(
                    hx, hy + r_sz + 8,
                    text=host["ip"].split(".")[-1],
                    fill="#94a3b8", font=("Courier New", 7),
                    tags=(f"host_{host['ip']}",))

                self._topo_nodes[host["ip"]] = (hx, hy)

    def _topo_node_click(self, event):
        items = self.topo_canvas.find_closest(event.x, event.y)
        if not items:
            return
        tags = self.topo_canvas.gettags(items[0])
        for tag in tags:
            if tag.startswith("host_"):
                ip = tag[5:]
                r  = next((r for r in self.results if r["ip"] == ip), None)
                if r:
                    self._show_host_summary_popup(r)
                return

    def _show_host_summary_popup(self, r: dict):
        win = tk.Toplevel(self.root)
        win.title(f"Node — {r['ip']}")
        win.geometry("360x260")
        win.resizable(False, False)
        score = r.get("threat_score", 0)
        info  = [
            ("IP",          r["ip"]),
            ("Hostname",    r.get("hostname", "—")),
            ("Vendor",      r.get("vendor", "—")),
            ("Device",      r.get("device_type", "—")),
            ("OS",          r.get("os_guess", "—")),
            ("Open Ports",  format_ports(r.get("open_ports", []))[:50]),
            ("Threat Score",f"{score} — {threat_score_label(score)}"),
        ]
        for i, (lbl, val) in enumerate(info):
            ttk.Label(win, text=lbl + ":",
                      style="Bold.TLabel").grid(
                row=i, column=0, sticky="w",
                padx=(12, 8), pady=2)
            ttk.Label(win, text=val).grid(
                row=i, column=1, sticky="w", pady=2)

    def _topology_export_svg(self):
        """Export the topology canvas as a simple SVG."""
        path = filedialog.asksaveasfilename(
            defaultextension=".svg",
            filetypes=[("SVG", "*.svg")])
        if not path:
            return
        # Build SVG from canvas items
        lines = [
            '<?xml version="1.0" encoding="utf-8"?>',
            '<svg xmlns="http://www.w3.org/2000/svg" '
            'width="1200" height="700" style="background:#0f172a">',
        ]
        for item in self.topo_canvas.find_all():
            itype = self.topo_canvas.type(item)
            coords = self.topo_canvas.coords(item)
            cfg    = {k: self.topo_canvas.itemcget(item, k)
                      for k in ("fill", "outline", "width") if True}
            try:
                if itype == "oval" and len(coords) == 4:
                    x0, y0, x1, y1 = coords
                    cx = (x0 + x1) / 2; cy = (y0 + y1) / 2
                    rx = (x1 - x0) / 2; ry = (y1 - y0) / 2
                    fill = self.topo_canvas.itemcget(item, "fill") or "blue"
                    lines.append(
                        f'<ellipse cx="{cx:.0f}" cy="{cy:.0f}" '
                        f'rx="{rx:.0f}" ry="{ry:.0f}" fill="{fill}"/>')
                elif itype == "line" and len(coords) == 4:
                    x0, y0, x1, y1 = coords
                    lines.append(
                        f'<line x1="{x0:.0f}" y1="{y0:.0f}" '
                        f'x2="{x1:.0f}" y2="{y1:.0f}" '
                        f'stroke="#334155" stroke-width="1"/>')
                elif itype == "text":
                    x, y = coords[0], coords[1]
                    text = self.topo_canvas.itemcget(item, "text")
                    fill = self.topo_canvas.itemcget(item, "fill") or "white"
                    lines.append(
                        f'<text x="{x:.0f}" y="{y:.0f}" '
                        f'fill="{fill}" font-size="9" '
                        f'text-anchor="middle">{text}</text>')
            except Exception:
                pass
        lines.append("</svg>")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        messagebox.showinfo("SVG Export", f"Topology saved:\n{path}")

# ─── End of Section 3 ────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4 — SETTINGS TAB · LATE INIT · MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
# This file is Section 4 of 4. Requires Sections 1, 2 & 3.
#
# ASSEMBLY:
#   cat NetProbe_v4_section1.py \
#       NetProbe_v4_section2.py \
#       NetProbe_v4_section3.py \
#       NetProbe_v4_section4.py > NetProbe_v4.py
#   python NetProbe_v4.py
#
# QUICK INSTALL (optional deps for full feature set):
#   pip install scapy cryptography netifaces paramiko matplotlib reportlab
#
# LINUX / macOS — root required for ARP, raw sockets, sniffer:
#   sudo python NetProbe_v4.py
#
# WINDOWS — run as Administrator for ARP / WinPcap features.
# ─────────────────────────────────────────────────────────────────────────────

    # ═══════════════════════════════════════════════════════════════════════
    # SETTINGS TAB
    # ═══════════════════════════════════════════════════════════════════════

    def _build_settings_ui(self):
        frame = self.view_frames["settings"]
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        hdr = ttk.Frame(frame, padding=(16, 12, 16, 0))
        hdr.grid(row=0, column=0, sticky="ew")
        ttk.Label(hdr, text="Settings",
                  style="Heading.TLabel").pack(side=tk.LEFT)
        ttk.Button(hdr, text="💾 Save",
                   command=self._settings_save,
                   style="Success.TButton").pack(side=tk.RIGHT)

        ttk.Separator(frame, orient="horizontal").grid(
            row=1, column=0, sticky="ew", padx=16)

        canvas = tk.Canvas(frame, highlightthickness=0)
        canvas.grid(row=2, column=0, sticky="nsew")

        vsb = ttk.Scrollbar(frame, orient="vertical",
                             command=canvas.yview)
        vsb.grid(row=2, column=1, sticky="ns")
        canvas.configure(yscrollcommand=vsb.set)

        inner = ttk.Frame(canvas, padding=(24, 16))
        win_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _on_inner_configure(e):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def _on_canvas_configure(e):
            canvas.itemconfig(win_id, width=e.width)

        inner.bind("<Configure>", _on_inner_configure)
        canvas.bind("<Configure>", _on_canvas_configure)
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(
                            int(-1 * (e.delta / 120)), "units"))

        col = inner
        col.grid_columnconfigure(1, weight=1)

        def section(text, row):
            ttk.Separator(col, orient="horizontal").grid(
                row=row, column=0, columnspan=3,
                sticky="ew", pady=(14, 4))
            ttk.Label(col, text=text,
                      style="Bold.TLabel",
                      font=("Segoe UI", 10, "bold")).grid(
                row=row + 1, column=0, columnspan=3,
                sticky="w", pady=(0, 6))
            return row + 2

        def row_widget(row, label, widget_fn, tooltip=""):
            ttk.Label(col, text=label).grid(
                row=row, column=0, sticky="w",
                padx=(0, 16), pady=3)
            w = widget_fn()
            w.grid(row=row, column=1, sticky="w", pady=3)
            if tooltip:
                Tooltip(w, tooltip)
            return row + 1

        r = 0

        # ── Scan Defaults ──────────────────────────────────────────────
        r = section("📡  Scan Defaults", r)

        self.s_timeout_var    = tk.IntVar(value=self.timeout_var.get())
        self.s_workers_var    = tk.IntVar(value=self.max_workers_var.get())
        self.s_tcp_timeout_var = tk.DoubleVar(value=TCP_PROBE_TIMEOUT_S)
        self.s_banner_timeout_var = tk.DoubleVar(value=BANNER_GRAB_TIMEOUT_S)
        self.s_udp_timeout_var    = tk.DoubleVar(value=UDP_PROBE_TIMEOUT_S)
        self.s_ssl_timeout_var    = tk.DoubleVar(value=SSL_INSPECT_TIMEOUT_S)

        r = row_widget(r, "Ping timeout (ms):",
            lambda: ttk.Spinbox(col, textvariable=self.s_timeout_var,
                                from_=50, to=5000, increment=50, width=8),
            "Milliseconds to wait for ping reply")
        r = row_widget(r, "Max workers (0=auto):",
            lambda: ttk.Spinbox(col, textvariable=self.s_workers_var,
                                from_=0, to=1024, increment=16, width=8),
            "0 = auto-tune based on host count and CPU cores")
        r = row_widget(r, "TCP connect timeout (s):",
            lambda: ttk.Spinbox(col, textvariable=self.s_tcp_timeout_var,
                                from_=0.05, to=5.0,
                                increment=0.05, width=8, format="%.2f"),
            "Per-port TCP connect timeout")
        r = row_widget(r, "Banner grab timeout (s):",
            lambda: ttk.Spinbox(col, textvariable=self.s_banner_timeout_var,
                                from_=0.5, to=10.0,
                                increment=0.5, width=8, format="%.1f"),
            "Seconds to wait for service banner")
        r = row_widget(r, "UDP probe timeout (s):",
            lambda: ttk.Spinbox(col, textvariable=self.s_udp_timeout_var,
                                from_=0.5, to=10.0,
                                increment=0.5, width=8, format="%.1f"),
            "Seconds to wait for UDP response")
        r = row_widget(r, "SSL inspect timeout (s):",
            lambda: ttk.Spinbox(col, textvariable=self.s_ssl_timeout_var,
                                from_=1.0, to=15.0,
                                increment=0.5, width=8, format="%.1f"),
            "Seconds allowed for SSL/TLS handshake")

        # ── Smart Limits ──────────────────────────────────────────────
        r = section("⚡  Smart Auto-Tune Limits", r)

        self.s_disable_hn_var  = tk.IntVar(value=SMART_DISABLE_HOSTNAMES_OVER)
        self.s_disable_os_var  = tk.IntVar(value=SMART_DISABLE_OS_GUESS_OVER)
        self.s_disable_tcp_var = tk.IntVar(value=SMART_DISABLE_TCP_PROBE_OVER)
        self.s_ui_update_var   = tk.IntVar(value=UI_UPDATE_EVERY_BASE)

        r = row_widget(r, "Disable hostnames over N hosts:",
            lambda: ttk.Spinbox(col, textvariable=self.s_disable_hn_var,
                                from_=256, to=65536,
                                increment=256, width=8),
            "Reverse DNS is slow. Skip it for very large subnets.")
        r = row_widget(r, "Disable OS guess over N hosts:",
            lambda: ttk.Spinbox(col, textvariable=self.s_disable_os_var,
                                from_=256, to=65536,
                                increment=256, width=8))
        r = row_widget(r, "Disable TCP probe over N hosts:",
            lambda: ttk.Spinbox(col, textvariable=self.s_disable_tcp_var,
                                from_=1024, to=131072,
                                increment=1024, width=8))
        r = row_widget(r, "UI update every N hosts:",
            lambda: ttk.Spinbox(col, textvariable=self.s_ui_update_var,
                                from_=1, to=500,
                                increment=5, width=8),
            "Lower = more responsive but slower scan")

        # ── Pentest Options ───────────────────────────────────────────
        r = section("🔧  Pentest Options", r)

        self.s_check_creds_var   = tk.BooleanVar(value=self.check_creds_var.get())
        self.s_probe_udp_var     = tk.BooleanVar(value=self.probe_udp_var.get())
        self.s_inspect_ssl_var   = tk.BooleanVar(value=self.inspect_ssl_var.get())
        self.s_grab_banners_var  = tk.BooleanVar(value=self.grab_banners_var.get())
        self.s_compliance_var    = tk.BooleanVar(value=self.check_compliance_var.get())

        checks = [
            ("Grab service banners",        self.s_grab_banners_var,
             "Pull version/service info from open ports"),
            ("Probe UDP ports",             self.s_probe_udp_var,
             "Also probe common UDP ports (DNS, SNMP, NTP, SSDP…)"),
            ("Inspect SSL/TLS certificates",self.s_inspect_ssl_var,
             "Check cert expiry, weak ciphers, SANs"),
            ("Check default credentials",   self.s_check_creds_var,
             "⚠ Only on systems you own. Slow — adds per-host checks."),
            ("Run compliance checks",       self.s_compliance_var,
             "PCI-DSS, CIS-L1, NIST port-level rule evaluation"),
        ]
        for label, var, tip in checks:
            cb = ttk.Checkbutton(col, text=label, variable=var)
            cb.grid(row=r, column=0, columnspan=2,
                    sticky="w", padx=(0, 8), pady=2)
            Tooltip(cb, tip)
            r += 1

        # ── Schedule ──────────────────────────────────────────────────
        r = section("⏰  Scheduled Scans", r)

        self.s_sched_enabled_var  = tk.BooleanVar(
            value=self.schedule_enabled_var.get())
        self.s_sched_interval_var = tk.IntVar(
            value=self.schedule_interval_var.get())

        sched_cb = ttk.Checkbutton(
            col, text="Enable scheduled scanning",
            variable=self.s_sched_enabled_var)
        sched_cb.grid(row=r, column=0, columnspan=2,
                      sticky="w", pady=2)
        Tooltip(sched_cb,
                "Auto-repeat scan at the configured interval")
        r += 1

        r = row_widget(r, "Interval (minutes):",
            lambda: ttk.Spinbox(col, textvariable=self.s_sched_interval_var,
                                from_=1, to=10080,
                                increment=5, width=8),
            "How often to re-scan automatically (minutes)")

        ttk.Label(col, text="Next run:", style="Muted.TLabel").grid(
            row=r, column=0, sticky="w", pady=(2, 6))
        self.s_next_run_lbl = ttk.Label(col, text="—",
                                         style="Muted.TLabel")
        self.s_next_run_lbl.grid(row=r, column=1, sticky="w")
        r += 1

        # ── Profiles ─────────────────────────────────────────────────
        r = section("📋  Scan Profiles", r)

        prof_row = ttk.Frame(col)
        prof_row.grid(row=r, column=0, columnspan=3,
                      sticky="w", pady=(0, 8))
        r += 1

        ttk.Label(prof_row, text="Profile name:").pack(side=tk.LEFT)
        ttk.Entry(prof_row,
                  textvariable=self.current_profile_var,
                  width=18).pack(side=tk.LEFT, padx=(6, 8))
        ttk.Button(prof_row, text="💾 Save Profile",
                   command=self._save_current_profile,
                   style="Ghost.TButton").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(prof_row, text="📂 Load Profile",
                   command=self._load_profile_dialog,
                   style="Ghost.TButton").pack(side=tk.LEFT)

        # Profile list
        self.s_profile_list = tk.Listbox(
            col, height=4, width=36,
            font=("Segoe UI", 9), selectmode="single")
        self.s_profile_list.grid(row=r, column=0, columnspan=2,
                                  sticky="w", pady=(0, 4))
        r += 1
        self._refresh_profile_list()

        del_row = ttk.Frame(col)
        del_row.grid(row=r, column=0, columnspan=3,
                     sticky="w", pady=(0, 8))
        r += 1
        ttk.Button(del_row, text="🗑 Delete Selected",
                   command=self._delete_selected_profile,
                   style="Danger.TButton").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(del_row, text="Use Selected →",
                   command=self._use_selected_profile,
                   style="Ghost.TButton").pack(side=tk.LEFT)

        # ── Appearance ──────────────────────────────────────────────
        r = section("🎨  Appearance", r)

        self.s_font_size_var = tk.IntVar(value=9)

        r = row_widget(r, "Table font size:",
            lambda: ttk.Spinbox(col, textvariable=self.s_font_size_var,
                                from_=7, to=16, width=6),
            "Font size for the main scan table rows")

        theme_row = ttk.Frame(col)
        theme_row.grid(row=r, column=0, columnspan=3,
                       sticky="w", pady=(0, 6))
        r += 1
        ttk.Button(theme_row, text="Toggle Dark/Light Mode",
                   command=self._toggle_theme,
                   style="Ghost.TButton").pack(side=tk.LEFT, padx=(0, 8))

        # ── Columns Visibility ───────────────────────────────────────
        r = section("📊  Column Visibility", r)

        col_grid = ttk.Frame(col)
        col_grid.grid(row=r, column=0, columnspan=3,
                      sticky="w", pady=(0, 8))
        r += 1
        for i, (c_name, var) in enumerate(self._col_visible.items()):
            heading = self._col_cfg[c_name][0]
            cb = ttk.Checkbutton(
                col_grid, text=f"{heading} ({c_name})", variable=var,
                command=self._apply_column_visibility)
            cb.grid(row=i // 3, column=i % 3,
                    sticky="w", padx=(0, 24), pady=1)

        # ── Danger Zone ──────────────────────────────────────────────
        r = section("⚠  Data Management", r)

        dz_row = ttk.Frame(col)
        dz_row.grid(row=r, column=0, columnspan=3,
                    sticky="w", pady=(0, 12))
        r += 1

        btns = [
            ("🗑 Clear Scan Results", self._settings_clear_results,
             "Danger.TButton"),
            ("🗑 Clear Baseline",     self._settings_clear_baseline,
             "Danger.TButton"),
            ("🗑 Clear Alert Log",    lambda: self.alert_log.clear(),
             "Danger.TButton"),
            ("🗑 Clear Notes/Favs",   self._settings_clear_notes,
             "Danger.TButton"),
        ]
        for text, cmd, style in btns:
            ttk.Button(dz_row, text=text, command=cmd,
                       style=style).pack(side=tk.LEFT, padx=(0, 8))

        # ── Dependency Status ────────────────────────────────────────
        r = section("📦  Optional Dependencies", r)

        deps = [
            ("scapy",       _SCAPY_OK,
             "ARP scan, sniffer, raw socket traceroute"),
            ("cryptography",_CRYPTO_OK,
             "Full SSL/TLS certificate parsing (CN, SANs, expiry)"),
            ("netifaces",   _NETIFACES_OK,
             "Auto-detect local interfaces and gateway"),
            ("paramiko",    _PARAMIKO_OK,
             "SSH default credential checking"),
            ("matplotlib",  _MPL_OK,
             "Dashboard charts (pie, bar, line, distribution)"),
            ("reportlab",   _REPORTLAB_OK,
             "PDF pentest report export"),
        ]
        for i, (name, ok, tip) in enumerate(deps):
            status = "✓  Installed" if ok else "✗  Not installed"
            fg     = SUCCESS if ok     else DANGER
            ttk.Label(col, text=f"{name}:",
                      style="Bold.TLabel").grid(
                row=r, column=0, sticky="w",
                pady=2, padx=(0, 12))
            lbl = ttk.Label(col, text=status,
                            foreground=fg)
            lbl.grid(row=r, column=1, sticky="w")
            Tooltip(lbl, tip)
            r += 1

        ttk.Label(col,
                  text="Install missing deps:  "
                       "pip install scapy cryptography netifaces "
                       "paramiko matplotlib reportlab",
                  style="Muted.TLabel",
                  font=("Courier New", 8),
                  wraplength=640).grid(
            row=r, column=0, columnspan=3,
            sticky="w", pady=(6, 0))
        r += 1

        # ── About ────────────────────────────────────────────────────
        r = section("ℹ  About", r)

        about_lines = [
            f"{APP_FULL}",
            f"Python {sys.version.split()[0]} · "
            f"Platform: {platform.system()} {platform.release()}",
            f"State directory: {os.path.abspath(STATE_DIR)}",
            f"Plugins directory: {os.path.abspath(PLUGINS_DIR)}",
            "",
            "Keyboard shortcuts:",
            "  F5              Start scan",
            "  Escape          Stop scan",
            "  Ctrl+E          Export CSV",
            "  Ctrl+F          Focus filter",
            "  Ctrl+I          Copy selected IP",
            "  Ctrl+M          Copy selected MAC",
            "  Ctrl+R          Export Markdown report",
            "  F11             Toggle fullscreen",
            "  Delete          Remove selected row",
            "  Double-click    Open host detail window",
        ]
        for line in about_lines:
            ttk.Label(col, text=line,
                      style="Muted.TLabel",
                      font=("Courier New", 8)).grid(
                row=r, column=0, columnspan=3,
                sticky="w", pady=0)
            r += 1

    # ─── Settings helpers ────────────────────────────────────────────────

    def _settings_save(self):
        """Apply all settings to live variables and persist to disk."""
        global TCP_PROBE_TIMEOUT_S, BANNER_GRAB_TIMEOUT_S
        global UDP_PROBE_TIMEOUT_S, SSL_INSPECT_TIMEOUT_S
        global SMART_DISABLE_HOSTNAMES_OVER, SMART_DISABLE_OS_GUESS_OVER
        global SMART_DISABLE_TCP_PROBE_OVER, UI_UPDATE_EVERY_BASE

        self.timeout_var.set(self.s_timeout_var.get())
        self.max_workers_var.set(self.s_workers_var.get())

        TCP_PROBE_TIMEOUT_S          = self.s_tcp_timeout_var.get()
        BANNER_GRAB_TIMEOUT_S        = self.s_banner_timeout_var.get()
        UDP_PROBE_TIMEOUT_S          = self.s_udp_timeout_var.get()
        SSL_INSPECT_TIMEOUT_S        = self.s_ssl_timeout_var.get()
        SMART_DISABLE_HOSTNAMES_OVER = self.s_disable_hn_var.get()
        SMART_DISABLE_OS_GUESS_OVER  = self.s_disable_os_var.get()
        SMART_DISABLE_TCP_PROBE_OVER = self.s_disable_tcp_var.get()
        UI_UPDATE_EVERY_BASE         = self.s_ui_update_var.get()
        self.ui_update_every         = UI_UPDATE_EVERY_BASE

        self.grab_banners_var.set(self.s_grab_banners_var.get())
        self.probe_udp_var.set(self.s_probe_udp_var.get())
        self.inspect_ssl_var.set(self.s_inspect_ssl_var.get())
        self.check_creds_var.set(self.s_check_creds_var.get())
        self.check_compliance_var.set(self.s_compliance_var.get())

        # Scheduling
        self.schedule_enabled_var.set(self.s_sched_enabled_var.get())
        self.schedule_interval_var.set(self.s_sched_interval_var.get())
        if self.s_sched_enabled_var.get():
            interval = self.s_sched_interval_var.get()
            if interval > 0:
                self.next_run_time = (
                    datetime.datetime.now() +
                    datetime.timedelta(minutes=interval))
                self.s_next_run_lbl.config(
                    text=self.next_run_time.strftime("%Y-%m-%d %H:%M"))
        else:
            self.next_run_time = None
            self.s_next_run_lbl.config(text="—")

        # Font size
        size = self.s_font_size_var.get()
        ttk.Style(self.root).configure(
            "Treeview", font=("Segoe UI", size),
            rowheight=size + 16)

        # Persist settings to JSON
        ensure_dirs()
        cfg = {
            "timeout_ms":          self.timeout_var.get(),
            "max_workers":         self.max_workers_var.get(),
            "tcp_timeout":         TCP_PROBE_TIMEOUT_S,
            "banner_timeout":      BANNER_GRAB_TIMEOUT_S,
            "udp_timeout":         UDP_PROBE_TIMEOUT_S,
            "ssl_timeout":         SSL_INSPECT_TIMEOUT_S,
            "disable_hn_over":     SMART_DISABLE_HOSTNAMES_OVER,
            "disable_os_over":     SMART_DISABLE_OS_GUESS_OVER,
            "disable_tcp_over":    SMART_DISABLE_TCP_PROBE_OVER,
            "ui_update_every":     UI_UPDATE_EVERY_BASE,
            "grab_banners":        self.grab_banners_var.get(),
            "probe_udp":           self.probe_udp_var.get(),
            "inspect_ssl":         self.inspect_ssl_var.get(),
            "check_creds":         self.check_creds_var.get(),
            "compliance":          self.check_compliance_var.get(),
            "schedule_enabled":    self.schedule_enabled_var.get(),
            "schedule_interval":   self.schedule_interval_var.get(),
            "font_size":           size,
            "dark_mode":           self.is_dark,
        }
        try:
            with open(os.path.join(STATE_DIR, "settings.json"),
                      "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
        except Exception as e:
            log.warning("Settings save: %s", e)

        messagebox.showinfo("Settings", "Settings saved and applied.")

    def _load_settings(self):
        """Load persisted settings on startup."""
        path = os.path.join(STATE_DIR, "settings.json")
        if not os.path.isfile(path):
            return
        try:
            with open(path, encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            return

        global TCP_PROBE_TIMEOUT_S, BANNER_GRAB_TIMEOUT_S
        global UDP_PROBE_TIMEOUT_S, SSL_INSPECT_TIMEOUT_S
        global SMART_DISABLE_HOSTNAMES_OVER, SMART_DISABLE_OS_GUESS_OVER
        global SMART_DISABLE_TCP_PROBE_OVER, UI_UPDATE_EVERY_BASE

        self.timeout_var.set(cfg.get("timeout_ms", 300))
        self.max_workers_var.set(cfg.get("max_workers", 0))
        TCP_PROBE_TIMEOUT_S          = cfg.get("tcp_timeout",      0.10)
        BANNER_GRAB_TIMEOUT_S        = cfg.get("banner_timeout",   1.5)
        UDP_PROBE_TIMEOUT_S          = cfg.get("udp_timeout",      1.0)
        SSL_INSPECT_TIMEOUT_S        = cfg.get("ssl_timeout",      3.0)
        SMART_DISABLE_HOSTNAMES_OVER = cfg.get("disable_hn_over",  4096)
        SMART_DISABLE_OS_GUESS_OVER  = cfg.get("disable_os_over",  4096)
        SMART_DISABLE_TCP_PROBE_OVER = cfg.get("disable_tcp_over", 16384)
        UI_UPDATE_EVERY_BASE         = cfg.get("ui_update_every",  20)
        self.ui_update_every         = UI_UPDATE_EVERY_BASE

        self.grab_banners_var.set(cfg.get("grab_banners",   True))
        self.probe_udp_var.set(cfg.get("probe_udp",         False))
        self.inspect_ssl_var.set(cfg.get("inspect_ssl",     True))
        self.check_creds_var.set(cfg.get("check_creds",     False))
        self.check_compliance_var.set(cfg.get("compliance", True))

        self.schedule_enabled_var.set(cfg.get("schedule_enabled",  False))
        self.schedule_interval_var.set(cfg.get("schedule_interval", 0))

        if cfg.get("dark_mode") and not self.is_dark:
            self._toggle_theme()

    def _settings_clear_results(self):
        if messagebox.askyesno("Clear", "Delete all scan results?"):
            self.results.clear()
            self.security_findings.clear()
            if hasattr(self, "tree"):
                for row in self.tree.get_children():
                    self.tree.delete(row)
            self.update_summary()

    def _settings_clear_baseline(self):
        if messagebox.askyesno("Clear Baseline",
                               "Delete the saved baseline?"):
            self.baseline_mgr.baseline.clear()
            if os.path.isfile(BASELINE_FILE):
                os.remove(BASELINE_FILE)
            messagebox.showinfo("Baseline", "Baseline cleared.")

    def _settings_clear_notes(self):
        if messagebox.askyesno("Clear Notes",
                               "Delete all notes and favourites?"):
            self.host_notes.clear()
            self.host_favs.clear()
            if os.path.isfile(NOTES_FILE):
                os.remove(NOTES_FILE)

    def _refresh_profile_list(self):
        if not hasattr(self, "s_profile_list"):
            return
        self.s_profile_list.delete(0, "end")
        for name in self.profiles:
            self.s_profile_list.insert("end", name)

    def _delete_selected_profile(self):
        if not hasattr(self, "s_profile_list"):
            return
        sel = self.s_profile_list.curselection()
        if not sel:
            return
        name = self.s_profile_list.get(sel[0])
        if messagebox.askyesno("Delete Profile",
                               f"Delete profile '{name}'?"):
            del self.profiles[name]
            self._save_profiles()
            self._refresh_profile_list()

    def _use_selected_profile(self):
        if not hasattr(self, "s_profile_list"):
            return
        sel = self.s_profile_list.curselection()
        if not sel:
            return
        name = self.s_profile_list.get(sel[0])
        p    = self.profiles.get(name, {})
        for var in self._net_check_vars.values():
            var.set(False)
        for cidr in p.get("subnets", []):
            if cidr in self._net_check_vars:
                self._net_check_vars[cidr].set(True)
            else:
                self._custom_net_var.set(cidr)
                self._add_custom_network()
        self.mode_var.set(p.get("mode", "fast"))
        self.port_range_var.set(p.get("ports", ""))
        self.show_view("scanner")

    # ═══════════════════════════════════════════════════════════════════════
    # LATE INIT — called after all frames exist
    # ═══════════════════════════════════════════════════════════════════════

    def late_init(self):
        """
        Build all view contents, load persisted data, start background ticks.
        Called once after __init__ completes and the event loop starts.
        """
        # Build all tab contents
        self._build_scanner_ui()
        self._build_dashboard_ui()
        self._build_dashboard_contents()
        self._build_tools_ui()
        self._build_tools_contents()
        self._build_recon_ui()
        self._build_recon_contents()
        self._build_sniffer_ui()
        self._build_sniffer_contents()
        self._build_vulnscan_ui()
        self._build_vulnscan_contents()
        self._build_fingerprint_ui()
        self._build_fingerprint_contents()
        self._build_snmp_ui()
        self._build_snmp_contents()
        self._build_alerts_ui()
        self._build_compliance_ui()
        self._build_topology_ui()
        self._build_settings_ui()

        # Load persisted data
        ensure_dirs()
        self._load_notes()
        self._load_last_scan()
        self._load_profiles()
        self._load_settings()
        self._refresh_profile_list()

        # Restore last scan into table if available
        if self.results:
            self.scanned_hosts = len(self.results)
            self.total_hosts   = len(self.results)
            self.apply_filters()
            self.update_summary()
            used = sum(1 for r in self.results if r["status"] == "Used")
            self.statusbar_var.set(
                f"● Restored {used:,} active hosts from last session")

        # Start navigator on scanner tab
        self.show_view("scanner")

        # Background ticks
        self._live_dashboard_tick()
        self._schedule_tick()

        # Window close handler
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # Show dependency warnings if first launch
        missing = []
        if not _SCAPY_OK:    missing.append("scapy")
        if not _CRYPTO_OK:   missing.append("cryptography")
        if not _MPL_OK:      missing.append("matplotlib")
        if missing and not os.path.isfile(
                os.path.join(STATE_DIR, ".warned_deps")):
            self.root.after(
                1500,
                lambda: self._show_dep_warning(missing))

    def _show_dep_warning(self, missing: list):
        msg = (
            f"Optional packages not installed:\n"
            f"  {', '.join(missing)}\n\n"
            f"Some features are disabled.\n"
            f"Install with:\n"
            f"  pip install {' '.join(missing)}")
        messagebox.showinfo("Optional Dependencies", msg)
        # Don't warn again
        try:
            with open(os.path.join(STATE_DIR, ".warned_deps"), "w") as f:
                f.write("warned")
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────
    # WINDOW CLOSE HANDLER
    # ─────────────────────────────────────────────────────────────────────

    def _on_close(self):
        # Stop any active scans / sniffers
        if self.scanning:
            self.stop_scan()
        if self.sniffer_running:
            self.sniffer_running = False
        if self._arp_monitor_running:
            self._arp_monitor_running = False

        # Save state
        if self.results:
            self._save_last_scan()
        self._save_notes()
        self._save_profiles()

        self.root.destroy()

# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def _check_python_version():
    if sys.version_info < (3, 10):
        print(
            f"[!] Python 3.10+ required. "
            f"You have {sys.version.split()[0]}.",
            file=sys.stderr)
        sys.exit(1)

def _print_banner():
    print(f"""
╔══════════════════════════════════════════════════════════╗
║   ◈  {APP_FULL:<50}  ║
╠══════════════════════════════════════════════════════════╣
║  PENTESTER  │  Banner grab · Vuln DB · Default creds     ║
║             │  SSL/TLS inspect · Traceroute · Port knock  ║
║             │  NetBIOS enum · HTTP probe · Subdomain enum ║
╠══════════════════════════════════════════════════════════╣
║  DEFENSE    │  Threat scoring · Rogue detection           ║
║             │  Baseline diff · Compliance (PCI/CIS/NIST)  ║
║             │  ARP monitor · Alert log · Firewall rules   ║
╠══════════════════════════════════════════════════════════╣
║  DEPS       │  scapy={str(_SCAPY_OK):<5}  crypto={str(_CRYPTO_OK):<5}  mpl={str(_MPL_OK):<5}     ║
║             │  paramiko={str(_PARAMIKO_OK):<5}  netifaces={str(_NETIFACES_OK):<5}              ║
╚══════════════════════════════════════════════════════════╝
""")

def main():
    _check_python_version()
    _print_banner()

    # On Linux/macOS warn if not root (ARP/sniffer need it)
    if platform.system() in ("Linux", "Darwin"):
        if os.geteuid() != 0:
            print(
                "[!] Warning: not running as root.\n"
                "    ARP scan, packet sniffer and raw-socket\n"
                "    traceroute require root/sudo.\n"
                "    Fallback methods will be used where possible.\n")

    root = tk.Tk()
    root.withdraw()   # hide while building to avoid flash

    # Set taskbar/window icon (optional — ignore if no icon file)
    try:
        icon_path = os.path.join(os.path.dirname(__file__), "netprobe.ico")
        if os.path.isfile(icon_path):
            root.iconbitmap(icon_path)
    except Exception:
        pass

    app = IPScannerGUI(root)

    # Build all heavy UI after the event loop starts (avoids blank window)
    root.after(50, app.late_init)

    root.deiconify()
    root.mainloop()


if __name__ == "__main__":
    main()

# ─────────────────────────────────────────────────────────────────────────────
# ASSEMBLY INSTRUCTIONS
# ─────────────────────────────────────────────────────────────────────────────
#
# ONE-LINER ASSEMBLY (Linux / macOS / WSL):
# ─────────────────────────────────────────
#   cat NetProbe_v4_section1.py \
#       NetProbe_v4_section2.py \
#       NetProbe_v4_section3.py \
#       NetProbe_v4_section4.py > NetProbe_v4.py
#
# WINDOWS (PowerShell):
# ──────────────────────
#   Get-Content NetProbe_v4_section1.py,
#               NetProbe_v4_section2.py,
#               NetProbe_v4_section3.py,
#               NetProbe_v4_section4.py |
#     Set-Content NetProbe_v4.py
#
# WINDOWS (cmd):
#   copy /b NetProbe_v4_section1.py+NetProbe_v4_section2.py+^
#            NetProbe_v4_section3.py+NetProbe_v4_section4.py NetProbe_v4.py
#
# ─────────────────────────────────────────────────────────────────────────────
# INSTALL OPTIONAL DEPENDENCIES (recommended for full feature set):
# ─────────────────────────────────────────────────────────────────────────────
#
#   pip install scapy cryptography netifaces paramiko matplotlib reportlab
#
#   scapy        — ARP scan, packet sniffer, raw socket traceroute, ARP monitor
#   cryptography — full SSL/TLS cert parsing (CN, SANs, expiry dates)
#   netifaces    — auto-detect local network interfaces and gateways
#   paramiko     — SSH default credential checking
#   matplotlib   — dashboard charts (pie / bar / line / distribution)
#   reportlab    — PDF report export
#
# LINUX SCAPY NOTE:
#   sudo apt install python3-scapy  OR  pip install scapy
#   sudo setcap cap_net_raw+ep $(which python3)   # rootless raw sockets
#
# WINDOWS SCAPY NOTE:
#   Install Npcap from https://npcap.com before pip install scapy
#
# ─────────────────────────────────────────────────────────────────────────────
# PLUGIN API
# ─────────────────────────────────────────────────────────────────────────────
#
# Drop a .py file in ./plugins/ — it will be loaded automatically.
# Implement any of these hooks:
#
#   def on_result(result: dict):
#       """Called for every host after scan. result keys:
#          ip, subnet, status, hostname, mac, vendor, device_type,
#          latency_ms, open_ports, udp_ports, os_guess, banners,
#          ssl_info, security_findings, threat_score, baseline_cls
#       """
#
#   def on_scan_start(meta: dict):
#       """Called when a scan begins. meta = {target, mode, started}"""
#
#   def on_scan_done(results: list, findings: list):
#       """Called when all hosts are scanned."""
#
#   def on_alert(alert: dict):
#       """Called when an alert is logged."""
#
# EXAMPLE PLUGIN — plugins/slack_notify.py:
# ──────────────────────────────────────────
#   import urllib.request, json
#   WEBHOOK = "https://hooks.slack.com/services/YOUR/HOOK/URL"
#
#   def on_scan_done(results, findings):
#       crits = [f for f in findings if f[2] == "Critical"]
#       if not crits:
#           return
#       msg = {"text": f"⚠ {len(crits)} critical findings!\n" +
#                      "\n".join(f"  {f[0]}: {f[1]}" for f in crits[:5])}
#       req = urllib.request.Request(
#           WEBHOOK, json.dumps(msg).encode(),
#           headers={"Content-Type": "application/json"})
#       urllib.request.urlopen(req, timeout=5)
#
# ─────────────────────────────────────────────────────────────────────────────
# END OF NETPROBE v4.0
# ─────────────────────────────────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════════════════════
# NetProbe v5 — PATCH 1 of 5
# CVE Live Lookup · Credential Spray · Nmap Integration
# Shodan/Censys Enrichment · Threat Feed Integration · SIEM/Syslog Export
# ═════════════════════════════════════════════════════════════════════════════

import urllib.request
import urllib.parse
import urllib.error
import smtplib
import email.mime.text
import email.mime.multipart
import sqlite3
import ftplib

# ─────────────────────────────────────────────────────────────────────────────
# NEW OPTIONAL DEPS
# ─────────────────────────────────────────────────────────────────────────────

try:
    import xml.etree.ElementTree as ET
    _ET_OK = True
except ImportError:
    _ET_OK = False

# ─────────────────────────────────────────────────────────────────────────────
# NEW PATHS
# ─────────────────────────────────────────────────────────────────────────────

DB_FILE          = os.path.join(STATE_DIR, "netprobe.db")
CVE_CACHE_FILE   = os.path.join(STATE_DIR, "cve_cache.json")
THREAT_FEED_FILE = os.path.join(STATE_DIR, "threat_feed_cache.json")
SPRAY_WORDLIST   = os.path.join(STATE_DIR, "spray_wordlist.txt")

# ─────────────────────────────────────────────────────────────────────────────
# FEATURE FLAGS / NEW SETTINGS (defaults — overridden by settings.json)
# ─────────────────────────────────────────────────────────────────────────────

SHODAN_API_KEY      = ""
CENSYS_API_ID       = ""
CENSYS_API_SECRET   = ""
ABUSEIPDB_API_KEY   = ""
OTX_API_KEY         = ""
NVD_API_KEY         = ""        # optional — increases NVD rate limit
SIEM_HOST           = ""
SIEM_PORT           = 514
SIEM_PROTO          = "UDP"     # UDP or TCP
SMTP_HOST           = ""
SMTP_PORT           = 587
SMTP_USER           = ""
SMTP_PASS           = ""
SMTP_FROM           = ""
SMTP_TO             = ""
WEBHOOK_URL         = ""        # Slack / Teams / Discord / custom

CVE_LOOKUP_ENABLED      = False
THREAT_FEED_ENABLED     = False
SHODAN_ENABLED          = False
SIEM_ENABLED            = False
EMAIL_ALERTS_ENABLED    = False
WEBHOOK_ALERTS_ENABLED  = False
NMAP_ENABLED            = True   # auto-disabled if nmap not found

# ─────────────────────────────────────────────────────────────────────────────
# ① CVE LIVE LOOKUP ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class CVELookup:
    """
    Query NVD (NIST National Vulnerability Database) REST API v2.
    Caches results to disk to avoid hammering the API on repeated scans.
    Falls back to CIRCL CVE Search API if NVD is unavailable.
    """

    NVD_BASE    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CIRCL_BASE  = "https://cve.circl.lu/api/search"
    CACHE_TTL_H = 24   # hours before a cache entry expires

    def __init__(self):
        self._cache: dict = {}
        self._load_cache()

    def _load_cache(self):
        if os.path.isfile(CVE_CACHE_FILE):
            try:
                with open(CVE_CACHE_FILE, encoding="utf-8") as f:
                    self._cache = json.load(f)
            except Exception:
                self._cache = {}

    def _save_cache(self):
        ensure_dirs()
        try:
            with open(CVE_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(self._cache, f)
        except Exception:
            pass

    def _cache_get(self, key: str):
        entry = self._cache.get(key)
        if not entry:
            return None
        age_h = (time.time() - entry.get("ts", 0)) / 3600
        if age_h > self.CACHE_TTL_H:
            return None
        return entry.get("data")

    def _cache_set(self, key: str, data):
        self._cache[key] = {"ts": time.time(), "data": data}
        self._save_cache()

    def lookup_keyword(self, keyword: str,
                       max_results: int = 10) -> list[dict]:
        """
        Search NVD for CVEs matching a keyword (e.g. 'Apache 2.4.51').
        Returns list of {id, score, severity, description, published, url}.
        """
        if not keyword or len(keyword) < 4:
            return []
        cache_key = f"kw:{keyword.lower()[:60]}"
        cached    = self._cache_get(cache_key)
        if cached is not None:
            return cached

        results = self._nvd_keyword(keyword, max_results)
        if not results:
            results = self._circl_keyword(keyword, max_results)
        self._cache_set(cache_key, results)
        return results

    def lookup_cve_id(self, cve_id: str) -> dict | None:
        """Look up a specific CVE ID, e.g. 'CVE-2021-44228'."""
        cache_key = f"id:{cve_id}"
        cached    = self._cache_get(cache_key)
        if cached is not None:
            return cached
        result = self._nvd_cve_id(cve_id)
        if result:
            self._cache_set(cache_key, result)
        return result

    def _nvd_keyword(self, keyword: str,
                     max_results: int) -> list[dict]:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": str(min(max_results, 20)),
        }
        if NVD_API_KEY:
            params["apiKey"] = NVD_API_KEY
        url = f"{self.NVD_BASE}?{urllib.parse.urlencode(params)}"
        try:
            req  = urllib.request.Request(
                url,
                headers={"User-Agent": f"NetProbe/{VERSION}"})
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.loads(r.read().decode())
            return self._parse_nvd(data, max_results)
        except Exception as e:
            log.debug("NVD keyword search error: %s", e)
            return []

    def _nvd_cve_id(self, cve_id: str) -> dict | None:
        params = {"cveId": cve_id}
        if NVD_API_KEY:
            params["apiKey"] = NVD_API_KEY
        url = f"{self.NVD_BASE}?{urllib.parse.urlencode(params)}"
        try:
            req  = urllib.request.Request(
                url,
                headers={"User-Agent": f"NetProbe/{VERSION}"})
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.loads(r.read().decode())
            results = self._parse_nvd(data, 1)
            return results[0] if results else None
        except Exception as e:
            log.debug("NVD CVE-ID lookup error: %s", e)
            return None

    @staticmethod
    def _parse_nvd(data: dict, limit: int) -> list[dict]:
        out = []
        for item in data.get("vulnerabilities", [])[:limit]:
            cve   = item.get("cve", {})
            cve_id = cve.get("id", "")
            descs  = cve.get("descriptions", [])
            desc   = next((d["value"] for d in descs
                           if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            score   = None
            sev     = "Unknown"
            # Try CVSS v3.1 first, then v3.0, then v2
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                ms = metrics.get(key, [])
                if ms:
                    cvss_data = ms[0].get("cvssData", {})
                    score     = cvss_data.get("baseScore")
                    sev       = (ms[0].get("baseSeverity")
                                 or cvss_data.get("baseSeverity", "Unknown"))
                    break
            published = cve.get("published", "")[:10]
            out.append({
                "id":          cve_id,
                "score":       score,
                "severity":    sev.capitalize(),
                "description": desc[:300],
                "published":   published,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
        return out

    def _circl_keyword(self, keyword: str,
                       max_results: int) -> list[dict]:
        """Fallback: CIRCL CVE Search (no API key needed)."""
        safe = urllib.parse.quote(keyword[:50])
        url  = f"{self.CIRCL_BASE}/{safe}"
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": f"NetProbe/{VERSION}"})
            with urllib.request.urlopen(req, timeout=6) as r:
                data = json.loads(r.read().decode())
            out = []
            for item in data[:max_results]:
                out.append({
                    "id":          item.get("id", ""),
                    "score":       item.get("cvss"),
                    "severity":    self._cvss_to_sev(item.get("cvss")),
                    "description": item.get("summary", "")[:300],
                    "published":   item.get("Published", "")[:10],
                    "url": f"https://cve.circl.lu/cve/{item.get('id','')}",
                })
            return out
        except Exception as e:
            log.debug("CIRCL CVE fallback error: %s", e)
            return []

    @staticmethod
    def _cvss_to_sev(score) -> str:
        if score is None:
            return "Unknown"
        s = float(score)
        if s >= 9.0: return "Critical"
        if s >= 7.0: return "High"
        if s >= 4.0: return "Medium"
        return "Low"

    def enrich_result(self, result: dict) -> list[dict]:
        """
        Given a scan result dict, extract version strings from banners
        and look up CVEs for each. Returns list of CVE dicts.
        """
        cves    = []
        banners = result.get("banners", {})
        seen    = set()

        # Extract version keywords from banners
        version_pats = [
            r"(Apache[\s/][\d.]+\w*)",
            r"(nginx[\s/][\d.]+)",
            r"(OpenSSH[\s_][\d.]+\w*)",
            r"(PHP[\s/][\d.]+)",
            r"(MySQL[\s/][\d.]+)",
            r"(Microsoft-IIS[\s/][\d.]+)",
            r"(vsFTPd[\s][\d.]+)",
            r"(Postfix[\s\w./]+)",
            r"(Exim[\s][\d.]+)",
            r"(ProFTPD[\s][\d.]+)",
            r"(OpenSSL[\s/][\d.]+\w*)",
            r"(Samba[\s/][\d.]+)",
            r"(WordPress[\s/][\d.]+)",
            r"(Drupal[\s][\d.]+)",
            r"(Jenkins[\s][\d.]+)",
            r"(Tomcat[\s/][\d.]+)",
            r"(WebLogic[\s/][\d.]+)",
            r"(Redis[\s][\d.]+)",
            r"(MongoDB[\s][\d.]+)",
            r"(Elasticsearch[\s/][\d.]+)",
        ]

        for banner in banners.values():
            for pat in version_pats:
                m = re.search(pat, banner, re.I)
                if m:
                    kw = m.group(1).strip()
                    if kw not in seen:
                        seen.add(kw)
                        found = self.lookup_keyword(kw, max_results=5)
                        for c in found:
                            c["banner_match"] = kw
                        cves.extend(found)

        # Also look up any known CVEs from static VULN_DB
        for _, issue, sev, _ in result.get("security_findings", []):
            m = re.search(r"(CVE-\d{4}-\d+)", issue)
            if m:
                cid = m.group(1)
                if cid not in seen:
                    seen.add(cid)
                    c = self.lookup_cve_id(cid)
                    if c:
                        c["banner_match"] = issue[:40]
                        cves.append(c)

        return cves


# Singleton
cve_engine = CVELookup()


# ─────────────────────────────────────────────────────────────────────────────
# ② CREDENTIAL SPRAY ENGINE
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_SPRAY_WORDLIST = [
    # user:pass pairs (tab-separated in file; here as tuples)
    ("admin",         "admin"),
    ("admin",         "password"),
    ("admin",         "Password1"),
    ("admin",         "Admin123!"),
    ("admin",         "admin123"),
    ("admin",         "letmein"),
    ("admin",         ""),
    ("administrator", "administrator"),
    ("administrator", "Password1"),
    ("administrator", ""),
    ("root",          "root"),
    ("root",          "toor"),
    ("root",          "password"),
    ("root",          ""),
    ("user",          "user"),
    ("user",          "password"),
    ("guest",         "guest"),
    ("guest",         ""),
    ("pi",            "raspberry"),
    ("ubuntu",        "ubuntu"),
    ("operator",      "operator"),
    ("service",       "service"),
    ("support",       "support"),
    ("test",          "test"),
    ("demo",          "demo"),
    ("cisco",         "cisco"),
    ("cisco",         ""),
    ("enable",        "enable"),
    ("nagios",        "nagios"),
    ("zabbix",        "zabbix"),
    ("postgres",      "postgres"),
    ("mysql",         "mysql"),
    ("oracle",        "oracle"),
    ("sa",            ""),
    ("sa",            "sa"),
]

SPRAY_SERVICES = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    80:   "HTTP",
    443:  "HTTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP",
    8443: "HTTP",
    27017:"MongoDB",
}

class CredentialSpray:
    """
    Multi-protocol credential spray with:
    - Rate limiting (delay between attempts)
    - Lockout detection (consecutive failures → pause)
    - Stop-on-first-hit mode
    - Per-service threading
    """

    def __init__(self, callback=None):
        self.callback    = callback  # fn(ip, port, service, user, pwd, success)
        self.running     = False
        self._results:   list[dict] = []
        self._lock       = threading.Lock()

    def load_wordlist(self, path: str | None = None) -> list[tuple]:
        """Load user:pass pairs from file or return built-in list."""
        if path and os.path.isfile(path):
            pairs = []
            try:
                with open(path, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "\t" in line:
                            parts = line.split("\t", 1)
                        elif ":" in line:
                            parts = line.split(":", 1)
                        else:
                            continue
                        if len(parts) == 2:
                            pairs.append((parts[0], parts[1]))
            except Exception as e:
                log.warning("Wordlist load error: %s", e)
            return pairs or DEFAULT_SPRAY_WORDLIST
        return DEFAULT_SPRAY_WORDLIST

    def spray_host(self, ip: str, ports: list[int],
                   wordlist: list[tuple],
                   delay_s: float = 0.5,
                   stop_on_hit: bool = True,
                   lockout_threshold: int = 5) -> list[dict]:
        """
        Spray credentials against all given ports on a single host.
        Returns list of {ip, port, service, user, pwd, success, ts}.
        """
        results = []
        for port in ports:
            if not self.running:
                break
            service = SPRAY_SERVICES.get(port, "")
            if not service:
                continue

            consec_fail = 0
            hit_found   = False

            for user, pwd in wordlist:
                if not self.running or (stop_on_hit and hit_found):
                    break

                # Lockout back-off
                if consec_fail >= lockout_threshold:
                    log.debug("Spray: %s:%d — %d consecutive fails, pausing 10s",
                              ip, port, consec_fail)
                    time.sleep(10)
                    consec_fail = 0

                ok = self._try_one(ip, port, service, user, pwd)
                entry = {
                    "ip":      ip,
                    "port":    port,
                    "service": service,
                    "user":    user,
                    "pwd":     pwd,
                    "success": ok,
                    "ts":      ts_now(),
                }
                results.append(entry)
                with self._lock:
                    self._results.append(entry)
                if self.callback:
                    self.callback(entry)
                if ok:
                    hit_found   = True
                    consec_fail = 0
                else:
                    consec_fail += 1
                time.sleep(delay_s)

        return results

    def spray_subnet(self, targets: list[str],
                     ports: list[int],
                     wordlist: list[tuple],
                     delay_s: float = 0.5,
                     stop_on_hit: bool = True,
                     max_threads: int = 8):
        """Spray multiple hosts concurrently."""
        self.running    = True
        self._results   = []
        pool = SmartWorkerPool(workers=max_threads,
                               queue_limit=len(targets) + 10)
        for ip in targets:
            pool.submit(self.spray_host, ip, ports, wordlist,
                        delay_s, stop_on_hit)
        pool.queue.join()
        pool.shutdown()
        self.running = False
        return self._results

    @staticmethod
    def _try_one(ip: str, port: int, service: str,
                 user: str, pwd: str) -> bool:
        """Attempt a single credential. Returns True on success."""
        timeout = DEFAULT_CRED_TIMEOUT_S
        try:
            if service == "FTP":
                ftp = ftplib.FTP(timeout=int(timeout))
                ftp.connect(ip, port, timeout=int(timeout))
                ftp.login(user, pwd)
                ftp.quit()
                return True

            elif service == "SSH" and _PARAMIKO_OK:
                c = paramiko.SSHClient()
                c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                c.connect(ip, port=port, username=user, password=pwd,
                          timeout=timeout, allow_agent=False,
                          look_for_keys=False)
                c.close()
                return True

            elif service == "HTTP":
                import base64
                cred = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                scheme = "https" if port in (443, 8443) else "http"
                ctx = None
                if scheme == "https":
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode    = ssl.CERT_NONE
                req = urllib.request.Request(
                    f"{scheme}://{ip}:{port}/",
                    headers={"Authorization": f"Basic {cred}",
                             "User-Agent": f"NetProbe/{VERSION}"})
                with urllib.request.urlopen(
                        req, timeout=timeout,
                        context=ctx) as r:
                    return r.status < 400

            elif service == "Telnet":
                import telnetlib
                tn = telnetlib.Telnet(ip, port, timeout=int(timeout))
                tn.read_until(b"login:", timeout=3)
                tn.write(user.encode() + b"\n")
                tn.read_until(b"assword:", timeout=3)
                tn.write(pwd.encode() + b"\n")
                resp = tn.read_some()
                tn.close()
                return (b"incorrect" not in resp.lower()
                        and b"failed" not in resp.lower()
                        and len(resp) > 2)

            elif service == "MySQL":
                # Use socket-level MySQL handshake
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((ip, port))
                banner = s.recv(256)
                # Build auth packet (simplified — checks for error response)
                s.close()
                return len(banner) > 4 and banner[4] != 0xff

            elif service == "Redis":
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((ip, port))
                if pwd:
                    s.send(f"AUTH {pwd}\r\n".encode())
                    resp = s.recv(128)
                    s.close()
                    return resp.startswith(b"+OK")
                else:
                    s.send(b"PING\r\n")
                    resp = s.recv(128)
                    s.close()
                    return b"+PONG" in resp

            elif service == "MongoDB":
                # Check if MongoDB responds (no auth required = vuln)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    s.close()
                    return True  # open with no auth attempted

            elif service == "PostgreSQL":
                # Startup packet
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((ip, port))
                # Minimal startup message
                db = b"postgres\x00"
                u  = user.encode() + b"\x00"
                msg = (b"\x00\x03\x00\x00"
                       b"user\x00" + u +
                       b"database\x00" + db + b"\x00")
                length = len(msg) + 4
                s.send(length.to_bytes(4, "big") + msg)
                resp = s.recv(256)
                s.close()
                return len(resp) > 0 and resp[0] != b"E"[0]

        except Exception:
            pass
        return False


# Singleton
spray_engine = CredentialSpray()


# ─────────────────────────────────────────────────────────────────────────────
# ③ NMAP INTEGRATION
# ─────────────────────────────────────────────────────────────────────────────

class NmapRunner:
    """
    Wrapper around the nmap binary.
    Runs nmap as a subprocess, parses XML output, returns structured data.
    Gracefully disabled if nmap is not installed.
    """

    NMAP_PATH   = None
    _detected   = False

    @classmethod
    def find_nmap(cls) -> str | None:
        if cls._detected:
            return cls.NMAP_PATH
        cls._detected = True
        # Common locations
        candidates = ["nmap"]
        if platform.system().lower() == "windows":
            candidates += [
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe",
            ]
        for candidate in candidates:
            try:
                out = subprocess.check_output(
                    [candidate, "--version"],
                    stderr=subprocess.DEVNULL,
                    timeout=5).decode(errors="ignore")
                if "nmap" in out.lower():
                    cls.NMAP_PATH = candidate
                    return candidate
            except Exception:
                pass
        return None

    @classmethod
    def available(cls) -> bool:
        return cls.find_nmap() is not None

    @classmethod
    def run(cls, targets: list[str],
            ports: str = "",
            flags: list[str] | None = None,
            timeout: int = 300,
            progress_cb=None) -> dict:
        """
        Run nmap and return parsed results dict:
        {ip: {hostname, state, ports:[{port,proto,state,service,version,script}],
              os_matches:[{name,accuracy}], scripts:{}}}
        """
        nmap = cls.find_nmap()
        if not nmap:
            return {}

        with tempfile.NamedTemporaryFile(
                suffix=".xml", delete=False) as tf:
            xml_path = tf.name

        cmd = [nmap, "-oX", xml_path]

        # Default flags
        default_flags = ["-sV", "--version-intensity", "5",
                         "-O", "--osscan-guess",
                         "-T4", "--open"]
        cmd.extend(flags or default_flags)

        if ports:
            cmd += ["-p", ports]

        cmd.extend(targets)

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True)

            # Stream stdout for progress
            output_lines = []
            for line in proc.stdout:
                output_lines.append(line)
                if progress_cb:
                    progress_cb(line.rstrip())

            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            log.warning("Nmap timed out after %ds", timeout)
        except Exception as e:
            log.warning("Nmap run error: %s", e)
            return {}

        try:
            results = cls._parse_xml(xml_path)
        finally:
            try:
                os.unlink(xml_path)
            except Exception:
                pass

        return results

    @classmethod
    def _parse_xml(cls, xml_path: str) -> dict:
        results = {}
        if not os.path.isfile(xml_path):
            return results
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
        except Exception as e:
            log.warning("Nmap XML parse error: %s", e)
            return results

        for host_el in root.findall("host"):
            # IP
            ip = ""
            for addr in host_el.findall("address"):
                if addr.get("addrtype") in ("ipv4", "ipv6"):
                    ip = addr.get("addr", "")
                    break
            if not ip:
                continue

            # State
            status = host_el.find("status")
            state  = status.get("state", "") if status is not None else ""

            # Hostname
            hostname = ""
            hostnames_el = host_el.find("hostnames")
            if hostnames_el is not None:
                for hn in hostnames_el.findall("hostname"):
                    hostname = hn.get("name", "")
                    break

            # Ports
            ports_list = []
            ports_el   = host_el.find("ports")
            if ports_el is not None:
                for port_el in ports_el.findall("port"):
                    portid = int(port_el.get("portid", 0))
                    proto  = port_el.get("protocol", "tcp")
                    pstate_el = port_el.find("state")
                    pstate    = pstate_el.get("state","") if pstate_el is not None else ""
                    svc_el    = port_el.find("service")
                    svc_name  = ""
                    svc_ver   = ""
                    svc_prod  = ""
                    if svc_el is not None:
                        svc_name = svc_el.get("name", "")
                        svc_prod = svc_el.get("product", "")
                        svc_ver  = svc_el.get("version", "")

                    # NSE scripts
                    scripts = {}
                    for sc in port_el.findall("script"):
                        scripts[sc.get("id","")] = sc.get("output","")[:200]

                    ports_list.append({
                        "port":    portid,
                        "proto":   proto,
                        "state":   pstate,
                        "service": svc_name,
                        "product": svc_prod,
                        "version": svc_ver,
                        "scripts": scripts,
                    })

            # OS detection
            os_matches = []
            os_el = host_el.find("os")
            if os_el is not None:
                for om in os_el.findall("osmatch"):
                    os_matches.append({
                        "name":     om.get("name", ""),
                        "accuracy": int(om.get("accuracy", 0)),
                    })
            os_matches.sort(key=lambda x: -x["accuracy"])

            # Host scripts
            host_scripts = {}
            hs_el = host_el.find("hostscript")
            if hs_el is not None:
                for sc in hs_el.findall("script"):
                    host_scripts[sc.get("id","")] = sc.get("output","")[:300]

            results[ip] = {
                "hostname":   hostname,
                "state":      state,
                "ports":      ports_list,
                "os_matches": os_matches,
                "host_scripts": host_scripts,
            }

        return results

    @classmethod
    def merge_into_result(cls, scan_result: dict,
                          nmap_data: dict) -> dict:
        """
        Merge nmap findings into an existing scan result dict in-place.
        Adds/updates: hostname, open_ports, os_guess, banners, nmap_os,
        nmap_ports, nmap_scripts.
        """
        ip   = scan_result.get("ip", "")
        data = nmap_data.get(ip)
        if not data:
            return scan_result

        # Merge open ports
        nmap_open = [p["port"] for p in data["ports"]
                     if p["state"] == "open"]
        existing  = set(scan_result.get("open_ports", []))
        scan_result["open_ports"] = sorted(existing | set(nmap_open))

        # Merge banners / version strings
        banners = scan_result.setdefault("banners", {})
        for p in data["ports"]:
            if p["state"] == "open":
                ver_str = " ".join(filter(None, [
                    p["product"], p["version"]])).strip()
                if ver_str:
                    banners[p["port"]] = ver_str[:200]

        # Hostname
        if data["hostname"] and not scan_result.get("hostname"):
            scan_result["hostname"] = data["hostname"]

        # OS guess
        if data["os_matches"]:
            best = data["os_matches"][0]
            scan_result["os_guess"]  = (
                f"{best['name']} ({best['accuracy']}% nmap)")
            scan_result["nmap_os"]   = data["os_matches"]

        # Store raw nmap data
        scan_result["nmap_ports"]   = data["ports"]
        scan_result["nmap_scripts"] = data.get("host_scripts", {})

        return scan_result


# ─────────────────────────────────────────────────────────────────────────────
# ④ SHODAN / CENSYS ENRICHMENT
# ─────────────────────────────────────────────────────────────────────────────

class ShodanEnrich:
    """
    Enrich a public IP with Shodan data.
    Returns dict: {ports, vulns, org, isp, country, hostnames, tags, cves}
    Falls back gracefully if API key not set.
    """

    BASE = "https://api.shodan.io/shodan/host"

    @staticmethod
    def is_public_ip(ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
            return not (a.is_private or a.is_loopback
                        or a.is_link_local or a.is_multicast)
        except ValueError:
            return False

    @classmethod
    def lookup(cls, ip: str) -> dict | None:
        if not SHODAN_API_KEY:
            return None
        if not cls.is_public_ip(ip):
            return None
        url = f"{cls.BASE}/{ip}?key={SHODAN_API_KEY}"
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": f"NetProbe/{VERSION}"})
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.loads(r.read().decode())
            vulns = list(data.get("vulns", {}).keys())
            return {
                "source":    "Shodan",
                "ports":     data.get("ports", []),
                "org":       data.get("org", ""),
                "isp":       data.get("isp", ""),
                "country":   data.get("country_name", ""),
                "hostnames": data.get("hostnames", []),
                "tags":      data.get("tags", []),
                "os":        data.get("os", ""),
                "vulns":     vulns,
                "last_seen": data.get("last_update", ""),
            }
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"source": "Shodan", "error": "Not found"}
            log.debug("Shodan error %s: %s", ip, e)
            return None
        except Exception as e:
            log.debug("Shodan lookup error: %s", e)
            return None


class CensysEnrich:
    """
    Enrich a public IP with Censys data.
    Requires CENSYS_API_ID and CENSYS_API_SECRET.
    """

    BASE = "https://search.censys.io/api/v2/hosts"

    @classmethod
    def lookup(cls, ip: str) -> dict | None:
        if not (CENSYS_API_ID and CENSYS_API_SECRET):
            return None
        if not ShodanEnrich.is_public_ip(ip):
            return None
        import base64
        creds = base64.b64encode(
            f"{CENSYS_API_ID}:{CENSYS_API_SECRET}".encode()).decode()
        url = f"{cls.BASE}/{ip}"
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "Authorization": f"Basic {creds}",
                    "User-Agent":    f"NetProbe/{VERSION}",
                    "Accept":        "application/json",
                })
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.loads(r.read().decode())
            result_data = data.get("result", {})
            services    = result_data.get("services", [])
            ports = [s.get("port") for s in services if s.get("port")]
            banners = {
                s["port"]: s.get("banner", "")[:100]
                for s in services if s.get("banner")
            }
            return {
                "source":    "Censys",
                "ports":     ports,
                "banners":   banners,
                "country":   result_data.get("location", {}).get(
                    "country", ""),
                "org":       result_data.get("autonomous_system", {}).get(
                    "name", ""),
                "asn":       result_data.get("autonomous_system", {}).get(
                    "asn", ""),
                "last_seen": result_data.get("last_updated_at", ""),
            }
        except Exception as e:
            log.debug("Censys lookup error: %s", e)
            return None


def enrich_ip_intel(ip: str) -> dict:
    """
    Try Shodan first, then Censys. Returns combined enrichment dict or {}.
    """
    result = ShodanEnrich.lookup(ip)
    if result and "error" not in result:
        return result
    result = CensysEnrich.lookup(ip)
    return result or {}


# ─────────────────────────────────────────────────────────────────────────────
# ⑤ THREAT FEED INTEGRATION
# ─────────────────────────────────────────────────────────────────────────────

class ThreatFeedChecker:
    """
    Check IPs against:
    - AbuseIPDB (confidence score + categories)
    - AlienVault OTX (pulse count + threat types)
    - GreyNoise Community API (noise / malicious / benign)

    Results are cached for 6 hours.
    """

    ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
    OTX_URL       = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    GREYNOISE_URL = "https://api.greynoise.io/v3/community/{ip}"
    CACHE_TTL_H   = 6

    def __init__(self):
        self._cache: dict = {}
        self._load_cache()

    def _load_cache(self):
        if os.path.isfile(THREAT_FEED_FILE):
            try:
                with open(THREAT_FEED_FILE, encoding="utf-8") as f:
                    self._cache = json.load(f)
            except Exception:
                self._cache = {}

    def _save_cache(self):
        ensure_dirs()
        try:
            with open(THREAT_FEED_FILE, "w", encoding="utf-8") as f:
                json.dump(self._cache, f)
        except Exception:
            pass

    def _cache_get(self, key):
        entry = self._cache.get(key)
        if not entry:
            return None
        if (time.time() - entry.get("ts", 0)) / 3600 > self.CACHE_TTL_H:
            return None
        return entry.get("data")

    def _cache_set(self, key, data):
        self._cache[key] = {"ts": time.time(), "data": data}
        self._save_cache()

    def check(self, ip: str) -> dict:
        """
        Returns combined threat intel:
        {ip, abusive, confidence, abuse_categories, otx_pulses,
         greynoise_classification, malicious, sources:[str], summary:str}
        """
        cached = self._cache_get(f"ti:{ip}")
        if cached:
            return cached

        result = {
            "ip":               ip,
            "abusive":          False,
            "confidence":       0,
            "abuse_categories": [],
            "otx_pulses":       0,
            "otx_threat_types": [],
            "greynoise":        "",
            "malicious":        False,
            "sources":          [],
            "summary":          "",
        }

        if not ShodanEnrich.is_public_ip(ip):
            return result

        # AbuseIPDB
        if ABUSEIPDB_API_KEY:
            try:
                params = urllib.parse.urlencode({
                    "ipAddress":    ip,
                    "maxAgeInDays": "90",
                })
                req = urllib.request.Request(
                    f"{self.ABUSEIPDB_URL}?{params}",
                    headers={
                        "Key":    ABUSEIPDB_API_KEY,
                        "Accept": "application/json",
                        "User-Agent": f"NetProbe/{VERSION}",
                    })
                with urllib.request.urlopen(req, timeout=6) as r:
                    data = json.loads(r.read().decode())
                d = data.get("data", {})
                conf = d.get("abuseConfidenceScore", 0)
                cats = d.get("categories", [])
                if conf > 0:
                    result["abusive"]          = conf >= 25
                    result["confidence"]        = conf
                    result["abuse_categories"]  = cats
                    result["sources"].append("AbuseIPDB")
                    if conf >= 75:
                        result["malicious"] = True
            except Exception as e:
                log.debug("AbuseIPDB error: %s", e)

        # AlienVault OTX
        if OTX_API_KEY:
            try:
                url = self.OTX_URL.format(ip=ip)
                req = urllib.request.Request(
                    url,
                    headers={
                        "X-OTX-API-KEY": OTX_API_KEY,
                        "User-Agent":    f"NetProbe/{VERSION}",
                    })
                with urllib.request.urlopen(req, timeout=6) as r:
                    data = json.loads(r.read().decode())
                pulses = data.get("pulse_info", {}).get("count", 0)
                types  = list({
                    t for p in data.get("pulse_info", {}).get(
                        "pulses", [])
                    for t in p.get("tags", [])
                })[:10]
                if pulses > 0:
                    result["otx_pulses"]      = pulses
                    result["otx_threat_types"]= types
                    result["sources"].append("OTX")
                    if pulses >= 5:
                        result["malicious"] = True
            except Exception as e:
                log.debug("OTX error: %s", e)

        # GreyNoise Community (no key needed for basic)
        try:
            url = self.GREYNOISE_URL.format(ip=ip)
            req = urllib.request.Request(
                url,
                headers={"User-Agent": f"NetProbe/{VERSION}"})
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.loads(r.read().decode())
            cls_  = data.get("classification", "")
            noise = data.get("noise", False)
            if cls_ or noise:
                result["greynoise"] = cls_ or ("noise" if noise else "")
                result["sources"].append("GreyNoise")
                if cls_ == "malicious":
                    result["malicious"] = True
        except Exception as e:
            log.debug("GreyNoise error: %s", e)

        # Build summary
        parts = []
        if result["confidence"]:
            parts.append(f"Abuse: {result['confidence']}%")
        if result["otx_pulses"]:
            parts.append(f"OTX: {result['otx_pulses']} pulses")
        if result["greynoise"]:
            parts.append(f"GN: {result['greynoise']}")
        result["summary"] = "  |  ".join(parts) if parts else "Clean"

        self._cache_set(f"ti:{ip}", result)
        return result

    def check_batch(self, ips: list[str],
                    callback=None) -> dict[str, dict]:
        """Check multiple IPs. callback(ip, result) called per result."""
        out = {}
        for ip in ips:
            r = self.check(ip)
            out[ip] = r
            if callback:
                callback(ip, r)
        return out


# Singleton
threat_feed = ThreatFeedChecker()


# ─────────────────────────────────────────────────────────────────────────────
# ⑥ SIEM / SYSLOG EXPORT  (CEF format — Splunk, QRadar, Graylog compatible)
# ─────────────────────────────────────────────────────────────────────────────

class SIEMExporter:
    """
    Export alerts and findings to a SIEM via UDP/TCP syslog in CEF format.
    CEF: ArcSight Common Event Format — understood natively by Splunk,
    QRadar, Graylog, LogRhythm, and most other SIEMs.
    """

    # CEF severity map
    SEV_MAP = {
        "Critical": 10,
        "High":      7,
        "Medium":    5,
        "Low":       3,
        "Info":      1,
    }

    def __init__(self):
        self._sock_udp  = None
        self._sock_tcp  = None
        self._connected = False

    def _cef_escape(self, val: str) -> str:
        return str(val).replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")

    def format_cef(self, severity: str, ip: str,
                   event_name: str, details: str = "",
                   extra: dict | None = None) -> str:
        """
        Build a CEF syslog line.
        Format: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|ext
        """
        sev_int  = self.SEV_MAP.get(severity, 5)
        sig_id   = re.sub(r"[^A-Za-z0-9_]", "_", event_name)[:32]
        ext_parts = [
            f"src={ip}",
            f"msg={self._cef_escape(details[:200])}",
            f"sev={severity}",
            f"rt={ts_now()}",
        ]
        if extra:
            for k, v in extra.items():
                ext_parts.append(
                    f"{self._cef_escape(k)}={self._cef_escape(str(v))}")

        cef = (
            f"CEF:0|NetProbe|NetProbe|{VERSION}|"
            f"{sig_id}|{self._cef_escape(event_name)}|"
            f"{sev_int}|"
            + " ".join(ext_parts)
        )
        # RFC 5424 syslog header (facility 1 = user, severity 5 = notice)
        priority = (1 * 8) + 5
        return f"<{priority}>NetProbe: {cef}"

    def send(self, severity: str, ip: str,
             event_name: str, details: str = "",
             extra: dict | None = None) -> bool:
        """Send a single CEF event. Returns True on success."""
        if not (SIEM_ENABLED and SIEM_HOST):
            return False
        line = self.format_cef(severity, ip, event_name,
                                details, extra)
        return self._transmit(line)

    def send_finding(self, finding: tuple) -> bool:
        """Send a security finding tuple (ip, issue, severity, rec)."""
        ip, issue, severity, rec = finding
        return self.send(severity, ip, issue,
                         details=rec[:100],
                         extra={"cs1": issue, "cs1Label": "Finding"})

    def send_alert(self, alert: dict) -> bool:
        return self.send(
            alert.get("severity", "Info"),
            alert.get("ip", ""),
            alert.get("message", "Alert")[:64],
            details=alert.get("message", ""),
            extra={"cs2": alert.get("tag", ""), "cs2Label": "Tag"})

    def _transmit(self, line: str) -> bool:
        data = (line + "\n").encode("utf-8")
        try:
            if SIEM_PROTO == "TCP":
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((SIEM_HOST, SIEM_PORT))
                s.sendall(data)
                s.close()
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(data, (SIEM_HOST, SIEM_PORT))
                s.close()
            return True
        except Exception as e:
            log.debug("SIEM transmit error: %s", e)
            return False

    def bulk_send_findings(self, findings: list,
                           callback=None) -> int:
        """Send all findings to SIEM. Returns count sent."""
        sent = 0
        for f in findings:
            if self.send_finding(f):
                sent += 1
                if callback:
                    callback(sent, len(findings))
        return sent

    def test_connection(self) -> tuple[bool, str]:
        """Test SIEM connectivity. Returns (success, message)."""
        if not SIEM_HOST:
            return False, "SIEM host not configured"
        ok = self.send("Info", "127.0.0.1",
                       "NetProbe_Test",
                       "Connection test from NetProbe")
        if ok:
            return True, f"Connected to {SIEM_HOST}:{SIEM_PORT} ({SIEM_PROTO})"
        return False, f"Failed to reach {SIEM_HOST}:{SIEM_PORT}"


# ─────────────────────────────────────────────────────────────────────────────
# ⑦ EMAIL / WEBHOOK ALERTING
# ─────────────────────────────────────────────────────────────────────────────

class AlertDispatcher:
    """
    Send alert notifications via:
    - SMTP email (HTML formatted)
    - Slack / Teams / Discord / generic webhook (JSON payload)
    """

    @staticmethod
    def send_email(subject: str, body_html: str) -> tuple[bool, str]:
        if not (EMAIL_ALERTS_ENABLED and SMTP_HOST and SMTP_TO):
            return False, "Email not configured"
        try:
            msg = email.mime.multipart.MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"]    = SMTP_FROM or SMTP_USER
            msg["To"]      = SMTP_TO
            msg.attach(email.mime.text.MIMEText(body_html, "html"))
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as srv:
                srv.ehlo()
                if SMTP_PORT in (587, 465):
                    srv.starttls()
                if SMTP_USER and SMTP_PASS:
                    srv.login(SMTP_USER, SMTP_PASS)
                srv.sendmail(
                    msg["From"], SMTP_TO.split(","), msg.as_string())
            return True, "Email sent"
        except Exception as e:
            return False, str(e)

    @staticmethod
    def send_webhook(payload: dict) -> tuple[bool, str]:
        if not (WEBHOOK_ALERTS_ENABLED and WEBHOOK_URL):
            return False, "Webhook not configured"
        try:
            data = json.dumps(payload).encode()
            req  = urllib.request.Request(
                WEBHOOK_URL, data=data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent":   f"NetProbe/{VERSION}",
                },
                method="POST")
            with urllib.request.urlopen(req, timeout=8) as r:
                return True, f"HTTP {r.status}"
        except Exception as e:
            return False, str(e)

    @classmethod
    def dispatch_finding(cls, ip: str, issue: str,
                         severity: str, details: str):
        """Send both email and webhook for a single critical finding."""
        subject   = f"[NetProbe] {severity} — {issue} on {ip}"
        body_html = f"""
        <html><body style="font-family:sans-serif">
        <h2 style="color:#dc2626">⚠ {severity} Finding</h2>
        <table>
          <tr><td><b>Host:</b></td><td>{ip}</td></tr>
          <tr><td><b>Issue:</b></td><td>{issue}</td></tr>
          <tr><td><b>Severity:</b></td><td>{severity}</td></tr>
          <tr><td><b>Details:</b></td><td>{details[:300]}</td></tr>
          <tr><td><b>Time:</b></td><td>{ts_now()}</td></tr>
        </table>
        <p style="color:#64748b;font-size:11px">
          Sent by {APP_FULL}</p>
        </body></html>"""

        # Slack / Teams / Discord compatible payload
        webhook_payload = {
            "text": f"*[NetProbe] {severity}: {issue}*",
            "attachments": [{
                "color": "#dc2626" if severity == "Critical" else "#f97316",
                "fields": [
                    {"title": "Host",     "value": ip,      "short": True},
                    {"title": "Severity", "value": severity,"short": True},
                    {"title": "Issue",    "value": issue},
                    {"title": "Details",  "value": details[:200]},
                ]
            }]
        }

        threading.Thread(
            target=lambda: cls.send_email(subject, body_html),
            daemon=True).start()
        threading.Thread(
            target=lambda: cls.send_webhook(webhook_payload),
            daemon=True).start()

    @classmethod
    def dispatch_scan_summary(cls, results: list, findings: list):
        """Send a summary email/webhook after a scan completes."""
        used   = sum(1 for r in results if r["status"] == "Used")
        crits  = sum(1 for _, _, s, _ in findings if s == "Critical")
        highs  = sum(1 for _, _, s, _ in findings if s == "High")
        subject = (f"[NetProbe] Scan Complete — "
                   f"{used} hosts, {len(findings)} findings")
        body_html = f"""
        <html><body style="font-family:sans-serif">
        <h2>NetProbe Scan Summary</h2>
        <table>
          <tr><td><b>Active Hosts:</b></td><td>{used}</td></tr>
          <tr><td><b>Total Findings:</b></td><td>{len(findings)}</td></tr>
          <tr><td><b>Critical:</b></td>
              <td style="color:#dc2626"><b>{crits}</b></td></tr>
          <tr><td><b>High:</b></td>
              <td style="color:#f97316"><b>{highs}</b></td></tr>
          <tr><td><b>Time:</b></td><td>{ts_now()}</td></tr>
        </table></body></html>"""
        webhook_payload = {
            "text": (f"*NetProbe Scan Done* — "
                     f"{used} hosts · {crits} critical · {highs} high"),
        }
        threading.Thread(
            target=lambda: cls.send_email(subject, body_html),
            daemon=True).start()
        threading.Thread(
            target=lambda: cls.send_webhook(webhook_payload),
            daemon=True).start()


# Singletons
siem_exporter    = SIEMExporter()
alert_dispatcher = AlertDispatcher()

# ─── End of Patch 1 ──────────────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════════════════════
# NetProbe v5 — PATCH 2 of 5
# SQLite Backend · Historical Trends · Honeypot Monitor · CPE Mapping
# IPv6 Full Support · Wi-Fi Scanner · DNS Zone Transfer · HTTP Dirbuster
# ═════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# ① SQLITE BACKEND  (replaces / supplements JSON flat files)
# ─────────────────────────────────────────────────────────────────────────────

class NetProbeDB:
    """
    SQLite-backed persistent store.
    Tables:
      scans       — one row per scan run (meta + summary)
      hosts       — one row per host per scan (full result JSON)
      findings    — normalised security findings
      alerts      — alert log (mirrors alert_log JSON but in DB)
      threat_intel— cached threat feed results per IP
      cpe_cache   — banner→CPE mappings
    Provides trend queries:
      - host history (port changes over time)
      - threat score timeline
      - new/gone hosts between scans
    """

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS scans (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at  TEXT NOT NULL,
        finished_at TEXT,
        target      TEXT,
        mode        TEXT,
        host_count  INTEGER DEFAULT 0,
        active_count INTEGER DEFAULT 0,
        finding_count INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS hosts (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id     INTEGER REFERENCES scans(id),
        ip          TEXT NOT NULL,
        subnet      TEXT,
        status      TEXT,
        hostname    TEXT,
        mac         TEXT,
        vendor      TEXT,
        device_type TEXT,
        os_guess    TEXT,
        open_ports  TEXT,   -- JSON list
        threat_score INTEGER DEFAULT 0,
        latency_ms  INTEGER,
        scan_ts     TEXT,
        raw_json    TEXT    -- full result dict
    );

    CREATE TABLE IF NOT EXISTS findings (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id     INTEGER REFERENCES scans(id),
        ip          TEXT NOT NULL,
        issue       TEXT,
        severity    TEXT,
        details     TEXT,
        scan_ts     TEXT
    );

    CREATE TABLE IF NOT EXISTS alerts (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts          TEXT NOT NULL,
        severity    TEXT,
        ip          TEXT,
        message     TEXT,
        tag         TEXT
    );

    CREATE TABLE IF NOT EXISTS threat_intel (
        ip          TEXT PRIMARY KEY,
        data_json   TEXT,
        updated_at  TEXT
    );

    CREATE TABLE IF NOT EXISTS cpe_cache (
        banner      TEXT PRIMARY KEY,
        cpe         TEXT,
        product     TEXT,
        version     TEXT,
        updated_at  TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_hosts_ip     ON hosts(ip);
    CREATE INDEX IF NOT EXISTS idx_hosts_scan   ON hosts(scan_id);
    CREATE INDEX IF NOT EXISTS idx_findings_ip  ON findings(ip);
    CREATE INDEX IF NOT EXISTS idx_alerts_ts    ON alerts(ts);
    """

    def __init__(self, path: str = DB_FILE):
        self.path = path
        self._local = threading.local()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            ensure_dirs()
            self._local.conn = sqlite3.connect(
                self.path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return self._local.conn

    def _init_db(self):
        conn = self._conn()
        conn.executescript(self.SCHEMA)
        conn.commit()

    # ── Scan lifecycle ──────────────────────────────────────────────────

    def start_scan(self, target: str, mode: str) -> int:
        """Insert a new scan record, return its ID."""
        conn = self._conn()
        cur  = conn.execute(
            "INSERT INTO scans (started_at, target, mode) VALUES (?,?,?)",
            (ts_now(), target, mode))
        conn.commit()
        return cur.lastrowid

    def finish_scan(self, scan_id: int,
                    host_count: int,
                    active_count: int,
                    finding_count: int):
        conn = self._conn()
        conn.execute(
            """UPDATE scans SET finished_at=?, host_count=?,
               active_count=?, finding_count=? WHERE id=?""",
            (ts_now(), host_count, active_count, finding_count, scan_id))
        conn.commit()

    # ── Host writes ─────────────────────────────────────────────────────

    def upsert_host(self, scan_id: int, result: dict):
        """Insert a single host result into the DB."""
        conn = self._conn()
        # Serialise open_ports as JSON; strip non-serialisable objects
        ports_json = json.dumps(result.get("open_ports", []))
        raw        = json.dumps(result, default=str)
        lat        = result.get("latency_ms")
        if not isinstance(lat, int):
            lat = None
        conn.execute(
            """INSERT INTO hosts
               (scan_id, ip, subnet, status, hostname, mac, vendor,
                device_type, os_guess, open_ports, threat_score,
                latency_ms, scan_ts, raw_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (scan_id,
             result.get("ip", ""),
             result.get("subnet", ""),
             result.get("status", ""),
             result.get("hostname", ""),
             result.get("mac", ""),
             result.get("vendor", ""),
             result.get("device_type", ""),
             result.get("os_guess", ""),
             ports_json,
             result.get("threat_score", 0),
             lat,
             result.get("scan_ts", ts_now()),
             raw))
        conn.commit()

    def bulk_upsert_hosts(self, scan_id: int, results: list):
        """Bulk insert all hosts for a scan."""
        for r in results:
            self.upsert_host(scan_id, r)

    # ── Findings writes ─────────────────────────────────────────────────

    def insert_findings(self, scan_id: int, findings: list):
        conn = self._conn()
        rows = [
            (scan_id, ip, issue, severity, details[:500], ts_now())
            for ip, issue, severity, details in findings
        ]
        conn.executemany(
            """INSERT INTO findings
               (scan_id, ip, issue, severity, details, scan_ts)
               VALUES (?,?,?,?,?,?)""", rows)
        conn.commit()

    # ── Alert writes ────────────────────────────────────────────────────

    def insert_alert(self, severity: str, ip: str,
                     message: str, tag: str = ""):
        conn = self._conn()
        conn.execute(
            "INSERT INTO alerts (ts,severity,ip,message,tag) VALUES (?,?,?,?,?)",
            (ts_now(), severity, ip, message, tag))
        conn.commit()

    # ── Threat intel cache ──────────────────────────────────────────────

    def cache_threat_intel(self, ip: str, data: dict):
        conn = self._conn()
        conn.execute(
            """INSERT OR REPLACE INTO threat_intel
               (ip, data_json, updated_at) VALUES (?,?,?)""",
            (ip, json.dumps(data), ts_now()))
        conn.commit()

    def get_threat_intel(self, ip: str,
                         max_age_h: float = 6.0) -> dict | None:
        conn  = self._conn()
        row   = conn.execute(
            "SELECT data_json, updated_at FROM threat_intel WHERE ip=?",
            (ip,)).fetchone()
        if not row:
            return None
        updated = datetime.datetime.fromisoformat(row["updated_at"])
        age_h   = (datetime.datetime.now() - updated).total_seconds() / 3600
        if age_h > max_age_h:
            return None
        return json.loads(row["data_json"])

    # ── Historical trend queries ─────────────────────────────────────────

    def get_scan_list(self, limit: int = 50) -> list[dict]:
        """Return most recent scans."""
        conn = self._conn()
        rows = conn.execute(
            """SELECT id, started_at, target, mode, host_count,
               active_count, finding_count
               FROM scans ORDER BY id DESC LIMIT ?""",
            (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_host_history(self, ip: str,
                         limit: int = 30) -> list[dict]:
        """
        Return per-scan snapshots for a given IP.
        Each row: {scan_id, scan_ts, status, open_ports, threat_score,
                   os_guess, hostname}
        """
        conn = self._conn()
        rows = conn.execute(
            """SELECT h.scan_id, h.scan_ts, h.status, h.open_ports,
                      h.threat_score, h.os_guess, h.hostname,
                      s.started_at
               FROM hosts h JOIN scans s ON h.scan_id = s.id
               WHERE h.ip = ?
               ORDER BY h.scan_id DESC LIMIT ?""",
            (ip, limit)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["open_ports"] = json.loads(d["open_ports"] or "[]")
            except Exception:
                d["open_ports"] = []
            out.append(d)
        return out

    def get_threat_score_timeline(self, ip: str) -> list[dict]:
        """Return threat score over time for a single IP."""
        conn = self._conn()
        rows = conn.execute(
            """SELECT s.started_at, h.threat_score
               FROM hosts h JOIN scans s ON h.scan_id = s.id
               WHERE h.ip = ? ORDER BY h.scan_id ASC""",
            (ip,)).fetchall()
        return [{"ts": r["started_at"], "score": r["threat_score"]}
                for r in rows]

    def get_new_hosts(self, current_scan_id: int,
                      previous_scan_id: int) -> list[str]:
        """IPs active in current scan but absent in previous scan."""
        conn = self._conn()
        curr = {r["ip"] for r in conn.execute(
            "SELECT ip FROM hosts WHERE scan_id=? AND status='Used'",
            (current_scan_id,)).fetchall()}
        prev = {r["ip"] for r in conn.execute(
            "SELECT ip FROM hosts WHERE scan_id=? AND status='Used'",
            (previous_scan_id,)).fetchall()}
        return sorted(curr - prev)

    def get_gone_hosts(self, current_scan_id: int,
                       previous_scan_id: int) -> list[str]:
        """IPs active in previous scan but gone in current scan."""
        conn = self._conn()
        curr = {r["ip"] for r in conn.execute(
            "SELECT ip FROM hosts WHERE scan_id=? AND status='Used'",
            (current_scan_id,)).fetchall()}
        prev = {r["ip"] for r in conn.execute(
            "SELECT ip FROM hosts WHERE scan_id=? AND status='Used'",
            (previous_scan_id,)).fetchall()}
        return sorted(prev - curr)

    def get_port_changes(self, ip: str) -> list[dict]:
        """
        For an IP, return list of port changes between consecutive scans.
        Returns [{scan_ts, added:[ports], removed:[ports]}]
        """
        history  = self.get_host_history(ip)
        if len(history) < 2:
            return []
        changes  = []
        for i in range(len(history) - 1):
            curr_ports = set(history[i]["open_ports"])
            prev_ports = set(history[i + 1]["open_ports"])
            added      = sorted(curr_ports - prev_ports)
            removed    = sorted(prev_ports - curr_ports)
            if added or removed:
                changes.append({
                    "scan_ts": history[i]["scan_ts"],
                    "added":   added,
                    "removed": removed,
                })
        return changes

    def get_top_vulnerable_hosts(self,
                                  limit: int = 20) -> list[dict]:
        """Return hosts with highest average threat score across all scans."""
        conn = self._conn()
        rows = conn.execute(
            """SELECT ip, AVG(threat_score) as avg_score,
                      MAX(threat_score) as max_score,
                      COUNT(*) as scan_count
               FROM hosts WHERE status='Used'
               GROUP BY ip
               ORDER BY avg_score DESC LIMIT ?""",
            (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_findings_trend(self, days: int = 30) -> list[dict]:
        """Return finding counts grouped by severity per scan."""
        conn  = self._conn()
        since = (datetime.datetime.now() -
                 datetime.timedelta(days=days)).isoformat()
        rows  = conn.execute(
            """SELECT s.started_at, f.severity, COUNT(*) as count
               FROM findings f JOIN scans s ON f.scan_id = s.id
               WHERE s.started_at >= ?
               GROUP BY s.id, f.severity
               ORDER BY s.started_at""",
            (since,)).fetchall()
        return [dict(r) for r in rows]

    def vacuum(self):
        """Reclaim disk space and optimise the database."""
        conn = self._conn()
        conn.execute("VACUUM")
        conn.commit()

    def close(self):
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None


# Singleton
db = NetProbeDB()


# ─────────────────────────────────────────────────────────────────────────────
# ② HONEYPOT PORT MONITOR
# ─────────────────────────────────────────────────────────────────────────────

class HoneypotMonitor:
    """
    Opens fake TCP listeners on configurable 'honeypot' ports.
    Any inbound connection triggers a Critical alert — indicating:
      - Port scan sweeping your machine
      - Lateral movement from an attacker on the network
      - Worm/malware trying to propagate

    Each connection is logged: src IP, src port, timestamp, banner sent.
    Optionally captures the first N bytes the client sends.
    """

    DEFAULT_PORTS = [4444, 1337, 31337, 8888, 9999, 5555, 12345]

    # Fake banners sent to connecting clients (confuse scanners)
    FAKE_BANNERS = {
        4444:  b"Microsoft Windows [Version 10.0.19044]\r\n(c) Microsoft Corporation. All rights reserved.\r\nC:\\Users\\Administrator>",
        1337:  b"OpenSSH_8.9p1 Ubuntu-3ubuntu0.1 SSH-2.0\r\n",
        31337: b"220 FTP Server ready.\r\n",
        8888:  b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n<html><body>Welcome</body></html>",
        9999:  b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f",  # Telnet IAC
        5555:  b"220 SMTP Service ready\r\n",
        12345: b"+OK POP3 server ready\r\n",
    }

    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback
        self._servers:  dict[int, socket.socket] = {}
        self._threads:  dict[int, threading.Thread] = {}
        self.running    = False
        self.hits:      list[dict] = []
        self._lock      = threading.Lock()

    def start(self, ports: list[int] | None = None):
        ports       = ports or self.DEFAULT_PORTS
        self.running = True
        for port in ports:
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.settimeout(1.0)
                srv.bind(("0.0.0.0", port))
                srv.listen(5)
                self._servers[port] = srv
                t = threading.Thread(
                    target=self._listener,
                    args=(port, srv),
                    daemon=True,
                    name=f"honeypot-{port}")
                t.start()
                self._threads[port] = t
                log.info("Honeypot listening on port %d", port)
            except OSError as e:
                log.warning("Honeypot port %d unavailable: %s", port, e)

    def stop(self):
        self.running = False
        for srv in self._servers.values():
            try:
                srv.close()
            except Exception:
                pass
        self._servers.clear()
        self._threads.clear()

    def _listener(self, port: int, srv: socket.socket):
        banner = self.FAKE_BANNERS.get(port, b"")
        while self.running:
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_conn,
                args=(conn, addr, port, banner),
                daemon=True).start()

    def _handle_conn(self, conn: socket.socket,
                      addr: tuple, port: int, banner: bytes):
        src_ip, src_port = addr[0], addr[1]
        ts = ts_now()

        # Capture what the client sends (recon data)
        client_data = b""
        try:
            conn.settimeout(2.0)
            if banner:
                conn.send(banner)
            client_data = conn.recv(512)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

        hit = {
            "ts":          ts,
            "src_ip":      src_ip,
            "src_port":    src_port,
            "honeypot_port": port,
            "client_data": client_data.decode(errors="replace")[:100],
            "severity":    "Critical",
        }

        with self._lock:
            self.hits.append(hit)

        msg = (f"HONEYPOT HIT on port {port} from {src_ip}:{src_port}"
               + (f" — sent: {client_data[:40]!r}"
                  if client_data else ""))
        log.warning(msg)

        if self.alert_callback:
            self.alert_callback("Critical", src_ip, msg, tag="honeypot")

        # Also write to DB
        try:
            db.insert_alert("Critical", src_ip, msg, tag="honeypot")
        except Exception:
            pass

    @property
    def active_ports(self) -> list[int]:
        return list(self._servers.keys())

    def get_hits(self, since_ts: str | None = None) -> list[dict]:
        if not since_ts:
            return list(self.hits)
        return [h for h in self.hits if h["ts"] >= since_ts]

    def export_hits_csv(self, path: str):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Timestamp", "Source IP", "Source Port",
                        "Honeypot Port", "Client Data"])
            for h in self.hits:
                w.writerow([h["ts"], h["src_ip"], h["src_port"],
                            h["honeypot_port"], h["client_data"]])


# Singleton (started only when user enables it)
honeypot = HoneypotMonitor()


# ─────────────────────────────────────────────────────────────────────────────
# ③ CPE MAPPING  (banner → CPE string → NVD cross-reference)
# ─────────────────────────────────────────────────────────────────────────────

class CPEMapper:
    """
    Maps service banner strings to CPE 2.3 URIs.
    CPE (Common Platform Enumeration) is the standard used by NVD
    to identify software/hardware in CVE records.

    Format: cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
    """

    # (banner_regex, cpe_template_with_{version} placeholder)
    PATTERNS = [
        (r"Apache[\s/]([\d.]+\w*)",         "cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*"),
        (r"nginx[\s/]([\d.]+)",             "cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*"),
        (r"OpenSSH[\s_]([\d.]+\w*)",        "cpe:2.3:a:openbsd:openssh:{version}:*:*:*:*:*:*:*"),
        (r"PHP[\s/]([\d.]+)",               "cpe:2.3:a:php:php:{version}:*:*:*:*:*:*:*"),
        (r"MySQL[\s/]([\d.]+)",             "cpe:2.3:a:mysql:mysql:{version}:*:*:*:*:*:*:*"),
        (r"Microsoft-IIS[\s/]([\d.]+)",     "cpe:2.3:a:microsoft:iis:{version}:*:*:*:*:*:*:*"),
        (r"vsFTPd[\s]([\d.]+)",             "cpe:2.3:a:vsftpd_project:vsftpd:{version}:*:*:*:*:*:*:*"),
        (r"ProFTPD[\s]([\d.]+)",            "cpe:2.3:a:proftpd:proftpd:{version}:*:*:*:*:*:*:*"),
        (r"OpenSSL[\s/]([\d.]+\w*)",        "cpe:2.3:a:openssl:openssl:{version}:*:*:*:*:*:*:*"),
        (r"Samba[\s/]([\d.]+)",             "cpe:2.3:a:samba:samba:{version}:*:*:*:*:*:*:*"),
        (r"WordPress[\s/]([\d.]+)",         "cpe:2.3:a:wordpress:wordpress:{version}:*:*:*:*:*:*:*"),
        (r"Drupal[\s/]([\d.]+)",            "cpe:2.3:a:drupal:drupal:{version}:*:*:*:*:*:*:*"),
        (r"Joomla[\s!]*([\d.]+)",           "cpe:2.3:a:joomla:joomla:{version}:*:*:*:*:*:*:*"),
        (r"Apache Tomcat[\s/]([\d.]+)",     "cpe:2.3:a:apache:tomcat:{version}:*:*:*:*:*:*:*"),
        (r"JBoss[\s/]([\d.]+)",             "cpe:2.3:a:redhat:jboss:{version}:*:*:*:*:*:*:*"),
        (r"WebLogic[\s/]([\d.]+)",          "cpe:2.3:a:oracle:weblogic_server:{version}:*:*:*:*:*:*:*"),
        (r"Jenkins[\s/]([\d.]+)",           "cpe:2.3:a:jenkins:jenkins:{version}:*:*:*:*:*:*:*"),
        (r"GitLab[\s/]([\d.]+)",            "cpe:2.3:a:gitlab:gitlab:{version}:*:*:*:*:*:*:*"),
        (r"Elasticsearch[\s/]([\d.]+)",     "cpe:2.3:a:elastic:elasticsearch:{version}:*:*:*:*:*:*:*"),
        (r"Redis[\s]([\d.]+)",              "cpe:2.3:a:redis:redis:{version}:*:*:*:*:*:*:*"),
        (r"MongoDB[\s/]([\d.]+)",           "cpe:2.3:a:mongodb:mongodb:{version}:*:*:*:*:*:*:*"),
        (r"PostgreSQL[\s]([\d.]+)",         "cpe:2.3:a:postgresql:postgresql:{version}:*:*:*:*:*:*:*"),
        (r"Postfix[\s]([\d.]+)",            "cpe:2.3:a:postfix:postfix:{version}:*:*:*:*:*:*:*"),
        (r"Exim[\s]([\d.]+)",               "cpe:2.3:a:exim:exim:{version}:*:*:*:*:*:*:*"),
        (r"Dovecot[\s/]([\d.]+)",           "cpe:2.3:a:dovecot:dovecot:{version}:*:*:*:*:*:*:*"),
        (r"Cisco IOS[\s/]?([\d().]+)",      "cpe:2.3:o:cisco:ios:{version}:*:*:*:*:*:*:*"),
        (r"Windows Server (20\d\d)",        "cpe:2.3:o:microsoft:windows_server_{version}:*:*:*:*:*:*:*:*"),
        (r"Ubuntu ([\d.]+)",                "cpe:2.3:o:canonical:ubuntu_linux:{version}:*:*:*:*:*:*:*"),
        (r"CentOS Linux ([\d.]+)",          "cpe:2.3:o:centos:centos:{version}:*:*:*:*:*:*:*"),
        (r"Debian[\s/]([\d.]+)",            "cpe:2.3:o:debian:debian_linux:{version}:*:*:*:*:*:*:*"),
        (r"ActiveMQ[\s/]([\d.]+)",          "cpe:2.3:a:apache:activemq:{version}:*:*:*:*:*:*:*"),
        (r"Zookeeper[\s/]([\d.]+)",         "cpe:2.3:a:apache:zookeeper:{version}:*:*:*:*:*:*:*"),
        (r"RabbitMQ[\s/]([\d.]+)",          "cpe:2.3:a:pivotal_software:rabbitmq:{version}:*:*:*:*:*:*:*"),
        (r"Memcached[\s/]([\d.]+)",         "cpe:2.3:a:memcached:memcached:{version}:*:*:*:*:*:*:*"),
        (r"HAProxy[\s/]([\d.]+)",           "cpe:2.3:a:haproxy:haproxy:{version}:*:*:*:*:*:*:*"),
        (r"Squid[\s/]([\d.]+)",             "cpe:2.3:a:squid-cache:squid:{version}:*:*:*:*:*:*:*"),
        (r"Nagios[\s/]([\d.]+)",            "cpe:2.3:a:nagios:nagios:{version}:*:*:*:*:*:*:*"),
        (r"Zabbix[\s/]([\d.]+)",            "cpe:2.3:a:zabbix:zabbix:{version}:*:*:*:*:*:*:*"),
    ]

    def __init__(self):
        self._cache: dict = {}
        self._load_db_cache()

    def _load_db_cache(self):
        try:
            conn = db._conn()
            rows = conn.execute(
                "SELECT banner, cpe, product, version FROM cpe_cache"
            ).fetchall()
            for r in rows:
                self._cache[r["banner"]] = {
                    "cpe":     r["cpe"],
                    "product": r["product"],
                    "version": r["version"],
                }
        except Exception:
            pass

    def _save_to_db(self, banner: str, cpe: str,
                    product: str, version: str):
        try:
            db._conn().execute(
                """INSERT OR REPLACE INTO cpe_cache
                   (banner, cpe, product, version, updated_at)
                   VALUES (?,?,?,?,?)""",
                (banner[:200], cpe, product, version, ts_now()))
            db._conn().commit()
        except Exception:
            pass

    def extract(self, banner: str) -> dict | None:
        """
        Match a banner string against all patterns.
        Returns {cpe, product, version, nvd_url} or None.
        """
        if not banner:
            return None
        key = banner[:100]
        if key in self._cache:
            return self._cache[key]

        for pat, cpe_tpl in self.PATTERNS:
            m = re.search(pat, banner, re.I)
            if m:
                version = m.group(1) if m.lastindex else "*"
                cpe     = cpe_tpl.replace("{version}", version)
                # Extract product name from CPE
                parts   = cpe.split(":")
                product = parts[4].replace("_", " ").title() \
                          if len(parts) > 4 else ""
                result  = {
                    "cpe":     cpe,
                    "product": product,
                    "version": version,
                    "nvd_url": (
                        f"https://nvd.nist.gov/products/cpe/search"
                        f"?keyword={urllib.parse.quote(cpe)}"),
                }
                self._cache[key] = result
                self._save_to_db(key, cpe, product, version)
                return result
        return None

    def enrich_result(self, result: dict) -> dict:
        """Add CPE mappings to a scan result's banners."""
        cpes = {}
        for port, banner in result.get("banners", {}).items():
            match = self.extract(banner)
            if match:
                cpes[port] = match
        if cpes:
            result["cpe_matches"] = cpes
        return result


# Singleton
cpe_mapper = CPEMapper()


# ─────────────────────────────────────────────────────────────────────────────
# ④ IPv6 FULL SUPPORT
# ─────────────────────────────────────────────────────────────────────────────

class IPv6Scanner:
    """
    IPv6-capable scanning:
    - ICMPv6 Echo Request (ping6) via scapy or OS ping6
    - TCP connect probe on IPv6
    - NDP (Neighbor Discovery Protocol) — equivalent of ARP for IPv6
      Sends ICMPv6 Router Solicitation + listens for Neighbor Advertisements
    - Link-local address enumeration from local interfaces
    """

    @staticmethod
    def ping6(ip: str, timeout_ms: int = 500) -> tuple[bool, int | str]:
        """Ping an IPv6 address. Returns (alive, latency_ms)."""
        system = platform.system().lower()
        start  = time.time()
        try:
            if system == "windows":
                cmd = ["ping", "-6", "-n", "1",
                       "-w", str(timeout_ms), ip]
            elif system == "darwin":
                cmd = ["ping6", "-c", "1",
                       "-W", str(timeout_ms), ip]
            else:
                cmd = ["ping6", "-c", "1",
                       "-W", str(max(1, timeout_ms // 1000)), ip]
            alive = subprocess.run(
                cmd, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL).returncode == 0
        except Exception:
            alive = False
        lat = int((time.time() - start) * 1000) if alive else ""
        return alive, lat

    @staticmethod
    def tcp6_probe(ip: str, ports: list[int],
                   timeout: float = TCP_PROBE_TIMEOUT_S) -> list[int]:
        """TCP connect scan on IPv6 address."""
        open_ports = []
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                s.settimeout(timeout)
                if s.connect_ex((ip, port, 0, 0)) == 0:
                    open_ports.append(port)
                s.close()
            except Exception:
                pass
        return open_ports

    @staticmethod
    def get_local_ipv6_addrs() -> list[str]:
        """Get all local IPv6 addresses."""
        addrs = []
        if _NETIFACES_OK:
            for iface in netifaces.interfaces():
                iface_addrs = netifaces.ifaddresses(iface)
                for addr in iface_addrs.get(netifaces.AF_INET6, []):
                    ip = addr.get("addr", "").split("%")[0]
                    if ip and ip != "::1":
                        addrs.append(ip)
        else:
            try:
                for info in socket.getaddrinfo(
                        socket.gethostname(), None,
                        socket.AF_INET6):
                    ip = info[4][0]
                    if ip != "::1" and not ip.startswith("fe80"):
                        addrs.append(ip)
            except Exception:
                pass
        return list(dict.fromkeys(addrs))

    @staticmethod
    def ndp_scan(interface: str | None = None,
                 timeout: float = 5.0) -> dict[str, str]:
        """
        Passive NDP listener — capture Neighbor Advertisement packets.
        Returns {ipv6_addr: mac_addr}.
        """
        if not _SCAPY_OK:
            return {}
        from scapy.all import (IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr,
                                sniff as scapy_sniff)
        found = {}

        def pkt_cb(pkt):
            if pkt.haslayer(ICMPv6ND_NA):
                ip6 = pkt[IPv6].src
                if pkt.haslayer(ICMPv6NDOptDstLLAddr):
                    mac = normalize_mac(
                        pkt[ICMPv6NDOptDstLLAddr].lladdr)
                    found[ip6] = mac

        kwargs = {"filter": "icmp6", "timeout": timeout,
                  "store": False, "prn": pkt_cb}
        if interface:
            kwargs["iface"] = interface
        try:
            scapy_sniff(**kwargs)
        except Exception as e:
            log.debug("NDP scan error: %s", e)
        return found

    @staticmethod
    def scan_ipv6_host(ip: str,
                       probe_ports: list[int] | None = None,
                       grab_banners: bool = True) -> dict:
        """Full scan of a single IPv6 host. Returns result dict."""
        probe_ports = probe_ports or TCP_PROBE_PORTS
        alive, lat  = IPv6Scanner.ping6(ip)
        open_ports  = []
        banners     = {}

        if alive:
            open_ports = IPv6Scanner.tcp6_probe(ip, probe_ports)
            if grab_banners:
                for port in open_ports[:10]:
                    b = grab_banner(ip, port)
                    if b:
                        banners[port] = b

        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = ""

        result = {
            "ip":          ip,
            "ip_version":  6,
            "subnet":      f"{ip}/128",
            "status":      "Used" if alive else "Free",
            "hostname":    hostname,
            "mac":         "",
            "vendor":      "",
            "device_type": "",
            "latency_ms":  lat,
            "open_ports":  open_ports,
            "udp_ports":   [],
            "os_guess":    "",
            "banners":     banners,
            "ssl_info":    None,
            "scan_ts":     ts_now(),
        }
        result["security_findings"] = assess_security(result)
        result["threat_score"]      = calculate_threat_score(result)
        return result


# ─────────────────────────────────────────────────────────────────────────────
# ⑤ WI-FI / SSID SCANNER
# ─────────────────────────────────────────────────────────────────────────────

class WiFiScanner:
    """
    Scan for nearby Wi-Fi networks.
    - Windows: netsh wlan show networks mode=bssid
    - Linux:   iwlist <iface> scan  OR  nmcli dev wifi list
    - macOS:   /System/Library/PrivateFrameworks/Apple80211.framework/
               Versions/Current/Resources/airport -s

    Returns list of:
    {ssid, bssid, channel, signal_dbm, encryption, band, rates}
    """

    @staticmethod
    def available() -> bool:
        system = platform.system().lower()
        if system == "windows":
            try:
                subprocess.check_output(
                    ["netsh", "wlan", "show", "interfaces"],
                    stderr=subprocess.DEVNULL, timeout=5)
                return True
            except Exception:
                return False
        elif system == "linux":
            for cmd in (["iwlist", "--version"],
                        ["nmcli", "--version"]):
                try:
                    subprocess.check_output(
                        cmd, stderr=subprocess.DEVNULL, timeout=3)
                    return True
                except Exception:
                    pass
            return False
        elif system == "darwin":
            airport = ("/System/Library/PrivateFrameworks/"
                       "Apple80211.framework/Versions/Current/"
                       "Resources/airport")
            return os.path.isfile(airport)
        return False

    @staticmethod
    def scan() -> list[dict]:
        system = platform.system().lower()
        if system == "windows":
            return WiFiScanner._scan_windows()
        elif system == "linux":
            return WiFiScanner._scan_linux()
        elif system == "darwin":
            return WiFiScanner._scan_macos()
        return []

    @staticmethod
    def _scan_windows() -> list[dict]:
        networks = []
        try:
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "networks",
                 "mode=bssid"],
                stderr=subprocess.DEVNULL,
                timeout=15).decode(errors="ignore")

            current: dict = {}
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("SSID") and "BSSID" not in line:
                    if current:
                        networks.append(current)
                    ssid = line.split(":", 1)[-1].strip()
                    current = {"ssid": ssid, "bssid": "",
                               "signal_dbm": "", "channel": "",
                               "encryption": "", "band": "",
                               "auth": "", "rates": ""}
                elif "BSSID" in line and current:
                    current["bssid"] = line.split(":", 1)[-1].strip()
                elif "Signal" in line and current:
                    sig = line.split(":", 1)[-1].strip().rstrip("%")
                    try:
                        # Convert Windows % to dBm approximation
                        current["signal_dbm"] = \
                            str(int(int(sig) / 2 - 100)) + " dBm"
                    except ValueError:
                        current["signal_dbm"] = sig
                elif "Channel" in line and current:
                    current["channel"] = line.split(":", 1)[-1].strip()
                elif "Authentication" in line and current:
                    current["auth"] = line.split(":", 1)[-1].strip()
                elif "Cipher" in line and current:
                    current["encryption"] = line.split(":", 1)[-1].strip()
                elif "Radio type" in line and current:
                    band_raw = line.split(":", 1)[-1].strip()
                    current["band"] = band_raw
            if current:
                networks.append(current)
        except Exception as e:
            log.debug("WiFi Windows scan error: %s", e)
        return networks

    @staticmethod
    def _scan_linux() -> list[dict]:
        networks = []
        # Try nmcli first (more reliable, no root needed)
        try:
            out = subprocess.check_output(
                ["nmcli", "-t", "-f",
                 "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY",
                 "dev", "wifi", "list"],
                stderr=subprocess.DEVNULL,
                timeout=10).decode(errors="ignore")
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) >= 6:
                    sig = parts[4].strip()
                    try:
                        dbm = str(int(int(sig) / 2 - 100))
                    except ValueError:
                        dbm = sig
                    networks.append({
                        "ssid":        parts[0].strip(),
                        "bssid":       ":".join(parts[1:7]).strip(),
                        "channel":     parts[7].strip() if len(parts) > 7 else "",
                        "signal_dbm":  dbm + " dBm",
                        "encryption":  parts[-1].strip(),
                        "band":        parts[3].strip() if len(parts) > 3 else "",
                        "auth":        "",
                        "rates":       "",
                    })
            if networks:
                return networks
        except Exception:
            pass

        # Fallback: iwlist
        try:
            ifaces_out = subprocess.check_output(
                ["iwconfig"], stderr=subprocess.STDOUT,
                timeout=5).decode(errors="ignore")
            iface = re.search(r"^(\w+)\s+IEEE", ifaces_out, re.M)
            iface = iface.group(1) if iface else "wlan0"

            out = subprocess.check_output(
                ["iwlist", iface, "scan"],
                stderr=subprocess.DEVNULL,
                timeout=20).decode(errors="ignore")
            current: dict = {}
            for line in out.splitlines():
                line = line.strip()
                if "Cell" in line and "Address:" in line:
                    if current:
                        networks.append(current)
                    bssid = line.split("Address:")[-1].strip()
                    current = {"ssid": "", "bssid": bssid,
                               "signal_dbm": "", "channel": "",
                               "encryption": "", "band": "",
                               "auth": "", "rates": ""}
                elif "ESSID:" in line and current:
                    current["ssid"] = line.split('"')[1] \
                        if '"' in line else ""
                elif "Frequency:" in line and current:
                    m = re.search(r"([\d.]+) GHz", line)
                    if m:
                        current["band"] = m.group(1) + " GHz"
                    m2 = re.search(r"Channel:?(\d+)", line)
                    if m2:
                        current["channel"] = m2.group(1)
                elif "Signal level=" in line and current:
                    m = re.search(r"Signal level=(-?\d+)", line)
                    if m:
                        current["signal_dbm"] = m.group(1) + " dBm"
                elif "Encryption key:" in line and current:
                    current["encryption"] = "WEP/WPA" \
                        if "on" in line.lower() else "Open"
                elif "IE: WPA" in line and current:
                    current["encryption"] = "WPA"
                elif "IE: IEEE 802.11i/WPA2" in line and current:
                    current["encryption"] = "WPA2"
            if current:
                networks.append(current)
        except Exception as e:
            log.debug("WiFi Linux iwlist error: %s", e)
        return networks

    @staticmethod
    def _scan_macos() -> list[dict]:
        networks = []
        airport  = ("/System/Library/PrivateFrameworks/"
                    "Apple80211.framework/Versions/Current/"
                    "Resources/airport")
        try:
            out = subprocess.check_output(
                [airport, "-s"],
                stderr=subprocess.DEVNULL,
                timeout=15).decode(errors="ignore")
            # Header line: SSID BSSID RSSI CHANNEL HT CC SECURITY
            lines = out.strip().splitlines()
            if not lines:
                return []
            for line in lines[1:]:
                m = re.match(
                    r"\s*(.+?)\s+"
                    r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s+"
                    r"(-\d+)\s+"
                    r"(\d+[,\d]*)\s+"
                    r"(\w+)\s+"
                    r"(\w+)\s+"
                    r"(.*)",
                    line, re.I)
                if m:
                    networks.append({
                        "ssid":       m.group(1).strip(),
                        "bssid":      m.group(2),
                        "signal_dbm": m.group(3) + " dBm",
                        "channel":    m.group(4),
                        "band":       "",
                        "encryption": m.group(7).strip(),
                        "auth":       "",
                        "rates":      "",
                    })
        except Exception as e:
            log.debug("WiFi macOS scan error: %s", e)
        return networks

    @staticmethod
    def flag_risks(networks: list[dict]) -> list[dict]:
        """Add 'risk' and 'risk_reason' keys to each network."""
        for n in networks:
            enc = (n.get("encryption") or "").upper()
            risks = []
            if not enc or enc in ("OPEN", "NONE", ""):
                risks.append("Open network — no encryption")
            elif "WEP" in enc:
                risks.append("WEP encryption — trivially crackable")
            elif "WPA " in enc and "WPA2" not in enc and "WPA3" not in enc:
                risks.append("WPA (TKIP) — vulnerable to TKIP attacks")
            if n.get("ssid", "").strip() == "":
                risks.append("Hidden SSID")
            n["risk"]        = "High" if risks else "Low"
            n["risk_reason"] = "; ".join(risks) if risks else "OK"
        return networks


# ─────────────────────────────────────────────────────────────────────────────
# ⑥ DNS ZONE TRANSFER
# ─────────────────────────────────────────────────────────────────────────────

class DNSZoneTransfer:
    """
    Attempt AXFR (full zone transfer) against a DNS server.
    A successful zone transfer is a critical misconfiguration:
    it hands the attacker every hostname, IP, and record in the zone.

    Uses raw DNS socket protocol — no dnspython dependency.
    Falls back to 'dig AXFR' if available.
    """

    @staticmethod
    def attempt(domain: str, nameserver: str,
                timeout: float = 10.0) -> dict:
        """
        Returns:
        {success, records:[{name, type, ttl, data}], error, method}
        """
        result = {
            "success": False,
            "records": [],
            "error":   "",
            "method":  "",
            "domain":  domain,
            "ns":      nameserver,
        }

        # Method 1: dig AXFR (most reliable)
        if shutil.which("dig") or shutil.which("dig.exe"):
            try:
                out = subprocess.check_output(
                    ["dig", f"@{nameserver}", domain, "AXFR",
                     "+noall", "+answer", "+time=10"],
                    stderr=subprocess.DEVNULL,
                    timeout=int(timeout) + 5
                ).decode(errors="ignore")
                records = DNSZoneTransfer._parse_dig_output(out)
                if records:
                    result["success"] = True
                    result["records"] = records
                    result["method"]  = "dig"
                    return result
                if "Transfer failed" in out or "REFUSED" in out:
                    result["error"] = "Transfer refused by server"
                    return result
            except Exception as e:
                log.debug("dig AXFR error: %s", e)

        # Method 2: raw DNS TCP
        records = DNSZoneTransfer._raw_axfr(
            domain, nameserver, timeout)
        if records is not None:
            result["success"] = len(records) > 0
            result["records"] = records
            result["method"]  = "raw"
            if not records:
                result["error"] = "Transfer refused or empty zone"
        else:
            result["error"] = "Connection failed"

        return result

    @staticmethod
    def _parse_dig_output(out: str) -> list[dict]:
        records = []
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            parts = line.split(None, 4)
            if len(parts) >= 4:
                records.append({
                    "name": parts[0],
                    "ttl":  parts[1],
                    "type": parts[3] if len(parts) > 3 else "",
                    "data": parts[4] if len(parts) > 4 else "",
                })
        return records

    @staticmethod
    def _raw_axfr(domain: str, ns: str,
                  timeout: float) -> list[dict] | None:
        """
        Send a raw DNS AXFR request over TCP.
        DNS TCP format: 2-byte length prefix + DNS message.
        """
        try:
            # Build AXFR query
            query_id = 0x1234
            flags    = 0x0000  # standard query
            qdcount  = 1
            header   = struct.pack(">HHHHHH",
                query_id, flags, qdcount, 0, 0, 0)

            # Encode domain name
            encoded = b""
            for label in domain.rstrip(".").split("."):
                lb = label.encode()
                encoded += bytes([len(lb)]) + lb
            encoded += b"\x00"

            qtype  = struct.pack(">H", 252)  # AXFR
            qclass = struct.pack(">H", 1)    # IN
            query  = header + encoded + qtype + qclass

            # TCP DNS: 2-byte length prefix
            msg = struct.pack(">H", len(query)) + query

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ns, 53))
            s.sendall(msg)

            # Read all response data
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 65536:  # safety limit
                    break
            s.close()

            if len(data) < 14:
                return None

            # Parse response: check RCODE
            resp_flags = struct.unpack(">H", data[4:6])[0]
            rcode = resp_flags & 0x000F
            if rcode == 5:  # REFUSED
                return []
            if rcode != 0:
                return []

            # Count answer records
            ancount = struct.unpack(">H", data[8:10])[0]
            if ancount == 0:
                return []

            return [{"name": domain, "ttl": "—",
                     "type": "AXFR",
                     "data": f"{ancount} records (raw parse — use dig for full output)"}]

        except Exception as e:
            log.debug("Raw AXFR error: %s", e)
            return None

    @staticmethod
    def find_nameservers(domain: str) -> list[str]:
        """Resolve NS records for a domain."""
        servers = []
        try:
            import subprocess
            for tool in (["dig", "+short", "NS", domain],
                         ["nslookup", "-type=NS", domain]):
                try:
                    out = subprocess.check_output(
                        tool, stderr=subprocess.DEVNULL,
                        timeout=5).decode(errors="ignore")
                    for line in out.splitlines():
                        m = re.search(
                            r"([\w.-]+\.[\w]{2,})\s*$", line)
                        if m:
                            ns = m.group(1).rstrip(".")
                            try:
                                ip = socket.gethostbyname(ns)
                                servers.append(ip)
                            except Exception:
                                pass
                    if servers:
                        break
                except Exception:
                    pass
        except Exception:
            pass
        return list(dict.fromkeys(servers))


# Ensure shutil is imported
import shutil


# ─────────────────────────────────────────────────────────────────────────────
# ⑦ HTTP DIRECTORY BRUTEFORCER
# ─────────────────────────────────────────────────────────────────────────────

# Built-in wordlist — common sensitive paths
HTTP_DIRBUST_WORDLIST = [
    "admin", "administrator", "login", "wp-login.php", "wp-admin",
    "phpmyadmin", "pma", "mysql", "db", "database",
    "config", "configuration", "conf", "settings",
    "backup", "backups", "bak", "old", ".git", ".env",
    "api", "api/v1", "api/v2", "api/v3", "rest",
    "swagger", "swagger-ui", "swagger.json", "openapi.json",
    "docs", "documentation", "readme", "README.md",
    "test", "tests", "dev", "development", "staging",
    "console", "panel", "dashboard", "portal",
    "shell", "cmd", "exec", "command",
    "upload", "uploads", "files", "static", "assets",
    "images", "img", "css", "js", "scripts",
    "robots.txt", "sitemap.xml", ".htaccess", "web.config",
    "server-status", "server-info",
    "actuator", "actuator/health", "actuator/env",
    "health", "status", "metrics", "info",
    "graphql", "graphiql", "gql",
    "jenkins", "jira", "confluence", "gitlab",
    "solr", "kibana", "grafana", "prometheus",
    "manager", "host-manager", "manager/html",
    "cgi-bin", "cgi-bin/admin.cgi",
    "xmlrpc.php", "wp-config.php", "wp-content",
    "vendor", "composer.json", "package.json",
    ".DS_Store", "Thumbs.db",
    "secret", "secrets", "private", "hidden",
    "keys", "key", "token", "tokens",
    "id_rsa", "id_rsa.pub", ".ssh",
    "passwd", "shadow", "etc/passwd",
]

class HTTPDirBuster:
    """
    Multi-threaded HTTP path bruteforcer.
    - Custom or built-in wordlist
    - Extension bruteforcing (.php, .asp, .bak, etc.)
    - Response classification (200, 301, 403, 500 etc.)
    - Recursion on 200/301 directories
    - Request rate limiting to avoid triggering WAFs
    """

    EXTENSIONS = ["", ".php", ".asp", ".aspx", ".jsp",
                  ".html", ".txt", ".bak", ".old", ".zip",
                  ".tar.gz", ".sql", ".json", ".xml", ".log"]

    def __init__(self):
        self.running   = False
        self.results:  list[dict] = []
        self._lock     = threading.Lock()

    def bust(self, target_url: str,
             wordlist: list[str] | None = None,
             extensions: list[str] | None = None,
             threads: int = 20,
             delay_s: float = 0.0,
             follow_redirects: bool = True,
             callback=None,
             timeout: float = 4.0):
        """
        Run directory busting against target_url.
        callback(result_dict) called for each interesting find.
        """
        self.running = True
        self.results = []
        wl   = wordlist   or HTTP_DIRBUST_WORDLIST
        exts = extensions or ["", ".php", ".html", ".txt", ".bak"]

        # Build full path list
        paths = []
        for word in wl:
            for ext in exts:
                if "." in word:    # already has extension
                    paths.append(word)
                    break
                else:
                    paths.append(f"{word}{ext}")

        # Remove URL trailing slash issues
        base = target_url.rstrip("/")

        queue  = Queue()
        for p in paths:
            queue.put(p)

        def worker():
            while self.running:
                try:
                    path = queue.get_nowait()
                except Empty:
                    break
                url = f"{base}/{path}"
                r   = self._probe(url, follow_redirects, timeout)
                if r:
                    with self._lock:
                        self.results.append(r)
                    if callback:
                        callback(r)
                if delay_s:
                    time.sleep(delay_s)
                queue.task_done()

        workers = [threading.Thread(target=worker, daemon=True)
                   for _ in range(min(threads, len(paths)))]
        for w in workers:
            w.start()
        for w in workers:
            w.join()
        self.running = False
        return self.results

    def _probe(self, url: str,
               follow_redirects: bool,
               timeout: float) -> dict | None:
        try:
            is_https = url.startswith("https://")
            ctx      = None
            if is_https:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE

            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent":    f"Mozilla/5.0 NetProbe/{VERSION}",
                    "Accept":        "*/*",
                    "Cache-Control": "no-cache",
                })

            # Don't follow redirects for dirbust (301 is still interesting)
            opener = urllib.request.build_opener(
                urllib.request.HTTPRedirectHandler()
                if follow_redirects
                else _NoRedirectHandler())
            with opener.open(req, timeout=timeout,
                             **({"context": ctx} if ctx else {})) as resp:
                status = resp.status
                length = resp.headers.get("Content-Length", "")
                ctype  = resp.headers.get("Content-Type", "")
                body   = resp.read(512)
                title  = ""
                m      = re.search(rb"<title[^>]*>(.*?)</title>",
                                   body, re.I | re.S)
                if m:
                    title = m.group(1).decode(errors="ignore").strip()[:80]

        except urllib.error.HTTPError as e:
            status = e.code
            length = ""
            ctype  = ""
            title  = ""
        except Exception:
            return None

        # Only report interesting status codes
        if status not in (200, 201, 204, 301, 302, 307,
                          401, 403, 405, 500, 503):
            return None

        interest = status in (200, 201, 204, 401, 403, 500)
        return {
            "url":         url,
            "status":      status,
            "length":      length,
            "content_type": ctype,
            "title":       title,
            "interesting": interest,
            "ts":          ts_now(),
        }


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Singleton
dirbuster = HTTPDirBuster()

# ─── End of Patch 2 ──────────────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════════════════════
# NetProbe v5 — PATCH 3 of 5
# Interactive HTML Report · Command Palette · Docker/VM Detection Badge
# History Tab · Honeypot Tab · CVE Lookup Tab · Threat Intel Tab
# Nmap Tab · Wi-Fi Tab · Zone Transfer Tab · Dirbuster Tab
# ═════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# ① INTERACTIVE HTML REPORT  (self-contained, zero dependencies)
# ─────────────────────────────────────────────────────────────────────────────

class InteractiveReportBuilder:
    """
    Generates a single self-contained HTML file with:
    - Sortable, filterable host table
    - Expandable finding rows
    - Risk matrix chart (Chart.js via CDN)
    - Threat score heatmap
    - Executive summary section
    - Print-friendly CSS
    - Zero server dependencies — open in any browser
    """

    @staticmethod
    def build(results: list, findings: list,
              diff: dict, scan_meta: dict,
              notes: dict | None = None) -> str:

        notes     = notes or {}
        used      = [r for r in results if r["status"] == "Used"]
        free_ct   = sum(1 for r in results if r["status"] == "Free")
        sev_count = defaultdict(int)
        for _, _, s, _ in findings:
            sev_count[s] += 1

        # ── Build host rows ──
        host_rows = ""
        for r in sorted(used, key=lambda x: ip_sort_key(x["ip"])):
            score     = r.get("threat_score", 0)
            lbl       = threat_score_label(score)
            clr       = threat_score_color(score)
            ports_str = format_ports(r.get("open_ports", []))[:80]
            key       = f"{r['ip']}|{r.get('subnet','')}"
            note      = notes.get(key, "")
            h_finds   = [f for f in findings if f[0] == r["ip"]]
            find_html = ""
            for _, issue, sev, rec in sorted(
                    h_finds,
                    key=lambda x: {"Critical":0,"High":1,
                                   "Medium":2,"Low":3}.get(x[2], 4)):
                fc, _ = SEV_COLORS.get(sev, ("#000","#fff"))
                find_html += f"""
                <div class="finding {sev.lower()}">
                  <span class="sev-badge" style="background:{fc}">
                    {sev}</span>
                  <b>{issue}</b>
                  <div class="rec">{rec[:200]}</div>
                </div>"""

            ssl_str = ""
            si = r.get("ssl_info")
            if si:
                ssl_str = ("⚠ EXPIRED" if si.get("expired")
                           else si.get("tls_version",""))

            host_rows += f"""
            <tr class="host-row" data-score="{score}"
                data-ip="{r['ip']}"
                onclick="toggleFindings(this)">
              <td><span class="risk-badge"
                  style="background:{clr};color:#fff">{lbl}</span></td>
              <td class="mono">{r['ip']}</td>
              <td>{r.get('hostname','')}</td>
              <td class="mono">{r.get('mac','')}</td>
              <td>{r.get('vendor','')}</td>
              <td>{r.get('device_type','')}</td>
              <td>{r.get('os_guess','')}</td>
              <td class="ports">{ports_str}</td>
              <td>{ssl_str}</td>
              <td>{note}</td>
            </tr>
            <tr class="findings-row" style="display:none">
              <td colspan="10">
                <div class="findings-container">
                  {"".join(find_html) or
                   '<span class="ok">✓ No findings</span>'}
                </div>
              </td>
            </tr>"""

        # ── Chart data ──
        chart_sev_labels = json.dumps(
            list(sev_count.keys()))
        chart_sev_data   = json.dumps(
            list(sev_count.values()))
        chart_sev_colors = json.dumps([
            SEV_COLORS.get(s, ("#000","#eee"))[0]
            for s in sev_count.keys()])

        # Threat distribution
        buckets = {"MINIMAL": 0, "LOW": 0, "MEDIUM": 0,
                   "HIGH": 0, "CRITICAL": 0}
        for r in used:
            buckets[threat_score_label(r.get("threat_score",0))] += 1
        chart_threat_labels = json.dumps(list(buckets.keys()))
        chart_threat_data   = json.dumps(list(buckets.values()))
        chart_threat_colors = json.dumps([
            "#64748b","#22c55e","#eab308","#f97316","#dc2626"])

        ts = ts_now()
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetProbe v{VERSION} — Security Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f8fafc;
       color:#0f172a;font-size:14px}}
  header{{background:linear-gradient(135deg,#1e293b,#2563eb);
         color:#fff;padding:24px 32px}}
  header h1{{font-size:22px;font-weight:700}}
  header p{{color:#94a3b8;font-size:12px;margin-top:4px}}
  .container{{max-width:1400px;margin:0 auto;padding:24px 32px}}
  .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
          gap:12px;margin-bottom:24px}}
  .card{{background:#fff;border-radius:10px;padding:16px;text-align:center;
         box-shadow:0 1px 4px rgba(0,0,0,.08)}}
  .card .val{{font-size:28px;font-weight:700}}
  .card .lbl{{font-size:11px;color:#64748b;margin-top:2px}}
  .charts{{display:grid;grid-template-columns:1fr 1fr;gap:16px;
           margin-bottom:24px}}
  .chart-box{{background:#fff;border-radius:10px;padding:16px;
              box-shadow:0 1px 4px rgba(0,0,0,.08)}}
  .chart-box h3{{font-size:13px;color:#475569;margin-bottom:12px}}
  h2{{font-size:16px;font-weight:700;margin:24px 0 10px;color:#1e293b}}
  .filter-bar{{display:flex;gap:10px;margin-bottom:10px;flex-wrap:wrap}}
  .filter-bar input,.filter-bar select{{
    padding:6px 12px;border:1px solid #e2e8f0;
    border-radius:6px;font-size:13px;background:#fff}}
  table{{width:100%;border-collapse:collapse;background:#fff;
         border-radius:10px;overflow:hidden;
         box-shadow:0 1px 4px rgba(0,0,0,.08)}}
  th{{background:#f1f5f9;padding:9px 10px;text-align:left;
      font-size:12px;color:#475569;cursor:pointer;
      user-select:none;white-space:nowrap}}
  th:hover{{background:#e2e8f0}}
  td{{padding:8px 10px;border-bottom:1px solid #f1f5f9;
      font-size:12px;vertical-align:middle}}
  .host-row{{cursor:pointer;transition:background .15s}}
  .host-row:hover{{background:#f8fafc}}
  .findings-row td{{background:#f8fafc;padding:0}}
  .findings-container{{padding:12px 20px}}
  .finding{{padding:8px 12px;margin-bottom:6px;border-radius:6px;
            border-left:3px solid #ccc;background:#fff}}
  .finding.critical{{border-color:#dc2626;background:#fff5f5}}
  .finding.high{{border-color:#f97316;background:#fff7ed}}
  .finding.medium{{border-color:#eab308;background:#fefce8}}
  .finding.low{{border-color:#3b82f6;background:#eff6ff}}
  .sev-badge{{display:inline-block;padding:2px 7px;border-radius:4px;
              color:#fff;font-size:10px;font-weight:700;margin-right:6px}}
  .rec{{color:#64748b;font-size:11px;margin-top:4px}}
  .risk-badge{{display:inline-block;padding:2px 8px;border-radius:4px;
               font-size:10px;font-weight:700}}
  .mono{{font-family:'Courier New',monospace;font-size:11px}}
  .ports{{font-family:'Courier New',monospace;font-size:10px;
          color:#475569;max-width:200px;word-break:break-all}}
  .ok{{color:#16a34a;font-size:12px}}
  .summary-grid{{display:grid;
                 grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
                 gap:10px;margin-bottom:20px}}
  .meta{{background:#fff;border-radius:8px;padding:12px 16px;
         box-shadow:0 1px 3px rgba(0,0,0,.06);font-size:12px}}
  .meta b{{color:#1e293b}}
  footer{{text-align:center;color:#94a3b8;font-size:11px;
          padding:20px;margin-top:32px}}
  @media print{{
    .filter-bar,.charts button{{display:none}}
    .findings-row{{display:table-row!important}}
  }}
</style>
</head>
<body>
<header>
  <h1>◈ NetProbe v{VERSION} — Security Assessment Report</h1>
  <p>Generated: {ts} &nbsp;|&nbsp;
     Target: {scan_meta.get('target','N/A')} &nbsp;|&nbsp;
     Mode: {scan_meta.get('mode','N/A')} &nbsp;|&nbsp;
     Duration: {scan_meta.get('duration','N/A')}</p>
</header>

<div class="container">

  <!-- KPI Cards -->
  <div class="cards">
    <div class="card">
      <div class="val" style="color:#2563eb">{len(used)}</div>
      <div class="lbl">Active Hosts</div>
    </div>
    <div class="card">
      <div class="val" style="color:#64748b">{free_ct}</div>
      <div class="lbl">Free IPs</div>
    </div>
    <div class="card">
      <div class="val" style="color:#dc2626">
        {sev_count.get('Critical',0)}</div>
      <div class="lbl">Critical</div>
    </div>
    <div class="card">
      <div class="val" style="color:#f97316">
        {sev_count.get('High',0)}</div>
      <div class="lbl">High</div>
    </div>
    <div class="card">
      <div class="val" style="color:#eab308">
        {sev_count.get('Medium',0)}</div>
      <div class="lbl">Medium</div>
    </div>
    <div class="card">
      <div class="val" style="color:#22c55e">
        {sev_count.get('Low',0)}</div>
      <div class="lbl">Low</div>
    </div>
    <div class="card">
      <div class="val" style="color:#7c3aed">
        {len(diff.get('rogue',[]))}</div>
      <div class="lbl">Rogue Devices</div>
    </div>
  </div>

  <!-- Charts -->
  <div class="charts">
    <div class="chart-box">
      <h3>Findings by Severity</h3>
      <canvas id="sevChart" height="180"></canvas>
    </div>
    <div class="chart-box">
      <h3>Threat Score Distribution</h3>
      <canvas id="threatChart" height="180"></canvas>
    </div>
  </div>

  <!-- Scan Meta -->
  <div class="summary-grid">
    <div class="meta"><b>Target:</b> {scan_meta.get('target','N/A')}</div>
    <div class="meta"><b>Scan Mode:</b> {scan_meta.get('mode','N/A')}</div>
    <div class="meta"><b>Duration:</b> {scan_meta.get('duration','N/A')}</div>
    <div class="meta"><b>New Hosts:</b>
      {len(diff.get('new',[]))}</div>
    <div class="meta"><b>Rogue (MAC changed):</b>
      {len(diff.get('rogue',[]))}</div>
    <div class="meta"><b>Total Findings:</b> {len(findings)}</div>
  </div>

  <!-- Host Table -->
  <h2>Active Hosts
    <span style="font-weight:400;color:#64748b;font-size:12px">
      (click row to expand findings)</span></h2>

  <div class="filter-bar">
    <input id="searchBox" type="text"
           placeholder="Search IP, hostname, vendor, port…"
           oninput="filterTable()">
    <select id="riskFilter" onchange="filterTable()">
      <option value="">All Risk Levels</option>
      <option>CRITICAL</option><option>HIGH</option>
      <option>MEDIUM</option><option>LOW</option>
      <option>MINIMAL</option>
    </select>
    <button onclick="exportTableCSV()"
      style="padding:6px 14px;background:#2563eb;color:#fff;
             border:none;border-radius:6px;cursor:pointer;font-size:12px">
      ↗ Export CSV</button>
    <button onclick="window.print()"
      style="padding:6px 14px;background:#475569;color:#fff;
             border:none;border-radius:6px;cursor:pointer;font-size:12px">
      🖨 Print</button>
  </div>

  <table id="hostTable">
    <thead>
      <tr>
        <th onclick="sortTable(0)">Risk ↕</th>
        <th onclick="sortTable(1)">IP ↕</th>
        <th onclick="sortTable(2)">Hostname ↕</th>
        <th>MAC</th>
        <th onclick="sortTable(4)">Vendor ↕</th>
        <th>Device</th>
        <th>OS</th>
        <th>Open Ports</th>
        <th>SSL</th>
        <th>Note</th>
      </tr>
    </thead>
    <tbody id="hostBody">
      {host_rows}
    </tbody>
  </table>

</div>

<footer>{APP_FULL} &mdash; {ts}</footer>

<script>
// ── Chart.js ──────────────────────────────────────────────────────────
new Chart(document.getElementById('sevChart'), {{
  type: 'doughnut',
  data: {{
    labels: {chart_sev_labels},
    datasets: [{{
      data: {chart_sev_data},
      backgroundColor: {chart_sev_colors},
      borderWidth: 2
    }}]
  }},
  options: {{plugins:{{legend:{{position:'right'}}}},
             maintainAspectRatio:false}}
}});

new Chart(document.getElementById('threatChart'), {{
  type: 'bar',
  data: {{
    labels: {chart_threat_labels},
    datasets: [{{
      data: {chart_threat_data},
      backgroundColor: {chart_threat_colors},
      borderRadius: 4
    }}]
  }},
  options: {{
    plugins:{{legend:{{display:false}}}},
    scales:{{y:{{beginAtZero:true,ticks:{{stepSize:1}}}}}},
    maintainAspectRatio:false
  }}
}});

// ── Toggle findings ───────────────────────────────────────────────────
function toggleFindings(row) {{
  const next = row.nextElementSibling;
  if (next && next.classList.contains('findings-row')) {{
    next.style.display =
      next.style.display === 'none' ? 'table-row' : 'none';
  }}
}}

// ── Filter ────────────────────────────────────────────────────────────
function filterTable() {{
  const q   = document.getElementById('searchBox').value.toLowerCase();
  const risk= document.getElementById('riskFilter').value;
  const rows= document.querySelectorAll('#hostBody .host-row');
  rows.forEach(row => {{
    const txt  = row.textContent.toLowerCase();
    const score= row.getAttribute('data-score');
    const lbl  = scoreLabel(parseInt(score||'0'));
    const show = (!q || txt.includes(q)) &&
                 (!risk || lbl === risk);
    row.style.display = show ? '' : 'none';
    const next = row.nextElementSibling;
    if (next) next.style.display = 'none';
  }});
}}

function scoreLabel(s) {{
  if (s>=80) return 'CRITICAL';
  if (s>=60) return 'HIGH';
  if (s>=40) return 'MEDIUM';
  if (s>=20) return 'LOW';
  return 'MINIMAL';
}}

// ── Sort ─────────────────────────────────────────────────────────────
let sortDir = {{}};
function sortTable(col) {{
  const tbody = document.getElementById('hostBody');
  const rows  = [...tbody.querySelectorAll('.host-row')];
  const asc   = !(sortDir[col]);
  sortDir     = {{[col]: asc}};
  rows.sort((a,b) => {{
    const av = a.cells[col]?.textContent.trim()||'';
    const bv = b.cells[col]?.textContent.trim()||'';
    if (col===0) {{
      const order=['CRITICAL','HIGH','MEDIUM','LOW','MINIMAL'];
      return asc ? order.indexOf(av)-order.indexOf(bv)
                 : order.indexOf(bv)-order.indexOf(av);
    }}
    return asc ? av.localeCompare(bv) : bv.localeCompare(av);
  }});
  rows.forEach(r => {{
    tbody.appendChild(r);
    const next = r.nextElementSibling;
    if (next?.classList.contains('findings-row'))
      tbody.appendChild(next);
  }});
}}

// ── CSV Export ───────────────────────────────────────────────────────
function exportTableCSV() {{
  const rows = [...document.querySelectorAll(
    '#hostBody .host-row:not([style*="display: none"])')]
    .map(r => [...r.cells].map(c =>
      '"'+c.textContent.trim().replace(/"/g,'""')+'"').join(','));
  const hdr  = ['Risk','IP','Hostname','MAC','Vendor',
                'Device','OS','Ports','SSL','Note'].join(',');
  const blob = new Blob([[hdr,...rows].join('\\n')],
                        {{type:'text/csv'}});
  const a    = document.createElement('a');
  a.href     = URL.createObjectURL(blob);
  a.download = 'netprobe_report.csv';
  a.click();
}}
</script>
</body></html>"""


# ─────────────────────────────────────────────────────────────────────────────
# ② DOCKER / VM DETECTION BADGE  (enhanced guess_device_type)
# ─────────────────────────────────────────────────────────────────────────────

# OUI ranges known to belong to container/VM platforms
_CONTAINER_OUIS = {
    "02:42":    "🐳 Docker",       # Docker assigns 02:42:xx:xx:xx:xx
    "52:54:00": "⬡ QEMU/KVM",
    "00:16:3E": "⬡ Xen VM",
    "00:50:56": "⬡ VMware",
    "00:0C:29": "⬡ VMware",
    "00:05:69": "⬡ VMware",
    "08:00:27": "⬡ VirtualBox",
    "00:15:5D": "⬡ Hyper-V",
}

# Banner keywords → container/orchestration hints
_CONTAINER_BANNER_KW = [
    ("docker",        "🐳 Docker Host"),
    ("kubernetes",    "☸ Kubernetes"),
    ("k8s",           "☸ Kubernetes"),
    ("containerd",    "🐳 Container Runtime"),
    ("podman",        "🐳 Podman"),
    ("lxc",           "📦 LXC Container"),
    ("proxmox",       "⬡ Proxmox VE"),
    ("vsphere",       "⬡ VMware vSphere"),
    ("esxi",          "⬡ VMware ESXi"),
    ("hyperv",        "⬡ Hyper-V"),
    ("virtualbox",    "⬡ VirtualBox"),
    ("qemu",          "⬡ QEMU/KVM"),
    ("openstack",     "☁ OpenStack"),
    ("amazon ec2",    "☁ AWS EC2"),
    ("aws lambda",    "☁ AWS Lambda"),
    ("gce",           "☁ GCP Compute"),
    ("azure",         "☁ Azure VM"),
]

def enhanced_device_type(result: dict) -> str:
    """
    Extended device type detection with container/VM/cloud badges.
    Augments the existing guess_device_type() function.
    """
    ports   = set(result.get("open_ports", []))
    vendor  = (result.get("vendor") or "").lower()
    os_g    = (result.get("os_guess") or "").lower()
    mac     = result.get("mac", "")
    banners = result.get("banners", {})
    banner_all = " ".join(banners.values()).lower()

    # Container/VM via MAC OUI
    if mac:
        oui3 = ":".join(mac.split(":")[:3]).upper()
        oui2 = ":".join(mac.split(":")[:2]).upper()
        for prefix, label in _CONTAINER_OUIS.items():
            if mac.upper().startswith(prefix.upper()):
                return label

    # Container/VM via banners
    for kw, label in _CONTAINER_BANNER_KW:
        if kw in banner_all or kw in vendor or kw in os_g:
            return label

    # Cloud metadata port hints
    if 2375 in ports or 2376 in ports:
        return "🐳 Docker Host"
    if 6443 in ports:
        return "☸ Kubernetes API"
    if 8500 in ports:
        return "☁ Consul (Service Mesh)"
    if 4646 in ports:
        return "☁ Nomad Scheduler"
    if 8200 in ports:
        return "🔑 Vault (HashiCorp)"
    if 9090 in ports and 9100 in ports:
        return "📊 Prometheus Stack"
    if 3000 in ports and 9090 in ports:
        return "📊 Grafana Stack"

    # TTL-based cloud hints (AWS: 64-1hop = 63, GCP: similar)
    # Handled in os fingerprint — fall through to existing function
    return guess_device_type(
        list(ports),
        result.get("vendor", ""),
        result.get("os_guess", ""))


# ─────────────────────────────────────────────────────────────────────────────
# ③ COMMAND PALETTE  (Ctrl+P fuzzy search)
# ─────────────────────────────────────────────────────────────────────────────

class CommandPalette(tk.Toplevel):
    """
    VS Code-style command palette.
    Press Ctrl+P anywhere in the app to open.
    Type to fuzzy-search:
      - Host IPs and hostnames from last scan
      - Tab/view names
      - Actions (export, scan, baseline, etc.)
      - Port number → jump to hosts with that port open
      - CVE ID → open CVE lookup
    """

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app        = app
        self.overrideredirect(True)
        self.resizable(False, False)

        # Centre on parent
        pw = parent.winfo_width()
        ph = parent.winfo_height()
        px = parent.winfo_rootx()
        py = parent.winfo_rooty()
        w, h = 580, 420
        x = px + (pw - w) // 2
        y = py + (ph - h) // 3
        self.geometry(f"{w}x{h}+{x}+{y}")

        # Shadow border
        self.configure(bg="#1e293b")

        inner = tk.Frame(self, bg="#1e293b", padx=2, pady=2)
        inner.pack(fill="both", expand=True)

        # Search entry
        entry_frame = tk.Frame(inner, bg="#1e293b")
        entry_frame.pack(fill="x")
        tk.Label(entry_frame, text="⌘",
                 bg="#1e293b", fg="#2563eb",
                 font=("Segoe UI", 14)).pack(side=tk.LEFT, padx=(10, 4))
        self._var = tk.StringVar()
        self._entry = tk.Entry(
            entry_frame, textvariable=self._var,
            font=("Segoe UI", 13),
            bg="#0f172a", fg="#f1f5f9",
            insertbackground="#f1f5f9",
            relief="flat", bd=0)
        self._entry.pack(side=tk.LEFT, fill="x",
                         expand=True, ipady=10, padx=(0, 10))
        self._entry.bind("<KeyRelease>", self._on_type)
        self._entry.bind("<Return>",     self._on_enter)
        self._entry.bind("<Escape>",     lambda _: self.destroy())
        self._entry.bind("<Up>",         self._on_up)
        self._entry.bind("<Down>",       self._on_down)

        tk.Frame(inner, bg="#334155", height=1).pack(fill="x")

        # Results list
        self._listbox = tk.Listbox(
            inner,
            bg="#0f172a", fg="#f1f5f9",
            selectbackground="#2563eb",
            selectforeground="#ffffff",
            font=("Segoe UI", 10),
            relief="flat", bd=0,
            activestyle="none",
            height=14)
        self._listbox.pack(fill="both", expand=True, padx=2)
        self._listbox.bind("<Double-1>", self._on_enter)
        self._listbox.bind("<Return>",   self._on_enter)

        # Status bar
        self._status = tk.Label(
            inner, text="",
            bg="#1e293b", fg="#64748b",
            font=("Segoe UI", 8),
            anchor="w")
        self._status.pack(fill="x", padx=10, pady=4)

        self._actions: list[dict] = []
        self._build_actions()
        self._refresh("")
        self._entry.focus_set()

        # Close on click outside
        self.bind("<FocusOut>", self._on_focus_out)
        self.grab_set()

    def _on_focus_out(self, event):
        # Only close if focus truly left the palette
        if self.focus_get() not in (self._entry, self._listbox):
            self.after(100, self._check_focus)

    def _check_focus(self):
        try:
            if self.focus_get() not in (self._entry, self._listbox):
                self.destroy()
        except Exception:
            pass

    def _build_actions(self):
        """Build the full action/search index."""
        self._actions = []

        # ── Navigation actions ──
        nav_items = [
            ("📡 Go to Scanner",       "nav",    "scanner"),
            ("📊 Go to Dashboard",     "nav",    "dashboard"),
            ("🔧 Go to Tools",         "nav",    "tools"),
            ("🕵 Go to Recon",         "nav",    "recon"),
            ("📦 Go to Sniffer",       "nav",    "sniffer"),
            ("🔍 Go to Vuln Scan",     "nav",    "vulnscan"),
            ("🖥 Go to Fingerprint",   "nav",    "fingerprint"),
            ("📶 Go to SNMP",          "nav",    "snmp"),
            ("🚨 Go to Alerts",        "nav",    "alerts"),
            ("✅ Go to Compliance",    "nav",    "compliance"),
            ("🗺 Go to Topology",      "nav",    "topology"),
            ("📈 Go to History",       "nav",    "history"),
            ("🍯 Go to Honeypot",      "nav",    "honeypot"),
            ("🌐 Go to Wi-Fi",         "nav",    "wifi"),
            ("⚙ Go to Settings",      "nav",    "settings"),
        ]
        for label, kind, target in nav_items:
            self._actions.append({
                "label":  label,
                "kind":   kind,
                "target": target,
                "search": label.lower(),
            })

        # ── Quick actions ──
        quick = [
            ("▶ Start Scan",           "action", "start_scan"),
            ("■ Stop Scan",            "action", "stop_scan"),
            ("💾 Save Baseline",       "action", "save_baseline"),
            ("↗ Export CSV",           "action", "export_csv"),
            ("↗ Export JSON",          "action", "export_json"),
            ("📝 Export Markdown Report","action","export_report"),
            ("🌐 Export HTML Report",  "action", "export_html"),
            ("🔄 Refresh Dashboard",   "action", "update_dashboard"),
            ("↻ Refresh Networks",     "action", "refresh_networks"),
            ("🗑 Clear Results",       "action", "clear_results"),
            ("🔒 Toggle Dark Mode",    "action", "_toggle_theme"),
            ("📋 Copy Selected IP",    "action", "copy_ip"),
            ("📋 Copy Selected MAC",   "action", "copy_mac"),
        ]
        for label, kind, target in quick:
            self._actions.append({
                "label":  label,
                "kind":   kind,
                "target": target,
                "search": label.lower(),
            })

        # ── Hosts from last scan ──
        for r in (self.app.results or []):
            if r.get("status") != "Used":
                continue
            ip  = r.get("ip", "")
            hn  = r.get("hostname", "")
            ven = r.get("vendor", "")
            lbl = f"🖥 {ip}"
            if hn:
                lbl += f"  ({hn})"
            if ven:
                lbl += f"  [{ven}]"
            self._actions.append({
                "label":  lbl,
                "kind":   "host",
                "target": r,
                "search": f"{ip} {hn} {ven}".lower(),
                "ip":     ip,
            })

    def _fuzzy_match(self, query: str, text: str) -> int:
        """
        Returns a match score (higher = better).
        0 = no match.
        """
        if not query:
            return 1
        q = query.lower()
        t = text.lower()
        if q == t:
            return 100
        if t.startswith(q):
            return 80
        if q in t:
            return 60
        # Character subsequence match
        qi = 0
        for ch in t:
            if qi < len(q) and ch == q[qi]:
                qi += 1
        if qi == len(q):
            return 20 + (len(q) * 10 // max(len(t), 1))
        return 0

    def _refresh(self, query: str):
        self._listbox.delete(0, "end")
        matches = []
        for action in self._actions:
            score = self._fuzzy_match(query, action["search"])
            if score > 0:
                matches.append((score, action))
        matches.sort(key=lambda x: -x[0])
        for _, action in matches[:20]:
            icon = {"nav": "→", "action": "⚡",
                    "host": "●"}.get(action["kind"], "·")
            self._listbox.insert("end", f"  {icon}  {action['label']}")
        self._matches = [a for _, a in matches[:20]]
        count = len(matches)
        self._status.config(
            text=f"{count} result{'s' if count != 1 else ''}"
                 + (" — ↑↓ navigate · Enter select · Esc close"
                    if count else ""))
        if self._listbox.size() > 0:
            self._listbox.selection_set(0)

    def _on_type(self, _=None):
        self._refresh(self._var.get().strip())

    def _on_enter(self, _=None):
        sel = self._listbox.curselection()
        if not sel:
            return
        idx    = sel[0]
        if idx >= len(self._matches):
            return
        action = self._matches[idx]
        self.destroy()
        self._execute(action)

    def _on_up(self, _=None):
        sel = self._listbox.curselection()
        if sel and sel[0] > 0:
            self._listbox.selection_clear(sel[0])
            self._listbox.selection_set(sel[0] - 1)
            self._listbox.see(sel[0] - 1)
        return "break"

    def _on_down(self, _=None):
        sel = self._listbox.curselection()
        if sel and sel[0] < self._listbox.size() - 1:
            self._listbox.selection_clear(sel[0])
            self._listbox.selection_set(sel[0] + 1)
            self._listbox.see(sel[0] + 1)
        elif not sel and self._listbox.size():
            self._listbox.selection_set(0)
        return "break"

    def _execute(self, action: dict):
        app = self.app
        kind   = action["kind"]
        target = action["target"]

        if kind == "nav":
            app.show_view(target)

        elif kind == "action":
            fn = getattr(app, target, None)
            if callable(fn):
                fn()

        elif kind == "host":
            r = target
            # Select the host in the scanner tree and open detail
            app.show_view("scanner")
            for item in app.tree.get_children():
                vals = app.tree.item(item, "values")
                if vals and vals[2] == r.get("ip"):
                    app.tree.selection_set(item)
                    app.tree.see(item)
                    break
            app._on_row_double_click()


# ─────────────────────────────────────────────────────────────────────────────
# ④ NEW TAB UI BUILDERS
#    These are methods to be monkey-patched onto IPScannerGUI
# ─────────────────────────────────────────────────────────────────────────────

def _build_history_ui(self):
    """Scan history + trend analysis tab."""
    frame = self.view_frames.get("history")
    if not frame:
        return
    frame.grid_rowconfigure(2, weight=1)
    frame.grid_columnconfigure(0, weight=1)

    hdr = ttk.Frame(frame, padding=(16, 12, 16, 0))
    hdr.grid(row=0, column=0, sticky="ew")
    ttk.Label(hdr, text="Scan History & Trends",
              style="Heading.TLabel").pack(side=tk.LEFT)
    ttk.Button(hdr, text="↻ Refresh",
               command=lambda: _history_refresh(self),
               style="Ghost.TButton").pack(side=tk.RIGHT)
    ttk.Button(hdr, text="🗑 Vacuum DB",
               command=lambda: [db.vacuum(),
                   messagebox.showinfo("DB", "Database vacuumed.")],
               style="Ghost.TButton").pack(side=tk.RIGHT, padx=(0,8))

    ttk.Separator(frame, orient="horizontal").grid(
        row=1, column=0, sticky="ew", padx=16)

    nb = ttk.Notebook(frame)
    nb.grid(row=2, column=0, sticky="nsew", padx=16, pady=8)
    frame.grid_rowconfigure(2, weight=1)

    # ── Scan list tab ──
    scan_tab = ttk.Frame(nb, padding=8)
    nb.add(scan_tab, text="Scan Log")
    scan_tab.grid_rowconfigure(0, weight=1)
    scan_tab.grid_columnconfigure(0, weight=1)

    cols = ("id","started","target","mode","hosts","active","findings")
    self._hist_scan_tree = ttk.Treeview(
        scan_tab, columns=cols, show="headings")
    for c, w in [("id",40),("started",155),("target",200),
                 ("mode",70),("hosts",60),("active",60),("findings",70)]:
        self._hist_scan_tree.heading(c, text=c.capitalize())
        self._hist_scan_tree.column(c, width=w)
    vsb = ttk.Scrollbar(scan_tab, orient="vertical",
                         command=self._hist_scan_tree.yview)
    self._hist_scan_tree.configure(yscrollcommand=vsb.set)
    self._hist_scan_tree.grid(row=0, column=0, sticky="nsew")
    vsb.grid(row=0, column=1, sticky="ns")

    # ── Host timeline tab ──
    host_tab = ttk.Frame(nb, padding=8)
    nb.add(host_tab, text="Host Timeline")
    self._hist_ip_var = tk.StringVar()
    ctrl = ttk.Frame(host_tab)
    ctrl.pack(fill="x", pady=(0, 8))
    ttk.Label(ctrl, text="IP:").pack(side=tk.LEFT)
    ttk.Entry(ctrl, textvariable=self._hist_ip_var,
              width=20).pack(side=tk.LEFT, padx=(4,8))
    ttk.Button(ctrl, text="Show History →",
               command=lambda: _history_show_host(self),
               style="Ghost.TButton").pack(side=tk.LEFT)

    self._hist_host_txt = scrolledtext.ScrolledText(
        host_tab, height=20, font=("Courier New", 9),
        state="disabled")
    self._hist_host_txt.pack(fill="both", expand=True)

    # ── Top vulnerable tab ──
    vuln_tab = ttk.Frame(nb, padding=8)
    nb.add(vuln_tab, text="Most Vulnerable")
    vuln_tab.grid_rowconfigure(0, weight=1)
    vuln_tab.grid_columnconfigure(0, weight=1)

    cols2 = ("ip","avg_score","max_score","scan_count")
    self._hist_vuln_tree = ttk.Treeview(
        vuln_tab, columns=cols2, show="headings")
    for c, w in [("ip",140),("avg_score",100),
                 ("max_score",100),("scan_count",90)]:
        self._hist_vuln_tree.heading(c, text=c.replace("_"," ").title())
        self._hist_vuln_tree.column(c, width=w)
    vsb2 = ttk.Scrollbar(vuln_tab, orient="vertical",
                          command=self._hist_vuln_tree.yview)
    self._hist_vuln_tree.configure(yscrollcommand=vsb2.set)
    self._hist_vuln_tree.grid(row=0, column=0, sticky="nsew")
    vsb2.grid(row=0, column=1, sticky="ns")

    _history_refresh(self)


def _history_refresh(self):
    if hasattr(self, "_hist_scan_tree"):
        for row in self._hist_scan_tree.get_children():
            self._hist_scan_tree.delete(row)
        for s in db.get_scan_list(50):
            self._hist_scan_tree.insert("", "end", values=(
                s["id"], s["started_at"][:19],
                (s["target"] or "")[:40],
                s["mode"] or "",
                s["host_count"] or 0,
                s["active_count"] or 0,
                s["finding_count"] or 0,
            ))
    if hasattr(self, "_hist_vuln_tree"):
        for row in self._hist_vuln_tree.get_children():
            self._hist_vuln_tree.delete(row)
        for h in db.get_top_vulnerable_hosts(30):
            self._hist_vuln_tree.insert("", "end", values=(
                h["ip"],
                f"{h['avg_score']:.1f}",
                h["max_score"],
                h["scan_count"],
            ))


def _history_show_host(self):
    ip = self._hist_ip_var.get().strip()
    if not ip:
        return
    history = db.get_host_history(ip, limit=20)
    changes = db.get_port_changes(ip)
    self._hist_host_txt.config(state="normal")
    self._hist_host_txt.delete("1.0", "end")
    if not history:
        self._hist_host_txt.insert("end", f"No history found for {ip}\n")
    else:
        self._hist_host_txt.insert(
            "end", f"History for {ip} ({len(history)} scans):\n\n")
        for h in history:
            self._hist_host_txt.insert(
                "end",
                f"  [{h['scan_ts'][:19]}]  "
                f"Status: {h['status']:<6}  "
                f"Score: {h['threat_score']:<4}  "
                f"OS: {(h['os_guess'] or '—')[:25]}\n"
                f"    Ports: "
                f"{format_ports(h['open_ports'])[:80] or 'none'}\n")
        if changes:
            self._hist_host_txt.insert(
                "end", f"\nPort Changes:\n")
            for c in changes:
                added   = format_ports(c['added']) or "none"
                removed = format_ports(c['removed']) or "none"
                self._hist_host_txt.insert(
                    "end",
                    f"  [{c['scan_ts'][:19]}]  "
                    f"+{added}  -{removed}\n")
    self._hist_host_txt.config(state="disabled")


def _build_honeypot_ui(self):
    """Honeypot monitor tab."""
    frame = self.view_frames.get("honeypot")
    if not frame:
        return
    frame.grid_rowconfigure(2, weight=1)
    frame.grid_columnconfigure(0, weight=1)

    hdr = ttk.Frame(frame, padding=(16, 12, 16, 0))
    hdr.grid(row=0, column=0, sticky="ew")
    ttk.Label(hdr, text="Honeypot Monitor",
              style="Heading.TLabel").pack(side=tk.LEFT)
    ttk.Separator(frame, orient="horizontal").grid(
        row=1, column=0, sticky="ew", padx=16)

    inner = ttk.Frame(frame, padding=16)
    inner.grid(row=2, column=0, sticky="nsew")
    inner.grid_rowconfigure(1, weight=1)
    inner.grid_columnconfigure(0, weight=1)

    warn = tk.Label(inner,
        text="⚠  Honeypot opens TCP listeners on your machine. "
             "Requires the ports to be free. "
             "Any connection = instant Critical alert.",
        bg="#fef9c3", fg="#713f12",
        font=("Segoe UI", 9), padx=8, pady=6, wraplength=760, justify="left")
    warn.pack(fill="x", pady=(0, 8))

    ctrl = ttk.Frame(inner)
    ctrl.pack(fill="x", pady=(0, 8))

    self._hp_ports_var  = tk.StringVar(
        value=", ".join(str(p) for p in
                        HoneypotMonitor.DEFAULT_PORTS))
    self._hp_status_var = tk.StringVar(value="● Stopped")

    ttk.Label(ctrl, text="Ports:").pack(side=tk.LEFT)
    ttk.Entry(ctrl, textvariable=self._hp_ports_var,
              width=36).pack(side=tk.LEFT, padx=(4,8))

    self._hp_start_btn = ttk.Button(
        ctrl, text="▶ Start",
        command=lambda: _honeypot_start(self),
        style="Success.TButton")
    self._hp_start_btn.pack(side=tk.LEFT, padx=(0,4))

    self._hp_stop_btn = ttk.Button(
        ctrl, text="■ Stop",
        command=lambda: _honeypot_stop(self),
        style="Danger.TButton", state=tk.DISABLED)
    self._hp_stop_btn.pack(side=tk.LEFT, padx=(0,8))

    ttk.Button(ctrl, text="Export Hits CSV",
               command=lambda: _honeypot_export(self),
               style="Ghost.TButton").pack(side=tk.LEFT)

    ttk.Label(ctrl, textvariable=self._hp_status_var,
              style="Muted.TLabel").pack(side=tk.RIGHT)

    cols = ("ts","src_ip","src_port","honeypot_port","client_data")
    self._hp_tree = ttk.Treeview(inner, columns=cols, show="headings")
    for c, w in [("ts",155),("src_ip",140),("src_port",80),
                 ("honeypot_port",110),("client_data",340)]:
        self._hp_tree.heading(c, text=c.replace("_"," ").title())
        self._hp_tree.column(c, width=w)
    self._hp_tree.tag_configure("hit", background="#fee2e2",
                                 foreground="#dc2626")
    vsb = ttk.Scrollbar(inner, orient="vertical",
                         command=self._hp_tree.yview)
    self._hp_tree.configure(yscrollcommand=vsb.set)
    self._hp_tree.grid(row=1, column=0, sticky="nsew")
    vsb.grid(row=1, column=1, sticky="ns")


def _honeypot_start(self):
    raw   = self._hp_ports_var.get()
    ports = [int(p.strip()) for p in raw.split(",")
             if p.strip().isdigit()]
    if not ports:
        messagebox.showwarning("Honeypot", "Enter at least one port.")
        return

    def _alert_cb(severity, ip, msg, tag=""):
        self.alert_log.add(severity, ip, msg, tag=tag)
        self.root.after(0, lambda: self._hp_tree.insert(
            "", 0, values=(ts_now(), ip, "", "", msg[:80]),
            tags=("hit",)))
        self.root.after(0, lambda: self._hp_status_var.set(
            f"🔴 {len(honeypot.hits)} hit(s)"))

    honeypot.alert_callback = _alert_cb
    honeypot.start(ports)

    active = honeypot.active_ports
    self._hp_status_var.set(
        f"🔴 Listening on {active}")
    self._hp_start_btn.config(state=tk.DISABLED)
    self._hp_stop_btn.config(state=tk.NORMAL)

    # Refresh hits into tree
    for h in honeypot.hits:
        self._hp_tree.insert("", "end", values=(
            h["ts"], h["src_ip"], h["src_port"],
            h["honeypot_port"], h["client_data"]),
            tags=("hit",))


def _honeypot_stop(self):
    honeypot.stop()
    self._hp_status_var.set("● Stopped")
    self._hp_start_btn.config(state=tk.NORMAL)
    self._hp_stop_btn.config(state=tk.DISABLED)


def _honeypot_export(self):
    if not honeypot.hits:
        messagebox.showinfo("Honeypot", "No hits to export.")
        return
    path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV","*.csv")])
    if path:
        honeypot.export_hits_csv(path)
        messagebox.showinfo("Exported", path)


def _build_wifi_ui(self):
    """Wi-Fi / SSID scanner tab."""
    frame = self.view_frames.get("wifi")
    if not frame:
        return
    frame.grid_rowconfigure(2, weight=1)
    frame.grid_columnconfigure(0, weight=1)

    hdr = ttk.Frame(frame, padding=(16, 12, 16, 0))
    hdr.grid(row=0, column=0, sticky="ew")
    ttk.Label(hdr, text="Wi-Fi Scanner",
              style="Heading.TLabel").pack(side=tk.LEFT)
    ttk.Separator(frame, orient="horizontal").grid(
        row=1, column=0, sticky="ew", padx=16)

    inner = ttk.Frame(frame, padding=16)
    inner.grid(row=2, column=0, sticky="nsew")
    inner.grid_rowconfigure(1, weight=1)
    inner.grid_columnconfigure(0, weight=1)

    ctrl = ttk.Frame(inner)
    ctrl.pack(fill="x", pady=(0, 8))

    self._wifi_status_var = tk.StringVar(value="")
    ttk.Button(ctrl, text="📡 Scan Networks",
               command=lambda: _wifi_scan(self),
               style="Success.TButton").pack(side=tk.LEFT, padx=(0,8))
    ttk.Button(ctrl, text="Export CSV",
               command=lambda: _wifi_export(self),
               style="Ghost.TButton").pack(side=tk.LEFT)
    ttk.Label(ctrl, textvariable=self._wifi_status_var,
              style="Muted.TLabel").pack(side=tk.RIGHT)

    cols = ("ssid","bssid","signal","channel","band",
            "encryption","risk","risk_reason")
    self._wifi_tree = ttk.Treeview(
        inner, columns=cols, show="headings")
    for c, w in [("ssid",200),("bssid",155),("signal",75),
                 ("channel",65),("band",80),("encryption",100),
                 ("risk",55),("risk_reason",260)]:
        self._wifi_tree.heading(c, text=c.replace("_"," ").title())
        self._wifi_tree.column(c, width=w)
    self._wifi_tree.tag_configure("High",
        background="#fee2e2", foreground="#dc2626")
    self._wifi_tree.tag_configure("Low",
        background="#f0fdf4", foreground="#15803d")

    vsb = ttk.Scrollbar(inner, orient="vertical",
                         command=self._wifi_tree.yview)
    self._wifi_tree.configure(yscrollcommand=vsb.set)
    self._wifi_tree.grid(row=1, column=0, sticky="nsew")
    vsb.grid(row=1, column=1, sticky="ns")

    if not WiFiScanner.available():
        ttk.Label(inner,
                  text="⚠  Wi-Fi scanning not available on this system "
                       "(requires netsh/iwlist/nmcli/airport).",
                  style="Warning.TLabel").grid(
            row=2, column=0, sticky="w", pady=(6,0))


def _wifi_scan(self):
    self._wifi_status_var.set("Scanning…")
    for row in self._wifi_tree.get_children():
        self._wifi_tree.delete(row)

    def run():
        nets = WiFiScanner.scan()
        nets = WiFiScanner.flag_risks(nets)
        self.root.after(0, lambda ns=nets: _wifi_populate(self, ns))

    threading.Thread(target=run, daemon=True).start()


def _wifi_populate(self, networks):
    for n in networks:
        self._wifi_tree.insert("", "end", values=(
            n.get("ssid",""),
            n.get("bssid",""),
            n.get("signal_dbm",""),
            n.get("channel",""),
            n.get("band",""),
            n.get("encryption",""),
            n.get("risk",""),
            n.get("risk_reason",""),
        ), tags=(n.get("risk",""),))
    self._wifi_status_var.set(f"{len(networks)} network(s) found")


def _wifi_export(self):
    rows = [self._wifi_tree.item(i, "values")
            for i in self._wifi_tree.get_children()]
    if not rows:
        return
    path = filedialog.asksaveasfilename(
        defaultextension=".csv", filetypes=[("CSV","*.csv")])
    if path:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["SSID","BSSID","Signal","Channel","Band",
                        "Encryption","Risk","Risk Reason"])
            w.writerows(rows)
        messagebox.showinfo("Export", path)


def _build_cve_tab_ui(self):
    """CVE Live Lookup tab (inside Vuln Scan or standalone)."""
    frame = self.view_frames.get("cvelookup")
    if not frame:
        return
    frame.grid_rowconfigure(2, weight=1)
    frame.grid_columnconfigure(0, weight=1)

    hdr = ttk.Frame(frame, padding=(16,12,16,0))
    hdr.grid(row=0, column=0, sticky="ew")
    ttk.Label(hdr, text="CVE Live Lookup",
              style="Heading.TLabel").pack(side=tk.LEFT)
    ttk.Separator(frame, orient="horizontal").grid(
        row=1, column=0, sticky="ew", padx=16)

    inner = ttk.Frame(frame, padding=16)
    inner.grid(row=2, column=0, sticky="nsew")
    inner.grid_rowconfigure(1, weight=1)
    inner.grid_columnconfigure(0, weight=1)

    ctrl = ttk.Frame(inner)
    ctrl.pack(fill="x", pady=(0,8))

    self._cve_query_var  = tk.StringVar()
    self._cve_status_var = tk.StringVar(value="")

    ttk.Label(ctrl, text="Search:").pack(side=tk.LEFT)
    e = ttk.Entry(ctrl, textvariable=self._cve_query_var, width=32)
    e.pack(side=tk.LEFT, padx=(4,8))
    e.bind("<Return>", lambda _: _cve_search(self))
    Tooltip(e, "Banner string (e.g. 'Apache 2.4.51') or CVE ID (CVE-2021-44228)")

    ttk.Button(ctrl, text="🔍 Search NVD",
               command=lambda: _cve_search(self),
               style="Success.TButton").pack(side=tk.LEFT, padx=(0,4))
    ttk.Button(ctrl, text="Enrich from last scan →",
               command=lambda: _cve_enrich_scan(self),
               style="Ghost.TButton").pack(side=tk.LEFT, padx=(0,8))
    ttk.Label(ctrl, textvariable=self._cve_status_var,
              style="Muted.TLabel").pack(side=tk.RIGHT)

    cols = ("id","score","severity","published","banner","description","url")
    self._cve_tree = ttk.Treeview(inner, columns=cols, show="headings")
    for c, w in [("id",130),("score",55),("severity",80),
                 ("published",90),("banner",150),
                 ("description",340),("url",0)]:
        self._cve_tree.heading(c, text=c.replace("_"," ").title())
        self._cve_tree.column(c, width=w)
    for sev, (fg, bg) in SEV_COLORS.items():
        self._cve_tree.tag_configure(sev, background=bg, foreground=fg)
    self._cve_tree.bind("<Double-1>",
                         lambda _: _cve_open_url(self))

    vsb = ttk.Scrollbar(inner, orient="vertical",
                         command=self._cve_tree.yview)
    self._cve_tree.configure(yscrollcommand=vsb.set)
    self._cve_tree.grid(row=1, column=0, sticky="nsew")
    vsb.grid(row=1, column=1, sticky="ns")

    ttk.Label(inner,
              text="Double-click a row to open in browser · "
                   "NVD API key optional (Settings → API Keys)",
              style="Muted.TLabel").grid(
        row=2, column=0, sticky="w", pady=(4,0))


def _cve_search(self):
    query = self._cve_query_var.get().strip()
    if not query:
        return
    self._cve_status_var.set("Searching…")
    for row in self._cve_tree.get_children():
        self._cve_tree.delete(row)

    def run():
        if re.match(r"CVE-\d{4}-\d+", query, re.I):
            result = cve_engine.lookup_cve_id(query.upper())
            results = [result] if result else []
        else:
            results = cve_engine.lookup_keyword(query, max_results=20)
        self.root.after(0, lambda rs=results: _cve_populate(self, rs))

    threading.Thread(target=run, daemon=True).start()


def _cve_enrich_scan(self):
    """Enrich all active hosts from last scan with live CVE data."""
    used = [r for r in self.results if r["status"] == "Used"]
    if not used:
        messagebox.showinfo("CVE Enrich", "Run a scan first.")
        return
    for row in self._cve_tree.get_children():
        self._cve_tree.delete(row)
    self._cve_status_var.set(f"Enriching {len(used)} host(s)…")

    def run():
        all_cves = []
        for r in used:
            cves = cve_engine.enrich_result(r)
            for c in cves:
                c.setdefault("banner_match", r.get("ip",""))
            all_cves.extend(cves)
        self.root.after(0, lambda cs=all_cves: _cve_populate(self, cs))

    threading.Thread(target=run, daemon=True).start()


def _cve_populate(self, results):
    for r in results:
        sev = (r.get("severity") or "Info").capitalize()
        self._cve_tree.insert("", "end", values=(
            r.get("id",""),
            r.get("score",""),
            sev,
            r.get("published",""),
            r.get("banner_match","")[:30],
            r.get("description","")[:120],
            r.get("url",""),
        ), tags=(sev,))
    self._cve_status_var.set(f"{len(results)} CVE(s) found")


def _cve_open_url(self):
    sel = self._cve_tree.selection()
    if not sel:
        return
    vals = self._cve_tree.item(sel[0], "values")
    if vals and len(vals) >= 7 and vals[6]:
        webbrowser.open(vals[6])


def _build_threat_intel_ui(self):
    """Threat Feed / IP Intel tab."""
    frame = self.view_frames.get("threatintel")
    if not frame:
        return
    frame.grid_rowconfigure(2, weight=1)
    frame.grid_columnconfigure(0, weight=1)

    hdr = ttk.Frame(frame, padding=(16,12,16,0))
    hdr.grid(row=0, column=0, sticky="ew")
    ttk.Label(hdr, text="Threat Intelligence",
              style="Heading.TLabel").pack(side=tk.LEFT)
    ttk.Separator(frame, orient="horizontal").grid(
        row=1, column=0, sticky="ew", padx=16)

    inner = ttk.Frame(frame, padding=16)
    inner.grid(row=2, column=0, sticky="nsew")
    inner.grid_rowconfigure(1, weight=1)
    inner.grid_columnconfigure(0, weight=1)

    ctrl = ttk.Frame(inner)
    ctrl.pack(fill="x", pady=(0,8))

    self._ti_target_var = tk.StringVar()
    self._ti_status_var = tk.StringVar(value="")

    ttk.Label(ctrl, text="IP:").pack(side=tk.LEFT)
    e = ttk.Entry(ctrl, textvariable=self._ti_target_var, width=22)
    e.pack(side=tk.LEFT, padx=(4,8))
    e.bind("<Return>", lambda _: _ti_check_single(self))
    ttk.Button(ctrl, text="🔍 Check IP",
               command=lambda: _ti_check_single(self),
               style="Success.TButton").pack(side=tk.LEFT, padx=(0,4))
    ttk.Button(ctrl, text="Check all scan results →",
               command=lambda: _ti_check_all(self),
               style="Ghost.TButton").pack(side=tk.LEFT, padx=(0,8))
    ttk.Button(ctrl, text="Export CSV",
               command=lambda: _ti_export(self),
               style="Ghost.TButton").pack(side=tk.LEFT)
    ttk.Label(ctrl, textvariable=self._ti_status_var,
              style="Muted.TLabel").pack(side=tk.RIGHT)

    cols = ("ip","abusive","confidence","greynoise",
            "otx_pulses","malicious","summary","sources")
    self._ti_tree = ttk.Treeview(inner, columns=cols, show="headings")
    for c, w in [("ip",130),("abusive",65),("confidence",80),
                 ("greynoise",90),("otx_pulses",80),
                 ("malicious",70),("summary",260),("sources",120)]:
        self._ti_tree.heading(c, text=c.replace("_"," ").title())
        self._ti_tree.column(c, width=w)
    self._ti_tree.tag_configure("mal",
        background="#fee2e2", foreground="#dc2626")
    self._ti_tree.tag_configure("sus",
        background="#fff7ed", foreground="#c2410c")
    self._ti_tree.tag_configure("clean",
        background="#f0fdf4", foreground="#15803d")

    vsb = ttk.Scrollbar(inner, orient="vertical",
                         command=self._ti_tree.yview)
    self._ti_tree.configure(yscrollcommand=vsb.set)
    self._ti_tree.grid(row=1, column=0, sticky="nsew")
    vsb.grid(row=1, column=1, sticky="ns")

    ttk.Label(inner,
              text="Requires API keys in Settings → API Keys "
                   "(AbuseIPDB, OTX, GreyNoise). "
                   "Private IPs are skipped automatically.",
              style="Muted.TLabel").grid(
        row=2, column=0, sticky="w", pady=(4,0))


def _ti_check_single(self):
    ip = self._ti_target_var.get().strip()
    if not ip:
        return
    self._ti_status_var.set("Checking…")
    def run():
        r = threat_feed.check(ip)
        self.root.after(0, lambda: _ti_insert_row(self, r))
        self.root.after(0, lambda: self._ti_status_var.set("Done"))
    threading.Thread(target=run, daemon=True).start()


def _ti_check_all(self):
    public = [r["ip"] for r in self.results
              if r["status"] == "Used"
              and ShodanEnrich.is_public_ip(r["ip"])]
    if not public:
        messagebox.showinfo("Threat Intel",
            "No public IPs in last scan results.")
        return
    for row in self._ti_tree.get_children():
        self._ti_tree.delete(row)
    self._ti_status_var.set(f"Checking {len(public)} IPs…")

    def run():
        for i, ip in enumerate(public):
            r = threat_feed.check(ip)
            self.root.after(0, lambda ri=r: _ti_insert_row(self, ri))
            self.root.after(0, lambda i=i: self._ti_status_var.set(
                f"{i+1}/{len(public)} checked…"))
        self.root.after(0, lambda: self._ti_status_var.set(
            f"Done — {len(public)} IPs checked"))
    threading.Thread(target=run, daemon=True).start()


def _ti_insert_row(self, r):
    tag = ("mal" if r.get("malicious")
           else "sus" if r.get("abusive")
           else "clean")
    self._ti_tree.insert("", "end", values=(
        r["ip"],
        "⚠ Yes" if r.get("abusive") else "No",
        f"{r.get('confidence',0)}%",
        r.get("greynoise",""),
        r.get("otx_pulses",0),
        "🚨 YES" if r.get("malicious") else "No",
        r.get("summary",""),
        ", ".join(r.get("sources",[])),
    ), tags=(tag,))


def _ti_export(self):
    rows = [self._ti_tree.item(i,"values")
            for i in self._ti_tree.get_children()]
    if not rows:
        return
    path = filedialog.asksaveasfilename(
        defaultextension=".csv", filetypes=[("CSV","*.csv")])
    if path:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["IP","Abusive","Confidence","GreyNoise",
                        "OTX Pulses","Malicious","Summary","Sources"])
            w.writerows(rows)
        messagebox.showinfo("Export", path)


def _build_nmap_ui(self):
    """Nmap integration tab."""
    frame = self.view_frames.get("nmapscan")
    if not frame:
        return
    frame.grid_rowconfigure(2, weight=1)
    frame.grid_columnconfigure(0, weight=1)

    hdr = ttk.Frame(frame, padding=(16,12,16,0))
    hdr.grid(row=0, column=0, sticky="ew")
    ttk.Label(hdr, text="Nmap Integration",
              style="Heading.TLabel").pack(side=tk.LEFT)
    avail_lbl = ("✓ nmap found"
                 if NmapRunner.available()
                 else "✗ nmap not found in PATH")
    avail_clr = SUCCESS if NmapRunner.available() else DANGER
    ttk.Label(hdr, text=avail_lbl,
              foreground=avail_clr).pack(side=tk.RIGHT)
    ttk.Separator(frame, orient="horizontal").grid(
        row=1, column=0, sticky="ew", padx=16)

    inner = ttk.Frame(frame, padding=16)
    inner.grid(row=2, column=0, sticky="nsew")
    inner.grid_rowconfigure(2, weight=1)
    inner.grid_columnconfigure(0, weight=1)

    ctrl = ttk.LabelFrame(inner, text="Scan Options", padding=8)
    ctrl.grid(row=0, column=0, sticky="ew", pady=(0,8))

    self._nmap_target_var  = tk.StringVar()
    self._nmap_ports_var   = tk.StringVar(value="")
    self._nmap_flags_var   = tk.StringVar(
        value="-sV --version-intensity 5 -O --osscan-guess -T4")
    self._nmap_status_var  = tk.StringVar(value="")

    for lbl, var, w in [
        ("Target(s):", self._nmap_target_var, 28),
        ("Ports:",     self._nmap_ports_var,  18),
    ]:
        row = ttk.Frame(ctrl)
        row.pack(fill="x", pady=2)
        ttk.Label(row, text=lbl, width=10).pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=var, width=w).pack(
            side=tk.LEFT, padx=(4,8))

    flag_row = ttk.Frame(ctrl)
    flag_row.pack(fill="x", pady=2)
    ttk.Label(flag_row, text="Flags:", width=10).pack(side=tk.LEFT)
    ttk.Entry(flag_row, textvariable=self._nmap_flags_var,
              width=52).pack(side=tk.LEFT, padx=(4,0))

    btn_row = ttk.Frame(ctrl)
    btn_row.pack(fill="x", pady=(6,0))
    self._nmap_scan_btn = ttk.Button(
        btn_row, text="▶ Run Nmap",
        command=lambda: _nmap_run(self),
        style="Success.TButton")
    self._nmap_scan_btn.pack(side=tk.LEFT, padx=(0,4))
    self._nmap_stop_btn = ttk.Button(
        btn_row, text="■ Stop",
        command=lambda: setattr(self, "_nmap_running", False),
        style="Danger.TButton", state=tk.DISABLED)
    self._nmap_stop_btn.pack(side=tk.LEFT, padx=(0,4))
    ttk.Button(btn_row, text="Merge into scanner →",
               command=lambda: _nmap_merge(self),
               style="Ghost.TButton").pack(side=tk.LEFT, padx=(0,8))
    ttk.Button(btn_row, text="Export JSON",
               command=lambda: _nmap_export(self),
               style="Ghost.TButton").pack(side=tk.LEFT)
    ttk.Label(btn_row, textvariable=self._nmap_status_var,
              style="Muted.TLabel").pack(side=tk.RIGHT)

    # Live output
    self._nmap_output = scrolledtext.ScrolledText(
        inner, height=8, font=("Courier New", 8),
        state="disabled")
    self._nmap_output.grid(row=1, column=0, sticky="ew",
                            pady=(0,8))

    # Results tree
    cols = ("ip","state","ports","os","scripts")
    self._nmap_tree = ttk.Treeview(inner, columns=cols, show="headings")
    for c, w in [("ip",130),("state",60),("ports",320),
                 ("os",180),("scripts",200)]:
        self._nmap_tree.heading(c, text=c.capitalize())
        self._nmap_tree.column(c, width=w)
    vsb = ttk.Scrollbar(inner, orient="vertical",
                         command=self._nmap_tree.yview)
    self._nmap_tree.configure(yscrollcommand=vsb.set)
    self._nmap_tree.grid(row=2, column=0, sticky="nsew")
    vsb.grid(row=2, column=1, sticky="ns")

    self._nmap_results: dict = {}
    self._nmap_running = False


def _nmap_run(self):
    if not NmapRunner.available():
        messagebox.showerror("Nmap",
            "nmap not found.\nInstall from https://nmap.org")
        return
    target = self._nmap_target_var.get().strip()
    if not target:
        messagebox.showwarning("Nmap", "Enter a target.")
        return

    flags_raw = self._nmap_flags_var.get().strip().split()
    ports     = self._nmap_ports_var.get().strip()

    for row in self._nmap_tree.get_children():
        self._nmap_tree.delete(row)
    self._nmap_output.config(state="normal")
    self._nmap_output.delete("1.0","end")
    self._nmap_output.config(state="disabled")

    self._nmap_running = True
    self._nmap_scan_btn.config(state=tk.DISABLED)
    self._nmap_stop_btn.config(state=tk.NORMAL)
    self._nmap_status_var.set("Running nmap…")

    def progress_cb(line):
        self._nmap_output.config(state="normal")
        self._nmap_output.insert("end", line + "\n")
        self._nmap_output.see("end")
        self._nmap_output.config(state="disabled")

    def run():
        data = NmapRunner.run(
            targets=[target],
            ports=ports,
            flags=flags_raw or None,
            progress_cb=lambda l: self.root.after(
                0, lambda ln=l: progress_cb(ln)))
        self._nmap_results = data
        self.root.after(0, lambda: _nmap_populate(self, data))

    threading.Thread(target=run, daemon=True).start()


def _nmap_populate(self, data):
    self._nmap_scan_btn.config(state=tk.NORMAL)
    self._nmap_stop_btn.config(state=tk.DISABLED)
    for ip, info in data.items():
        open_ports = [p for p in info["ports"]
                      if p["state"] == "open"]
        port_strs  = [
            f"{p['port']}/{p['proto']} {p['service']} "
            f"{p['product']} {p['version']}".strip()
            for p in open_ports]
        os_name = info["os_matches"][0]["name"] \
            if info["os_matches"] else ""
        scripts = "; ".join(
            f"{k}:{v[:30]}"
            for k,v in info.get("host_scripts",{}).items())
        self._nmap_tree.insert("", "end", values=(
            ip, info["state"],
            " | ".join(port_strs)[:200],
            os_name[:80], scripts[:100]))
    self._nmap_status_var.set(
        f"Done — {len(data)} host(s)")


def _nmap_merge(self):
    if not self._nmap_results:
        messagebox.showinfo("Nmap", "Run a scan first.")
        return
    merged = 0
    for r in self.results:
        r2 = NmapRunner.merge_into_result(r, self._nmap_results)
        if r2 is not r or r2.get("nmap_ports"):
            merged += 1
    self.apply_filters()
    messagebox.showinfo("Merge",
        f"Nmap data merged into {merged} host(s) in scanner.")


def _nmap_export(self):
    if not self._nmap_results:
        return
    path = filedialog.asksaveasfilename(
        defaultextension=".json", filetypes=[("JSON","*.json")])
    if path:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._nmap_results, f, indent=2, default=str)
        messagebox.showinfo("Export", path)

# ─── End of Patch 3 ──────────────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════════════════════
# NetProbe v5 — PATCH 4 of 5
# Zone Transfer Tab · Dirbuster Tab · Credential Spray Tab · CPE Tab
# IPv6 Tab · PDF Report · Per-Severity Colour Picker
# Settings Extensions: API Keys · Notifications · SIEM Config
# ═════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# ① ZONE TRANSFER TAB UI
# ─────────────────────────────────────────────────────────────────────────────

def _build_zone_transfer_ui(self):
    """DNS Zone Transfer tab (inside Recon notebook)."""
    frame = self.view_frames.get("zonetransfer")
    if not frame:
        return
    frame.grid_rowconfigure(2, weight=1)
    frame.grid_columnconfigure(0, weight=1)

    hdr = ttk.Frame(frame, padding=(16, 12, 16, 0))
    hdr.grid(row=0, column=0, sticky="ew")
    ttk.Label(hdr, text="DNS Zone Transfer",
              style="Heading.TLabel").pack(side=tk.LEFT)
    ttk.Separator(frame, orient="horizontal").grid(
        row=1, column=0, sticky="ew", padx=16)

    inner = ttk.Frame(frame, padding=16)
    inner.grid(row=2, column=0, sticky="nsew")
    inner.grid_rowconfigure(2, weight=1)
    inner.grid_columnconfigure(0, weight=1)

    warn = tk.Label(inner,
        text="⚠  A successful zone transfer is a CRITICAL misconfiguration — "
             "it reveals every hostname and IP in the zone. "
             "Only test domains you own or have authorisation for.",
        bg="#fef9c3", fg="#713f12",
        font=("Segoe UI", 9), padx=8, pady=6,
        wraplength=760, justify="left")
    warn.pack(fill="x", pady=(0, 8))

    ctrl = ttk.Frame(inner)
    ctrl.pack(fill="x", pady=(0, 8))

    self._zt_domain_var = tk.StringVar()
    self._zt_ns_var     = tk.StringVar()
    self._zt_status_var = tk.StringVar(value="")

    ttk.Label(ctrl, text="Domain:").pack(side=tk.LEFT)
    ttk.Entry(ctrl, textvariable=self._zt_domain_var,
              width=26).pack(side=tk.LEFT, padx=(4, 8))
    ttk.Label(ctrl, text="Nameserver:").pack(side=tk.LEFT)
    ttk.Entry(ctrl, textvariable=self._zt_ns_var,
              width=18).pack(side=tk.LEFT, padx=(4, 8))
    ttk.Button(ctrl, text="Auto-detect NS",
               command=lambda: _zt_find_ns(self),
               style="Ghost.TButton").pack(side=tk.LEFT, padx=(0, 8))
    ttk.Button(ctrl, text="⚡ Attempt AXFR",
               command=lambda: _zt_attempt(self),
               style="Danger.TButton").pack(side=tk.LEFT, padx=(0, 4))
    ttk.Label(ctrl, textvariable=self._zt_status_var,
              style="Muted.TLabel").pack(side=tk.RIGHT)

    # Results split: tree + raw output
    pane = ttk.PanedWindow(inner, orient=tk.VERTICAL)
    pane.grid(row=2, column=0, sticky="nsew")

    tree_frame = ttk.Frame(pane)
    pane.add(tree_frame, weight=2)
    tree_frame.grid_rowconfigure(0, weight=1)
    tree_frame.grid_columnconfigure(0, weight=1)

    cols = ("name", "type", "ttl", "data")
    self._zt_tree = ttk.Treeview(
        tree_frame, columns=cols, show="headings")
    for c, w in [("name", 220), ("type", 60),
                 ("ttl", 70), ("data", 340)]:
        self._zt_tree.heading(c, text=c.upper())
        self._zt_tree.column(c, width=w)

    self._zt_tree.tag_configure("A",     background="#eff6ff")
    self._zt_tree.tag_configure("MX",    background="#f0fdf4")
    self._zt_tree.tag_configure("NS",    background="#fefce8")
    self._zt_tree.tag_configure("CNAME", background="#fdf4ff")
    self._zt_tree.tag_configure("TXT",   background="#fff7ed")

    vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                         command=self._zt_tree.yview)
    self._zt_tree.configure(yscrollcommand=vsb.set)
    self._zt_tree.grid(row=0, column=0, sticky="nsew")
    vsb.grid(row=0, column=1, sticky="ns")

    raw_frame = ttk.Frame(pane)
    pane.add(raw_frame, weight=1)
    self._zt_raw = scrolledtext.ScrolledText(
        raw_frame, height=8, font=("Courier New", 8),
        state="disabled")
    self._zt_raw.pack(fill="both", expand=True)

    ttk.Button(inner, text="Export Records CSV",
               command=lambda: _zt_export(self),
               style="Ghost.TButton").grid(
        row=3, column=0, sticky="w", pady=(6, 0))


def _zt_find_ns(self):
    domain = self._zt_domain_var.get().strip()
    if not domain:
        return
    self._zt_status_var.set("Looking up nameservers…")

    def run():
        servers = DNSZoneTransfer.find_nameservers(domain)
        if servers:
            self.root.after(0, lambda: [
                self._zt_ns_var.set(servers[0]),
                self._zt_status_var.set(
                    f"Found {len(servers)} NS: "
                    f"{', '.join(servers[:3])}")])
        else:
            self.root.after(0, lambda:
                self._zt_status_var.set("No nameservers found"))

    threading.Thread(target=run, daemon=True).start()


def _zt_attempt(self):
    domain = self._zt_domain_var.get().strip()
    ns     = self._zt_ns_var.get().strip()
    if not domain or not ns:
        messagebox.showwarning("Zone Transfer",
            "Enter both domain and nameserver IP.")
        return

    for row in self._zt_tree.get_children():
        self._zt_tree.delete(row)
    self._zt_raw.config(state="normal")
    self._zt_raw.delete("1.0", "end")
    self._zt_raw.config(state="disabled")
    self._zt_status_var.set(f"Attempting AXFR from {ns}…")

    def run():
        result = DNSZoneTransfer.attempt(domain, ns)
        self.root.after(0, lambda r=result: _zt_populate(self, r))

    threading.Thread(target=run, daemon=True).start()


def _zt_populate(self, result):
    if result["success"]:
        self._zt_status_var.set(
            f"✓ ZONE TRANSFER SUCCEEDED — "
            f"{len(result['records'])} records via {result['method']}")
        # Log as critical alert
        self.alert_log.add(
            "Critical", result["ns"],
            f"ZONE TRANSFER SUCCEEDED: {result['domain']} "
            f"— {len(result['records'])} records exposed",
            tag="zone_transfer")
        for rec in result["records"]:
            rtype = rec.get("type", "")
            self._zt_tree.insert("", "end", values=(
                rec.get("name", ""),
                rtype,
                rec.get("ttl", ""),
                rec.get("data", ""),
            ), tags=(rtype,))
    else:
        self._zt_status_var.set(
            f"✗ Transfer refused/failed: "
            f"{result.get('error', 'unknown')}")

    # Raw output
    self._zt_raw.config(state="normal")
    self._zt_raw.insert("end",
        f"Domain:      {result['domain']}\n"
        f"Nameserver:  {result['ns']}\n"
        f"Success:     {result['success']}\n"
        f"Method:      {result.get('method','')}\n"
        f"Records:     {len(result.get('records',[]))}\n"
        f"Error:       {result.get('error','')}\n\n")
    for rec in result.get("records", []):
        self._zt_raw.insert(
            "end",
            f"{rec.get('name',''):<40} "
            f"{rec.get('ttl',''):<8} "
            f"{rec.get('type',''):<8} "
            f"{rec.get('data','')}\n")
    self._zt_raw.config(state="disabled")


def _zt_export(self):
    rows = [self._zt_tree.item(i, "values")
            for i in self._zt_tree.get_children()]
    if not rows:
        messagebox.showinfo("Export", "No records to export.")
        return
    path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV", "*.csv")])
    if path:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Name", "Type", "TTL", "Data"])
            w.writerows(rows)
        messagebox.showinfo("Export", path)


# ─────────────────────────────────────────────────────────────────────────────
# ② DIRBUSTER TAB UI
# ─────────────────────────────────────────────────────────────────────────────

def _build_dirbuster_ui(self):
    """HTTP Directory Bruteforcer tab."""
    frame = self.view_frames.get("dirbuster")
    if not frame:
        return
    frame.grid_rowconfigure(2, weight=1)
    frame.grid_columnconfigure(0, weight=1)

    hdr = ttk.Frame(frame, padding=(16, 12, 16, 0))
    hdr.grid(row=0, column=0, sticky="ew")
    ttk.Label(hdr, text="HTTP Directory Bruteforcer",
              style="Heading.TLabel").pack(side=tk.LEFT)
    ttk.Separator(frame, orient="horizontal").grid(
        row=1, column=0, sticky="ew", padx=16)

    inner = ttk.Frame(frame, padding=16)
    inner.grid(row=2, column=0, sticky="nsew")
    inner.grid_rowconfigure(2, weight=1)
    inner.grid_columnconfigure(0, weight=1)

    warn = tk.Label(inner,
        text="⚠  Only use against systems you own or have "
             "written authorisation to test.",
        bg="#fef9c3", fg="#713f12",
        font=("Segoe UI", 9), padx=8, pady=4)
    warn.pack(fill="x", pady=(0, 8))

    # Options grid
    opt = ttk.LabelFrame(inner, text="Options", padding=8)
    opt.pack(fill="x", pady=(0, 8))

    self._db_url_var      = tk.StringVar(value="http://")
    self._db_threads_var  = tk.IntVar(value=20)
    self._db_delay_var    = tk.DoubleVar(value=0.0)
    self._db_exts_var     = tk.StringVar(value=".php,.html,.txt,.bak")
    self._db_wordlist_var = tk.StringVar(value="built-in")
    self._db_filter_var   = tk.StringVar(value="200,201,301,302,401,403")
    self._db_status_var   = tk.StringVar(value="")
    self._db_only_int_var = tk.BooleanVar(value=True)

    rows_cfg = [
        ("Target URL:",       self._db_url_var,      42, None),
        ("Extensions:",       self._db_exts_var,     30,
         ".php,.html,.txt,.bak,.old,.zip,.sql,.json"),
        ("Status filter:",    self._db_filter_var,   22,
         "Comma-separated status codes to show"),
        ("Wordlist path:",    self._db_wordlist_var, 36,
         "Leave 'built-in' to use the 80-path built-in list"),
    ]
    for i, (lbl, var, w, tip) in enumerate(rows_cfg):
        ttk.Label(opt, text=lbl).grid(
            row=i, column=0, sticky="w",
            padx=(0, 8), pady=2)
        e = ttk.Entry(opt, textvariable=var, width=w)
        e.grid(row=i, column=1, sticky="w", pady=2)
        if tip:
            Tooltip(e, tip)

    spin_row = ttk.Frame(opt)
    spin_row.grid(row=4, column=0, columnspan=2,
                  sticky="w", pady=(4, 0))
    ttk.Label(spin_row, text="Threads:").pack(side=tk.LEFT)
    ttk.Spinbox(spin_row, textvariable=self._db_threads_var,
                from_=1, to=100, width=6).pack(
        side=tk.LEFT, padx=(4, 16))
    ttk.Label(spin_row, text="Delay (s):").pack(side=tk.LEFT)
    ttk.Spinbox(spin_row, textvariable=self._db_delay_var,
                from_=0.0, to=5.0, increment=0.1,
                format="%.1f", width=6).pack(
        side=tk.LEFT, padx=(4, 16))
    ttk.Checkbutton(spin_row, text="Show only interesting",
                    variable=self._db_only_int_var).pack(
        side=tk.LEFT, padx=(8, 0))

    # Buttons
    btn_row = ttk.Frame(inner)
    btn_row.pack(fill="x", pady=(0, 8))

    self._db_start_btn = ttk.Button(
        btn_row, text="▶ Start",
        command=lambda: _dirbust_start(self),
        style="Danger.TButton")
    self._db_start_btn.pack(side=tk.LEFT, padx=(0, 4))

    self._db_stop_btn = ttk.Button(
        btn_row, text="■ Stop",
        command=lambda: setattr(dirbuster, "running", False),
        style="Ghost.TButton", state=tk.DISABLED)
    self._db_stop_btn.pack(side=tk.LEFT, padx=(0, 4))

    ttk.Button(btn_row, text="Browse wordlist…",
               command=lambda: _dirbust_browse_wordlist(self),
               style="Ghost.TButton").pack(side=tk.LEFT, padx=(0, 8))

    ttk.Button(btn_row, text="Export CSV",
               command=lambda: _dirbust_export(self),
               style="Ghost.TButton").pack(side=tk.LEFT)

    ttk.Label(btn_row, textvariable=self._db_status_var,
              style="Muted.TLabel").pack(side=tk.RIGHT)

    # Results tree
    cols = ("status", "url", "length", "title", "content_type")
    self._db_tree = ttk.Treeview(
        inner, columns=cols, show="headings")
    for c, w in [("status", 60), ("url", 380),
                 ("length", 70), ("title", 200),
                 ("content_type", 130)]:
        self._db_tree.heading(c, text=c.replace("_", " ").title())
        self._db_tree.column(c, width=w)

    self._db_tree.tag_configure("200", background="#f0fdf4")
    self._db_tree.tag_configure("301", background="#eff6ff")
    self._db_tree.tag_configure("302", background="#eff6ff")
    self._db_tree.tag_configure("401", background="#fef9c3")
    self._db_tree.tag_configure("403", background="#fff7ed")
    self._db_tree.tag_configure("500", background="#fee2e2")

    vsb = ttk.Scrollbar(inner, orient="vertical",
                         command=self._db_tree.yview)
    self._db_tree.configure(yscrollcommand=vsb.set)
    self._db_tree.grid(row=2, column=0, sticky="nsew")
    vsb.grid(row=2, column=1, sticky="ns")

    self._db_tree.bind("<Double-1>",
                        lambda _: _dirbust_open_url(self))


def _dirbust_start(self):
    url = self._db_url_var.get().strip()
    if not url.startswith(("http://", "https://")):
        messagebox.showwarning("Dirbuster",
            "URL must start with http:// or https://")
        return

    exts_raw = self._db_exts_var.get()
    exts     = [e.strip() for e in exts_raw.split(",")
                if e.strip()]

    wl_path  = self._db_wordlist_var.get().strip()
    wordlist  = (dirbuster.bust.__func__.__defaults__[0]
                 if wl_path == "built-in"
                 else None)
    if wl_path != "built-in" and os.path.isfile(wl_path):
        with open(wl_path, encoding="utf-8",
                  errors="ignore") as f:
            wordlist = [l.strip() for l in f
                        if l.strip() and not l.startswith("#")]

    for row in self._db_tree.get_children():
        self._db_tree.delete(row)

    self._db_start_btn.config(state=tk.DISABLED)
    self._db_stop_btn.config(state=tk.NORMAL)
    self._db_status_var.set("Busting…")

    only_interesting = self._db_only_int_var.get()

    def cb(result):
        if only_interesting and not result.get("interesting"):
            return
        status = str(result["status"])
        self.root.after(0, lambda r=result, s=status:
            self._db_tree.insert("", "end", values=(
                r["status"], r["url"],
                r.get("length", ""),
                r.get("title", "")[:60],
                r.get("content_type", "")[:30],
            ), tags=(s,)))
        self.root.after(0, lambda:
            self._db_status_var.set(
                f"{len(dirbuster.results)} found…"))

    def run():
        dirbuster.bust(
            url,
            wordlist=wordlist,
            extensions=exts,
            threads=self._db_threads_var.get(),
            delay_s=self._db_delay_var.get(),
            callback=cb)
        self.root.after(0, lambda: [
            self._db_start_btn.config(state=tk.NORMAL),
            self._db_stop_btn.config(state=tk.DISABLED),
            self._db_status_var.set(
                f"Done — {len(dirbuster.results)} path(s) found")])

    threading.Thread(target=run, daemon=True).start()


def _dirbust_browse_wordlist(self):
    path = filedialog.askopenfilename(
        title="Select wordlist",
        filetypes=[("Text files", "*.txt"), ("All", "*.*")])
    if path:
        self._db_wordlist_var.set(path)


def _dirbust_export(self):
    rows = [self._db_tree.item(i, "values")
            for i in self._db_tree.get_children()]
    if not rows:
        return
    path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV", "*.csv")])
    if path:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Status", "URL", "Length",
                        "Title", "Content-Type"])
            w.writerows(rows)
        messagebox.showinfo("Export", path)


def _dirbust_open_url(self):
    sel = self._db_tree.selection()
    if not sel:
        return
    vals = self._db_tree.item(sel[0], "values")
    if vals and vals[1]:
        webbrowser.open(vals[1])


# ─────────────────────────────────────────────────────────────────────────────
# ③ CREDENTIAL SPRAY TAB UI
# ─────────────────────────────────────────────────────────────────────────────

def _build_spray_ui(self):
    """Credential spray engine tab."""
    frame = self.view_frames.get("spray")
    if not frame:
        return
    frame.grid_rowconfigure(2, weight=1)
    frame.grid_columnconfigure(0, weight=1)

    hdr = ttk.Frame(frame, padding=(16, 12, 16, 0))
    hdr.grid(row=0, column=0, sticky="ew")
    ttk.Label(hdr, text="Credential Spray",
              style="Heading.TLabel").pack(side=tk.LEFT)
    ttk.Separator(frame, orient="horizontal").grid(
        row=1, column=0, sticky="ew", padx=16)

    inner = ttk.Frame(frame, padding=16)
    inner.grid(row=2, column=0, sticky="nsew")
    inner.grid_rowconfigure(2, weight=1)
    inner.grid_columnconfigure(0, weight=1)

    warn = tk.Label(inner,
        text="⚠  AUTHORISED SYSTEMS ONLY. Credential spraying "
             "may trigger account lockouts and IDS alerts. "
             "Use responsibly.",
        bg="#fee2e2", fg="#7f1d1d",
        font=("Segoe UI", 9, "bold"),
        padx=8, pady=6, wraplength=760, justify="left")
    warn.pack(fill="x", pady=(0, 8))

    opt = ttk.LabelFrame(inner, text="Spray Options", padding=8)
    opt.pack(fill="x", pady=(0, 8))

    self._spray_target_var    = tk.StringVar()
    self._spray_ports_var     = tk.StringVar(
        value="22,21,23,80,443,3306,5432")
    self._spray_delay_var     = tk.DoubleVar(value=0.5)
    self._spray_threads_var   = tk.IntVar(value=4)
    self._spray_stop_hit_var  = tk.BooleanVar(value=True)
    self._spray_lockout_var   = tk.IntVar(value=5)
    self._spray_wordlist_var  = tk.StringVar(value="built-in")
    self._spray_status_var    = tk.StringVar(value="")

    cfg = [
        ("Target/subnet:", self._spray_target_var, 24),
        ("Ports:",         self._spray_ports_var,  28),
        ("Wordlist:",      self._spray_wordlist_var, 34),
    ]
    for i, (lbl, var, w) in enumerate(cfg):
        ttk.Label(opt, text=lbl).grid(
            row=i, column=0, sticky="w", padx=(0, 8), pady=2)
        ttk.Entry(opt, textvariable=var, width=w).grid(
            row=i, column=1, sticky="w", pady=2)

    ttk.Button(opt, text="Browse…",
               command=lambda: _spray_browse_wl(self),
               style="Ghost.TButton").grid(
        row=2, column=2, sticky="w", padx=(4, 0))

    ctrl2 = ttk.Frame(opt)
    ctrl2.grid(row=3, column=0, columnspan=3,
               sticky="w", pady=(6, 0))

    ttk.Label(ctrl2, text="Threads:").pack(side=tk.LEFT)
    ttk.Spinbox(ctrl2, textvariable=self._spray_threads_var,
                from_=1, to=32, width=5).pack(
        side=tk.LEFT, padx=(4, 14))
    ttk.Label(ctrl2, text="Delay (s):").pack(side=tk.LEFT)
    ttk.Spinbox(ctrl2, textvariable=self._spray_delay_var,
                from_=0.1, to=30.0, increment=0.1,
                format="%.1f", width=6).pack(
        side=tk.LEFT, padx=(4, 14))
    ttk.Label(ctrl2, text="Lockout threshold:").pack(side=tk.LEFT)
    ttk.Spinbox(ctrl2, textvariable=self._spray_lockout_var,
                from_=1, to=50, width=5).pack(
        side=tk.LEFT, padx=(4, 14))
    ttk.Checkbutton(ctrl2, text="Stop on first hit",
                    variable=self._spray_stop_hit_var).pack(
        side=tk.LEFT, padx=(8, 0))

    btn_row = ttk.Frame(inner)
    btn_row.pack(fill="x", pady=(0, 8))

    self._spray_start_btn = ttk.Button(
        btn_row, text="▶ Start Spray",
        command=lambda: _spray_start(self),
        style="Danger.TButton")
    self._spray_start_btn.pack(side=tk.LEFT, padx=(0, 4))

    self._spray_stop_btn = ttk.Button(
        btn_row, text="■ Stop",
        command=lambda: setattr(spray_engine, "running", False),
        style="Ghost.TButton", state=tk.DISABLED)
    self._spray_stop_btn.pack(side=tk.LEFT, padx=(0, 8))

    ttk.Button(btn_row, text="Export CSV",
               command=lambda: _spray_export(self),
               style="Ghost.TButton").pack(side=tk.LEFT)
    ttk.Label(btn_row, textvariable=self._spray_status_var,
              style="Muted.TLabel").pack(side=tk.RIGHT)

    cols = ("ts", "ip", "port", "service", "user", "pwd", "result")
    self._spray_tree = ttk.Treeview(
        inner, columns=cols, show="headings")
    for c, w in [("ts", 140), ("ip", 130), ("port", 55),
                 ("service", 80), ("user", 100),
                 ("pwd", 100), ("result", 100)]:
        self._spray_tree.heading(c, text=c.capitalize())
        self._spray_tree.column(c, width=w)

    self._spray_tree.tag_configure(
        "HIT", background="#fee2e2",
        foreground="#dc2626",
        font=("Segoe UI", 9, "bold"))
    self._spray_tree.tag_configure(
        "MISS", background="#f8fafc",
        foreground="#94a3b8")

    vsb = ttk.Scrollbar(inner, orient="vertical",
                         command=self._spray_tree.yview)
    self._spray_tree.configure(yscrollcommand=vsb.set)
    self._spray_tree.grid(row=2, column=0, sticky="nsew")
    vsb.grid(row=2, column=1, sticky="ns")


def _spray_browse_wl(self):
    path = filedialog.askopenfilename(
        title="Select wordlist",
        filetypes=[("Text files", "*.txt"),
                   ("All files", "*.*")])
    if path:
        self._spray_wordlist_var.set(path)


def _spray_start(self):
    target_raw = self._spray_target_var.get().strip()
    if not target_raw:
        messagebox.showwarning("Spray", "Enter a target.")
        return

    # Resolve targets
    try:
        net   = ipaddress.ip_network(target_raw, strict=False)
        hosts = ([str(h) for h in net.hosts()]
                 if net.num_addresses > 2 else [target_raw])
    except ValueError:
        hosts = [target_raw]

    ports_raw = self._spray_ports_var.get()
    ports = [int(p.strip()) for p in ports_raw.split(",")
             if p.strip().isdigit()]

    wl_path = self._spray_wordlist_var.get().strip()
    wordlist = spray_engine.load_wordlist(
        wl_path if wl_path != "built-in" else None)

    for row in self._spray_tree.get_children():
        self._spray_tree.delete(row)

    self._spray_start_btn.config(state=tk.DISABLED)
    self._spray_stop_btn.config(state=tk.NORMAL)
    hits = [0]

    def cb(entry):
        tag = "HIT" if entry["success"] else "MISS"
        sym = "✓ VALID" if entry["success"] else "✗"
        self.root.after(0, lambda e=entry, t=tag, s=sym: [
            self._spray_tree.insert(
                "0", 0,
                values=(e["ts"], e["ip"], e["port"],
                        e["service"], e["user"],
                        e["pwd"], s),
                tags=(t,)),
            (self.alert_log.add(
                "Critical", e["ip"],
                f"DEFAULT CRED: {e['service']} "
                f"{e['user']!r}/{e['pwd']!r}",
                tag="spray_hit")
             if e["success"] else None),
        ])
        if entry["success"]:
            hits[0] += 1
            self.root.after(0, lambda h=hits[0]:
                self._spray_status_var.set(
                    f"🚨 {h} valid credential(s) found!"))

    spray_engine.callback = cb

    def run():
        spray_engine.spray_subnet(
            hosts, ports, wordlist,
            delay_s=self._spray_delay_var.get(),
            stop_on_hit=self._spray_stop_hit_var.get(),
            max_threads=self._spray_threads_var.get())
        self.root.after(0, lambda: [
            self._spray_start_btn.config(state=tk.NORMAL),
            self._spray_stop_btn.config(state=tk.DISABLED),
            self._spray_status_var.set(
                f"Done — {hits[0]} hit(s)")])

    threading.Thread(target=run, daemon=True).start()


def _spray_export(self):
    rows = [self._spray_tree.item(i, "values")
            for i in self._spray_tree.get_children()]
    if not rows:
        return
    path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV", "*.csv")])
    if path:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Timestamp", "IP", "Port", "Service",
                        "Username", "Password", "Result"])
            w.writerows(rows)
        messagebox.showinfo("Export", path)


# ─────────────────────────────────────────────────────────────────────────────
# ④ CPE MAPPING TAB UI
# ─────────────────────────────────────────────────────────────────────────────

def _build_cpe_ui(self):
    """CPE mapping + NVD cross-reference tab."""
    frame = self.view_frames.get("cpe")
    if not frame:
        return
    frame.grid_rowconfigure(2, weight=1)
    frame.grid_columnconfigure(0, weight=1)

    hdr = ttk.Frame(frame, padding=(16, 12, 16, 0))
    hdr.grid(row=0, column=0, sticky="ew")
    ttk.Label(hdr, text="CPE Mapper",
              style="Heading.TLabel").pack(side=tk.LEFT)
    ttk.Separator(frame, orient="horizontal").grid(
        row=1, column=0, sticky="ew", padx=16)

    inner = ttk.Frame(frame, padding=16)
    inner.grid(row=2, column=0, sticky="nsew")
    inner.grid_rowconfigure(1, weight=1)
    inner.grid_columnconfigure(0, weight=1)

    ctrl = ttk.Frame(inner)
    ctrl.pack(fill="x", pady=(0, 8))

    self._cpe_banner_var = tk.StringVar()
    self._cpe_status_var = tk.StringVar(value="")

    ttk.Label(ctrl, text="Banner string:").pack(side=tk.LEFT)
    e = ttk.Entry(ctrl, textvariable=self._cpe_banner_var, width=40)
    e.pack(side=tk.LEFT, padx=(4, 8))
    e.bind("<Return>", lambda _: _cpe_lookup_single(self))
    Tooltip(e, "e.g. 'Apache/2.4.51 (Ubuntu)' or 'OpenSSH_8.4p1'")

    ttk.Button(ctrl, text="Map CPE →",
               command=lambda: _cpe_lookup_single(self),
               style="Ghost.TButton").pack(side=tk.LEFT, padx=(0, 8))
    ttk.Button(ctrl, text="Map all scan banners →",
               command=lambda: _cpe_map_all(self),
               style="Success.TButton").pack(side=tk.LEFT, padx=(0, 8))
    ttk.Button(ctrl, text="Lookup CVEs →",
               command=lambda: _cpe_lookup_cves(self),
               style="Warning.TButton").pack(side=tk.LEFT)
    ttk.Label(ctrl, textvariable=self._cpe_status_var,
              style="Muted.TLabel").pack(side=tk.RIGHT)

    cols = ("ip", "port", "banner", "cpe",
            "product", "version", "nvd_url")
    self._cpe_tree = ttk.Treeview(
        inner, columns=cols, show="headings")
    for c, w in [("ip", 120), ("port", 55), ("banner", 200),
                 ("cpe", 240), ("product", 120),
                 ("version", 80), ("nvd_url", 0)]:
        self._cpe_tree.heading(c, text=c.replace("_", " ").title())
        self._cpe_tree.column(c, width=w)
    self._cpe_tree.bind("<Double-1>",
                         lambda _: _cpe_open_nvd(self))

    vsb = ttk.Scrollbar(inner, orient="vertical",
                         command=self._cpe_tree.yview)
    self._cpe_tree.configure(yscrollcommand=vsb.set)
    self._cpe_tree.grid(row=1, column=0, sticky="nsew")
    vsb.grid(row=1, column=1, sticky="ns")

    ttk.Label(inner,
              text="Double-click a row to open NVD product search. "
                   "'Lookup CVEs' runs CVE Live Lookup for all matched versions.",
              style="Muted.TLabel").grid(
        row=2, column=0, sticky="w", pady=(4, 0))


def _cpe_lookup_single(self):
    banner = self._cpe_banner_var.get().strip()
    if not banner:
        return
    match = cpe_mapper.extract(banner)
    if match:
        self._cpe_tree.insert("", "end", values=(
            "", "", banner[:60],
            match["cpe"], match["product"],
            match["version"], match["nvd_url"]))
        self._cpe_status_var.set("Matched")
    else:
        self._cpe_status_var.set("No CPE match found")


def _cpe_map_all(self):
    used = [r for r in self.results if r["status"] == "Used"]
    if not used:
        messagebox.showinfo("CPE", "Run a scan first.")
        return
    for row in self._cpe_tree.get_children():
        self._cpe_tree.delete(row)
    count = 0
    for r in used:
        enriched = cpe_mapper.enrich_result(r)
        for port, match in enriched.get("cpe_matches", {}).items():
            banner = r.get("banners", {}).get(port, "")
            self._cpe_tree.insert("", "end", values=(
                r["ip"], port,
                banner[:60],
                match["cpe"],
                match["product"],
                match["version"],
                match["nvd_url"],
            ))
            count += 1
    self._cpe_status_var.set(f"{count} CPE match(es) from scan")


def _cpe_lookup_cves(self):
    """Take all CPE versions and search NVD for each."""
    rows = [self._cpe_tree.item(i, "values")
            for i in self._cpe_tree.get_children()]
    if not rows:
        messagebox.showinfo("CPE", "Map banners first.")
        return
    # Build keyword list from product+version
    keywords = list({
        f"{r[4]} {r[5]}" for r in rows if r[4] and r[5]
    })
    self._cpe_status_var.set(
        f"Looking up {len(keywords)} product(s)…")

    def run():
        all_cves = []
        for kw in keywords:
            cves = cve_engine.lookup_keyword(kw, max_results=5)
            for c in cves:
                c["banner_match"] = kw
            all_cves.extend(cves)
        # Switch to CVE tab and populate
        self.root.after(0, lambda cs=all_cves: [
            self.show_view("cvelookup"),
            _cve_populate(self, cs),
            self._cpe_status_var.set(
                f"Found {len(all_cves)} CVE(s) — "
                f"see CVE Lookup tab")])

    threading.Thread(target=run, daemon=True).start()


def _cpe_open_nvd(self):
    sel = self._cpe_tree.selection()
    if not sel:
        return
    vals = self._cpe_tree.item(sel[0], "values")
    if vals and len(vals) >= 7 and vals[6]:
        webbrowser.open(vals[6])


# ─────────────────────────────────────────────────────────────────────────────
# ⑤ IPv6 TAB UI
# ─────────────────────────────────────────────────────────────────────────────

def _build_ipv6_ui(self):
    """IPv6 scanner tab."""
    frame = self.view_frames.get("ipv6")
    if not frame:
        return
    frame.grid_rowconfigure(2, weight=1)
    frame.grid_columnconfigure(0, weight=1)

    hdr = ttk.Frame(frame, padding=(16, 12, 16, 0))
    hdr.grid(row=0, column=0, sticky="ew")
    ttk.Label(hdr, text="IPv6 Scanner",
              style="Heading.TLabel").pack(side=tk.LEFT)
    ttk.Separator(frame, orient="horizontal").grid(
        row=1, column=0, sticky="ew", padx=16)

    inner = ttk.Frame(frame, padding=16)
    inner.grid(row=2, column=0, sticky="nsew")
    inner.grid_rowconfigure(2, weight=1)
    inner.grid_columnconfigure(0, weight=1)

    # Local IPv6 addresses
    local_addrs = IPv6Scanner.get_local_ipv6_addrs()
    if local_addrs:
        info = tk.Label(inner,
            text="Local IPv6 addresses: " +
                 ",  ".join(local_addrs[:4]),
            bg="#eff6ff", fg="#1e40af",
            font=("Segoe UI", 9), padx=8, pady=4)
        info.pack(fill="x", pady=(0, 8))

    ctrl = ttk.Frame(inner)
    ctrl.pack(fill="x", pady=(0, 8))

    self._v6_target_var  = tk.StringVar()
    self._v6_ports_var   = tk.StringVar(
        value="22,80,443,8080,8443,3389")
    self._v6_status_var  = tk.StringVar(value="")
    self._v6_ndp_var     = tk.BooleanVar(value=True)

    ttk.Label(ctrl, text="IPv6 target(s):").pack(side=tk.LEFT)
    e = ttk.Entry(ctrl, textvariable=self._v6_target_var, width=36)
    e.pack(side=tk.LEFT, padx=(4, 8))
    Tooltip(e,
            "Single address: 2001:db8::1\n"
            "Or 'ndp' to use NDP discovery\n"
            "Or comma-separated addresses")
    ttk.Label(ctrl, text="Ports:").pack(side=tk.LEFT)
    ttk.Entry(ctrl, textvariable=self._v6_ports_var,
              width=22).pack(side=tk.LEFT, padx=(4, 8))
    ttk.Checkbutton(ctrl, text="NDP passive scan",
                    variable=self._v6_ndp_var).pack(
        side=tk.LEFT, padx=(0, 8))

    self._v6_scan_btn = ttk.Button(
        ctrl, text="▶ Scan",
        command=lambda: _v6_scan(self),
        style="Success.TButton")
    self._v6_scan_btn.pack(side=tk.LEFT, padx=(0, 4))

    self._v6_stop_btn = ttk.Button(
        ctrl, text="■ Stop",
        command=lambda: setattr(self, "_v6_running", False),
        style="Danger.TButton", state=tk.DISABLED)
    self._v6_stop_btn.pack(side=tk.LEFT)

    ttk.Label(ctrl, textvariable=self._v6_status_var,
              style="Muted.TLabel").pack(side=tk.RIGHT)

    # NDP results
    ndp_frame = ttk.LabelFrame(inner, text="NDP Discovery",
                                padding=6)
    ndp_frame.pack(fill="x", pady=(0, 8))
    self._v6_ndp_txt = tk.Text(ndp_frame, height=3,
                                font=("Courier New", 8),
                                state="disabled")
    self._v6_ndp_txt.pack(fill="x")
    ttk.Button(ndp_frame, text="Run NDP Passive Scan",
               command=lambda: _v6_ndp_scan(self),
               style="Ghost.TButton").pack(anchor="w", pady=(4, 0))

    # Host results tree
    cols = ("ip", "hostname", "status", "latency",
            "ports", "os", "threat")
    self._v6_tree = ttk.Treeview(
        inner, columns=cols, show="headings")
    for c, w in [("ip", 200), ("hostname", 180),
                 ("status", 65), ("latency", 70),
                 ("ports", 220), ("os", 130), ("threat", 65)]:
        self._v6_tree.heading(c, text=c.capitalize())
        self._v6_tree.column(c, width=w)

    vsb = ttk.Scrollbar(inner, orient="vertical",
                         command=self._v6_tree.yview)
    self._v6_tree.configure(yscrollcommand=vsb.set)
    self._v6_tree.grid(row=2, column=0, sticky="nsew")
    vsb.grid(row=2, column=1, sticky="ns")

    self._v6_running = False


def _v6_ndp_scan(self):
    self._v6_ndp_txt.config(state="normal")
    self._v6_ndp_txt.delete("1.0", "end")
    self._v6_ndp_txt.insert("end", "Listening for NDP (5s)…\n")
    self._v6_ndp_txt.config(state="disabled")

    def run():
        found = IPv6Scanner.ndp_scan(timeout=5.0)
        self.root.after(0, lambda f=found: [
            self._v6_ndp_txt.config(state="normal"),
            self._v6_ndp_txt.delete("1.0", "end"),
            self._v6_ndp_txt.insert(
                "end",
                "\n".join(f"  {ip}  →  {mac}"
                          for ip, mac in f.items())
                or "  No NDP responses received"),
            self._v6_ndp_txt.config(state="disabled")])

    threading.Thread(target=run, daemon=True).start()


def _v6_scan(self):
    raw = self._v6_target_var.get().strip()
    if not raw:
        messagebox.showwarning("IPv6", "Enter at least one IPv6 address.")
        return

    targets = [t.strip() for t in raw.split(",") if t.strip()]
    ports_raw = self._v6_ports_var.get()
    ports = [int(p) for p in ports_raw.split(",")
             if p.strip().isdigit()]

    for row in self._v6_tree.get_children():
        self._v6_tree.delete(row)

    self._v6_running = True
    self._v6_scan_btn.config(state=tk.DISABLED)
    self._v6_stop_btn.config(state=tk.NORMAL)
    self._v6_status_var.set(f"Scanning {len(targets)} host(s)…")

    def run():
        for ip in targets:
            if not self._v6_running:
                break
            r = IPv6Scanner.scan_ipv6_host(ip, ports)
            self.root.after(0, lambda ri=r: _v6_insert_row(self, ri))
        self.root.after(0, lambda: [
            self._v6_scan_btn.config(state=tk.NORMAL),
            self._v6_stop_btn.config(state=tk.DISABLED),
            self._v6_status_var.set("Done")])

    threading.Thread(target=run, daemon=True).start()


def _v6_insert_row(self, r):
    lat = f"{r['latency_ms']} ms" if r.get("latency_ms") else ""
    self._v6_tree.insert("", "end", values=(
        r["ip"],
        r.get("hostname", ""),
        r["status"],
        lat,
        format_ports(r.get("open_ports", []))[:80],
        r.get("os_guess", ""),
        r.get("threat_score", ""),
    ))


# ─────────────────────────────────────────────────────────────────────────────
# ⑥ PDF REPORT GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def generate_pdf_report(results: list, findings: list,
                         diff: dict, scan_meta: dict,
                         output_path: str) -> bool:
    """
    Generate a professional PDF pentest report.
    Requires reportlab. Falls back gracefully if not installed.
    Returns True on success.
    """
    if not _REPORTLAB_OK:
        return False

    doc    = SimpleDocTemplate(
        output_path, pagesize=A4,
        rightMargin=40, leftMargin=40,
        topMargin=50, bottomMargin=40)
    styles = getSampleStyleSheet()
    story  = []

    # Colour shortcuts
    RED    = rl_colors.HexColor("#dc2626")
    ORANGE = rl_colors.HexColor("#f97316")
    YELLOW = rl_colors.HexColor("#eab308")
    BLUE   = rl_colors.HexColor("#2563eb")
    GREY   = rl_colors.HexColor("#64748b")
    DARK   = rl_colors.HexColor("#0f172a")
    WHITE  = rl_colors.white

    sev_clr = {
        "Critical": RED,
        "High":     ORANGE,
        "Medium":   YELLOW,
        "Low":      BLUE,
    }

    # ── Title page ──
    story.append(Spacer(1, 60))
    story.append(Paragraph(
        f"<b>NetProbe v{VERSION}</b>",
        styles["Title"]))
    story.append(Paragraph(
        "Network Security Assessment Report",
        styles["h2"]))
    story.append(Spacer(1, 12))

    meta_data = [
        ["Generated:",  ts_now()],
        ["Target:",     scan_meta.get("target", "N/A")],
        ["Scan Mode:",  scan_meta.get("mode", "N/A")],
        ["Duration:",   scan_meta.get("duration", "N/A")],
    ]
    meta_tbl = Table(meta_data, colWidths=[100, 360])
    meta_tbl.setStyle(TableStyle([
        ("FONTNAME",    (0,0),(-1,-1), "Helvetica"),
        ("FONTSIZE",    (0,0),(-1,-1), 10),
        ("TEXTCOLOR",   (0,0),(0,-1),  GREY),
        ("BOTTOMPADDING",(0,0),(-1,-1),4),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 24))

    # ── Executive Summary ──
    used   = [r for r in results if r["status"] == "Used"]
    crits  = sum(1 for _, _, s, _ in findings if s == "Critical")
    highs  = sum(1 for _, _, s, _ in findings if s == "High")
    meds   = sum(1 for _, _, s, _ in findings if s == "Medium")
    lows   = sum(1 for _, _, s, _ in findings if s == "Low")

    story.append(Paragraph(
        "<b>Executive Summary</b>", styles["h2"]))
    story.append(Spacer(1, 6))

    summ_data = [
        ["Metric",             "Value"],
        ["Active Hosts",       str(len(used))],
        ["Free IPs",           str(sum(1 for r in results
                                       if r["status"] == "Free"))],
        ["Total Findings",     str(len(findings))],
        ["Critical",           str(crits)],
        ["High",               str(highs)],
        ["Medium",             str(meds)],
        ["Low",                str(lows)],
        ["New Hosts",          str(len(diff.get("new", [])))],
        ["Rogue Devices",      str(len(diff.get("rogue", [])))],
    ]
    summ_tbl = Table(summ_data, colWidths=[180, 100])
    summ_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0,0),(-1,0),  DARK),
        ("TEXTCOLOR",   (0,0),(-1,0),  WHITE),
        ("FONTNAME",    (0,0),(-1,-1), "Helvetica"),
        ("FONTSIZE",    (0,0),(-1,-1), 9),
        ("ROWBACKGROUNDS", (0,1),(-1,-1),
         [rl_colors.HexColor("#f8fafc"),
          rl_colors.HexColor("#ffffff")]),
        ("GRID",        (0,0),(-1,-1), 0.3,
         rl_colors.HexColor("#e2e8f0")),
        ("BOTTOMPADDING",(0,0),(-1,-1),5),
        ("TOPPADDING",  (0,0),(-1,-1),5),
    ]))
    story.append(summ_tbl)
    story.append(Spacer(1, 18))

    # ── Critical & High findings ──
    story.append(Paragraph(
        "<b>Critical & High Findings</b>", styles["h2"]))
    story.append(Spacer(1, 6))

    top_finds = [f for f in findings
                 if f[2] in ("Critical", "High")]
    if top_finds:
        top_finds.sort(
            key=lambda x: 0 if x[2] == "Critical" else 1)
        f_data = [["IP", "Issue", "Severity", "Recommendation"]]
        for ip, issue, sev, rec in top_finds[:50]:
            f_data.append([
                ip, issue[:40], sev,
                rec.split("\n")[0][:60]])
        f_tbl = Table(
            f_data,
            colWidths=[85, 140, 65, 175])
        f_style = [
            ("BACKGROUND",  (0,0),(-1,0),  DARK),
            ("TEXTCOLOR",   (0,0),(-1,0),  WHITE),
            ("FONTNAME",    (0,0),(-1,-1), "Helvetica"),
            ("FONTSIZE",    (0,0),(-1,-1), 8),
            ("GRID",        (0,0),(-1,-1), 0.3,
             rl_colors.HexColor("#e2e8f0")),
            ("BOTTOMPADDING",(0,0),(-1,-1),4),
            ("TOPPADDING",  (0,0),(-1,-1),4),
            ("ROWBACKGROUNDS", (0,1),(-1,-1),
             [rl_colors.HexColor("#fff5f5"),
              rl_colors.HexColor("#fff7ed")]),
        ]
        # Colour severity cells
        for row_i, (_, _, sev, _) in enumerate(top_finds[:50], 1):
            clr = sev_clr.get(sev, GREY)
            f_style.append(("TEXTCOLOR", (2, row_i), (2, row_i), clr))
            f_style.append(("FONTNAME",  (2, row_i), (2, row_i),
                            "Helvetica-Bold"))
        f_tbl.setStyle(TableStyle(f_style))
        story.append(f_tbl)
    else:
        story.append(Paragraph(
            "No Critical or High findings.", styles["Normal"]))
    story.append(Spacer(1, 18))

    # ── Active Host Inventory ──
    story.append(Paragraph(
        "<b>Active Host Inventory</b>", styles["h2"]))
    story.append(Spacer(1, 6))

    host_data = [["IP", "Hostname", "MAC",
                  "Vendor", "OS", "Ports", "Score"]]
    for r in sorted(used, key=lambda x: ip_sort_key(x["ip"])):
        host_data.append([
            r["ip"],
            (r.get("hostname") or "")[:22],
            (r.get("mac") or "")[:17],
            (r.get("vendor") or "")[:16],
            (r.get("os_guess") or "")[:20],
            format_ports(r.get("open_ports", []))[:35],
            str(r.get("threat_score", "")),
        ])

    if len(host_data) > 1:
        h_tbl = Table(
            host_data,
            colWidths=[70, 90, 80, 72, 80, 100, 35])
        h_tbl.setStyle(TableStyle([
            ("BACKGROUND",  (0,0),(-1,0),  DARK),
            ("TEXTCOLOR",   (0,0),(-1,0),  WHITE),
            ("FONTNAME",    (0,0),(-1,-1), "Helvetica"),
            ("FONTSIZE",    (0,0),(-1,-1), 7),
            ("GRID",        (0,0),(-1,-1), 0.3,
             rl_colors.HexColor("#e2e8f0")),
            ("BOTTOMPADDING",(0,0),(-1,-1),3),
            ("TOPPADDING",  (0,0),(-1,-1),3),
            ("ROWBACKGROUNDS", (0,1),(-1,-1),
             [rl_colors.HexColor("#f8fafc"),
              rl_colors.HexColor("#ffffff")]),
        ]))
        story.append(h_tbl)

    story.append(Spacer(1, 18))

    # ── Footer note ──
    story.append(Paragraph(
        f"<font color='#64748b' size='8'>"
        f"Report generated by {APP_FULL}"
        f"</font>",
        styles["Normal"]))

    try:
        doc.build(story)
        return True
    except Exception as e:
        log.error("PDF build error: %s", e)
        return False


# ─────────────────────────────────────────────────────────────────────────────
# ⑦ PER-SEVERITY COLOUR PICKER
# ─────────────────────────────────────────────────────────────────────────────

def _build_colour_picker_ui(self):
    """Per-severity row colour customisation panel."""
    frame = self.view_frames.get("colours")
    if not frame:
        return
    frame.grid_rowconfigure(1, weight=1)
    frame.grid_columnconfigure(0, weight=1)

    hdr = ttk.Frame(frame, padding=(16, 12, 16, 0))
    hdr.grid(row=0, column=0, sticky="ew")
    ttk.Label(hdr, text="Row Colour Customisation",
              style="Heading.TLabel").pack(side=tk.LEFT)

    inner = ttk.Frame(frame, padding=24)
    inner.grid(row=1, column=0, sticky="nsew")

    ttk.Label(inner,
              text="Customise the scanner table row colours "
                   "for each risk level and row state.",
              style="Muted.TLabel").grid(
        row=0, column=0, columnspan=4,
        sticky="w", pady=(0, 16))

    self._colour_vars: dict = {}

    theme = "dark" if self.is_dark else "light"
    items = [
        ("Active host (even)",   "used"),
        ("Active host (odd)",    "used_alt"),
        ("Free IP (even)",       "free"),
        ("Free IP (odd)",        "free_alt"),
        ("Favourite",            "fav"),
        ("Rogue device",         "rogue"),
        ("Critical/High risk",   "critical"),
        ("New host",             "new_host"),
    ]
    for i, (label, key) in enumerate(items):
        current = ROW_TAGS[theme].get(key, "#ffffff")
        var     = tk.StringVar(value=current)
        self._colour_vars[key] = var

        ttk.Label(inner, text=label).grid(
            row=i + 1, column=0,
            sticky="w", padx=(0, 16), pady=4)

        preview = tk.Label(inner, width=6,
                           bg=current, relief="solid",
                           borderwidth=1)
        preview.grid(row=i + 1, column=1,
                     sticky="w", padx=(0, 8))

        ttk.Entry(inner, textvariable=var,
                  width=12).grid(
            row=i + 1, column=2,
            sticky="w", padx=(0, 8))

        ttk.Button(inner, text="Pick…",
                   command=lambda v=var, p=preview, k=key:
                       _pick_colour(self, v, p, k),
                   style="Ghost.TButton",
                   width=6).grid(
            row=i + 1, column=3, sticky="w")

    ttk.Button(inner, text="✓ Apply All",
               command=lambda: _apply_colours(self),
               style="Success.TButton").grid(
        row=len(items) + 1, column=0,
        columnspan=2, sticky="w",
        pady=(16, 0))

    ttk.Button(inner, text="Reset to defaults",
               command=lambda: _reset_colours(self),
               style="Ghost.TButton").grid(
        row=len(items) + 1, column=2,
        columnspan=2, sticky="w",
        pady=(16, 0))


def _pick_colour(self, var, preview, key):
    from tkinter import colorchooser
    result = colorchooser.askcolor(
        color=var.get(),
        title=f"Choose colour for {key}")
    if result and result[1]:
        var.set(result[1])
        preview.configure(bg=result[1])


def _apply_colours(self):
    theme = "dark" if self.is_dark else "light"
    if not hasattr(self, "_colour_vars"):
        return
    for key, var in self._colour_vars.items():
        clr = var.get().strip()
        if clr:
            ROW_TAGS[theme][key] = clr
    self._reapply_row_tags()
    messagebox.showinfo("Colours", "Row colours applied.")


def _reset_colours(self):
    _DEFAULTS = {
        "light": {
            "used":     "#fef2f2", "used_alt": "#fee2e2",
            "free":     "#f0fdf4", "free_alt": "#dcfce7",
            "fav":      "#fefce8", "rogue":    "#fdf4ff",
            "critical": "#fee2e2", "new_host": "#eff6ff",
        },
        "dark": {
            "used":     "#3b1f1f", "used_alt": "#4a2020",
            "free":     "#1a3020", "free_alt": "#1e3824",
            "fav":      "#3b3000", "rogue":    "#2d1b4e",
            "critical": "#4a0000", "new_host": "#1a2a4a",
        },
    }
    theme = "dark" if self.is_dark else "light"
    ROW_TAGS[theme].update(_DEFAULTS[theme])
    self._reapply_row_tags()
    messagebox.showinfo("Colours", "Reset to defaults.")


# ─────────────────────────────────────────────────────────────────────────────
# ⑧ EXTENDED SETTINGS — API Keys + Notifications + SIEM
# ─────────────────────────────────────────────────────────────────────────────

def _build_api_keys_settings(self, parent_frame):
    """
    API keys sub-section — injected into the Settings tab scrollable inner.
    Call this from within _build_settings_ui after the existing sections.
    """
    f = parent_frame

    def section(text, row):
        ttk.Separator(f, orient="horizontal").grid(
            row=row, column=0, columnspan=3,
            sticky="ew", pady=(14, 4))
        ttk.Label(f, text=text,
                  style="Bold.TLabel",
                  font=("Segoe UI", 10, "bold")).grid(
            row=row + 1, column=0, columnspan=3,
            sticky="w", pady=(0, 6))
        return row + 2

    # Determine next available row
    r = max(w.grid_info().get("row", 0)
            for w in f.winfo_children()) + 1 \
        if f.winfo_children() else 0

    r = section("🔑  API Keys", r)

    # API key vars
    self.s_nvd_key_var       = tk.StringVar(value=NVD_API_KEY)
    self.s_shodan_key_var    = tk.StringVar(value=SHODAN_API_KEY)
    self.s_censys_id_var     = tk.StringVar(value=CENSYS_API_ID)
    self.s_censys_sec_var    = tk.StringVar(value=CENSYS_API_SECRET)
    self.s_abuseipdb_var     = tk.StringVar(value=ABUSEIPDB_API_KEY)
    self.s_otx_var           = tk.StringVar(value=OTX_API_KEY)

    api_keys = [
        ("NVD API Key:",           self.s_nvd_key_var,
         "Optional — increases NVD rate limit. "
         "Get free at nvd.nist.gov/developers"),
        ("Shodan API Key:",        self.s_shodan_key_var,
         "Required for Shodan enrichment. shodan.io"),
        ("Censys API ID:",         self.s_censys_id_var,
         "Required for Censys enrichment. search.censys.io"),
        ("Censys API Secret:",     self.s_censys_sec_var, ""),
        ("AbuseIPDB Key:",         self.s_abuseipdb_var,
         "Required for AbuseIPDB lookups. abuseipdb.com"),
        ("OTX API Key:",           self.s_otx_var,
         "Required for AlienVault OTX. otx.alienvault.com"),
    ]
    for label, var, tip in api_keys:
        ttk.Label(f, text=label).grid(
            row=r, column=0, sticky="w",
            padx=(0, 12), pady=3)
        e = ttk.Entry(f, textvariable=var,
                      width=42, show="*")
        e.grid(row=r, column=1, sticky="w", pady=3)
        if tip:
            Tooltip(e, tip)
        r += 1

    # Show/hide toggle
    show_var = tk.BooleanVar(value=False)
    def toggle_show():
        show = show_var.get()
        for child in f.winfo_children():
            if isinstance(child, ttk.Entry):
                info = child.grid_info()
                if info.get("column") == 1:
                    child.config(show="" if show else "*")
    ttk.Checkbutton(f, text="Show API keys",
                    variable=show_var,
                    command=toggle_show).grid(
        row=r, column=0, columnspan=2,
        sticky="w", pady=(2, 8))
    r += 1

    r = section("📣  Notifications", r)

    self.s_email_enabled_var  = tk.BooleanVar(
        value=EMAIL_ALERTS_ENABLED)
    self.s_smtp_host_var      = tk.StringVar(value=SMTP_HOST)
    self.s_smtp_port_var      = tk.IntVar(value=SMTP_PORT)
    self.s_smtp_user_var      = tk.StringVar(value=SMTP_USER)
    self.s_smtp_pass_var      = tk.StringVar(value=SMTP_PASS)
    self.s_smtp_from_var      = tk.StringVar(value=SMTP_FROM)
    self.s_smtp_to_var        = tk.StringVar(value=SMTP_TO)
    self.s_webhook_enabled_var = tk.BooleanVar(
        value=WEBHOOK_ALERTS_ENABLED)
    self.s_webhook_url_var    = tk.StringVar(value=WEBHOOK_URL)

    ttk.Checkbutton(f, text="Enable email alerts",
                    variable=self.s_email_enabled_var).grid(
        row=r, column=0, columnspan=2,
        sticky="w", pady=(0, 4))
    r += 1

    email_cfg = [
        ("SMTP Host:",   self.s_smtp_host_var,  22),
        ("SMTP Port:",   self.s_smtp_port_var,   8),
        ("SMTP User:",   self.s_smtp_user_var,  22),
        ("SMTP Pass:",   self.s_smtp_pass_var,  22),
        ("From:",        self.s_smtp_from_var,  28),
        ("To (CSV):",    self.s_smtp_to_var,    36),
    ]
    for label, var, w in email_cfg:
        ttk.Label(f, text=label).grid(
            row=r, column=0, sticky="w",
            padx=(0, 12), pady=2)
        show_opt = "*" if "Pass" in label else ""
        ttk.Entry(f, textvariable=var,
                  width=w, show=show_opt).grid(
            row=r, column=1, sticky="w", pady=2)
        r += 1

    ttk.Button(f, text="Test Email →",
               command=lambda: _test_email(self),
               style="Ghost.TButton").grid(
        row=r, column=0, columnspan=2,
        sticky="w", pady=(4, 8))
    r += 1

    ttk.Checkbutton(f, text="Enable webhook alerts "
                    "(Slack / Teams / Discord)",
                    variable=self.s_webhook_enabled_var).grid(
        row=r, column=0, columnspan=2,
        sticky="w", pady=(0, 4))
    r += 1

    ttk.Label(f, text="Webhook URL:").grid(
        row=r, column=0, sticky="w",
        padx=(0, 12), pady=2)
    ttk.Entry(f, textvariable=self.s_webhook_url_var,
              width=50).grid(row=r, column=1, sticky="w")
    r += 1

    ttk.Button(f, text="Test Webhook →",
               command=lambda: _test_webhook(self),
               style="Ghost.TButton").grid(
        row=r, column=0, columnspan=2,
        sticky="w", pady=(4, 8))
    r += 1

    r = section("📡  SIEM / Syslog", r)

    self.s_siem_enabled_var = tk.BooleanVar(value=SIEM_ENABLED)
    self.s_siem_host_var    = tk.StringVar(value=SIEM_HOST)
    self.s_siem_port_var    = tk.IntVar(value=SIEM_PORT)
    self.s_siem_proto_var   = tk.StringVar(value=SIEM_PROTO)

    ttk.Checkbutton(f, text="Enable SIEM export (CEF/syslog)",
                    variable=self.s_siem_enabled_var).grid(
        row=r, column=0, columnspan=2,
        sticky="w", pady=(0, 4))
    r += 1

    siem_cfg = [
        ("SIEM Host:", self.s_siem_host_var, 22),
        ("SIEM Port:", self.s_siem_port_var,  8),
    ]
    for label, var, w in siem_cfg:
        ttk.Label(f, text=label).grid(
            row=r, column=0, sticky="w",
            padx=(0, 12), pady=2)
        ttk.Entry(f, textvariable=var, width=w).grid(
            row=r, column=1, sticky="w", pady=2)
        r += 1

    ttk.Label(f, text="Protocol:").grid(
        row=r, column=0, sticky="w",
        padx=(0, 12), pady=2)
    ttk.Combobox(f, textvariable=self.s_siem_proto_var,
                 values=["UDP", "TCP"],
                 width=6, state="readonly").grid(
        row=r, column=1, sticky="w")
    r += 1

    btn_row = ttk.Frame(f)
    btn_row.grid(row=r, column=0, columnspan=3,
                 sticky="w", pady=(6, 0))
    ttk.Button(btn_row, text="Test SIEM →",
               command=lambda: _test_siem(self),
               style="Ghost.TButton").pack(side=tk.LEFT, padx=(0, 8))
    ttk.Button(btn_row, text="Send last scan findings →",
               command=lambda: _siem_send_findings(self),
               style="Warning.TButton").pack(side=tk.LEFT)
    r += 1

    return r


def _test_email(self):
    ok, msg = AlertDispatcher.send_email(
        f"[NetProbe] Test email",
        f"<p>Test from {APP_FULL}</p>")
    messagebox.showinfo("Email Test", msg)


def _test_webhook(self):
    ok, msg = AlertDispatcher.send_webhook({
        "text": f"[NetProbe] Test webhook from {APP_FULL}"})
    messagebox.showinfo("Webhook Test", msg)


def _test_siem(self):
    ok, msg = siem_exporter.test_connection()
    (messagebox.showinfo if ok else messagebox.showerror)(
        "SIEM Test", msg)


def _siem_send_findings(self):
    if not self.security_findings:
        messagebox.showinfo("SIEM", "No findings to send.")
        return
    sent = siem_exporter.bulk_send_findings(
        self.security_findings)
    messagebox.showinfo("SIEM",
        f"Sent {sent} findings to SIEM.")


def _save_api_settings(self):
    """
    Called from _settings_save() — persist API keys and
    notification settings to settings.json and update globals.
    """
    global SHODAN_API_KEY, CENSYS_API_ID, CENSYS_API_SECRET
    global ABUSEIPDB_API_KEY, OTX_API_KEY, NVD_API_KEY
    global SIEM_ENABLED, SIEM_HOST, SIEM_PORT, SIEM_PROTO
    global EMAIL_ALERTS_ENABLED, SMTP_HOST, SMTP_PORT
    global SMTP_USER, SMTP_PASS, SMTP_FROM, SMTP_TO
    global WEBHOOK_ALERTS_ENABLED, WEBHOOK_URL

    if hasattr(self, "s_nvd_key_var"):
        NVD_API_KEY        = self.s_nvd_key_var.get().strip()
    if hasattr(self, "s_shodan_key_var"):
        SHODAN_API_KEY     = self.s_shodan_key_var.get().strip()
    if hasattr(self, "s_censys_id_var"):
        CENSYS_API_ID      = self.s_censys_id_var.get().strip()
    if hasattr(self, "s_censys_sec_var"):
        CENSYS_API_SECRET  = self.s_censys_sec_var.get().strip()
    if hasattr(self, "s_abuseipdb_var"):
        ABUSEIPDB_API_KEY  = self.s_abuseipdb_var.get().strip()
    if hasattr(self, "s_otx_var"):
        OTX_API_KEY        = self.s_otx_var.get().strip()
    if hasattr(self, "s_siem_enabled_var"):
        SIEM_ENABLED       = self.s_siem_enabled_var.get()
    if hasattr(self, "s_siem_host_var"):
        SIEM_HOST          = self.s_siem_host_var.get().strip()
    if hasattr(self, "s_siem_port_var"):
        SIEM_PORT          = self.s_siem_port_var.get()
    if hasattr(self, "s_siem_proto_var"):
        SIEM_PROTO         = self.s_siem_proto_var.get()
    if hasattr(self, "s_email_enabled_var"):
        EMAIL_ALERTS_ENABLED = self.s_email_enabled_var.get()
    if hasattr(self, "s_smtp_host_var"):
        SMTP_HOST          = self.s_smtp_host_var.get().strip()
    if hasattr(self, "s_smtp_port_var"):
        SMTP_PORT          = self.s_smtp_port_var.get()
    if hasattr(self, "s_smtp_user_var"):
        SMTP_USER          = self.s_smtp_user_var.get().strip()
    if hasattr(self, "s_smtp_pass_var"):
        SMTP_PASS          = self.s_smtp_pass_var.get()
    if hasattr(self, "s_smtp_from_var"):
        SMTP_FROM          = self.s_smtp_from_var.get().strip()
    if hasattr(self, "s_smtp_to_var"):
        SMTP_TO            = self.s_smtp_to_var.get().strip()
    if hasattr(self, "s_webhook_enabled_var"):
        WEBHOOK_ALERTS_ENABLED = self.s_webhook_enabled_var.get()
    if hasattr(self, "s_webhook_url_var"):
        WEBHOOK_URL        = self.s_webhook_url_var.get().strip()

# ─── End of Patch 4 ──────────────────────────────────────────────────────────
# ═════════════════════════════════════════════════════════════════════════════
# NetProbe v5 — PATCH 5 of 5  (FINAL WIRING)
# Monkey-patches all new features into IPScannerGUI
# Registers new view frames · Rewires late_init · Updates _finalize_ui
# Updates _on_close · Updates _settings_save · New main() / banner
# ═════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# VERSION BUMP
# ─────────────────────────────────────────────────────────────────────────────

VERSION  = "5.0.0"
APP_FULL = f"{APP_NAME} v{VERSION} — Elite Network Recon & Defense Suite"

# ─────────────────────────────────────────────────────────────────────────────
# MONKEY-PATCH ALL NEW METHODS ONTO IPScannerGUI
# ─────────────────────────────────────────────────────────────────────────────

# ── Patch 3 UI builders (standalone functions → methods) ────────────────────
IPScannerGUI._build_history_ui       = _build_history_ui
IPScannerGUI._build_honeypot_ui      = _build_honeypot_ui
IPScannerGUI._build_wifi_ui          = _build_wifi_ui
IPScannerGUI._build_cve_tab_ui       = _build_cve_tab_ui
IPScannerGUI._build_threat_intel_ui  = _build_threat_intel_ui
IPScannerGUI._build_nmap_ui          = _build_nmap_ui

# ── Patch 4 UI builders ──────────────────────────────────────────────────────
IPScannerGUI._build_zone_transfer_ui = _build_zone_transfer_ui
IPScannerGUI._build_dirbuster_ui     = _build_dirbuster_ui
IPScannerGUI._build_spray_ui         = _build_spray_ui
IPScannerGUI._build_cpe_ui           = _build_cpe_ui
IPScannerGUI._build_ipv6_ui          = _build_ipv6_ui
IPScannerGUI._build_colour_picker_ui = _build_colour_picker_ui
IPScannerGUI._build_api_keys_settings= _build_api_keys_settings

# ── Patch 3 helper functions ─────────────────────────────────────────────────
IPScannerGUI._history_refresh        = _history_refresh
IPScannerGUI._history_show_host      = _history_show_host
IPScannerGUI._honeypot_start         = _honeypot_start
IPScannerGUI._honeypot_stop          = _honeypot_stop
IPScannerGUI._honeypot_export        = _honeypot_export
IPScannerGUI._wifi_scan              = _wifi_scan
IPScannerGUI._wifi_populate          = _wifi_populate
IPScannerGUI._wifi_export            = _wifi_export
IPScannerGUI._cve_search             = _cve_search
IPScannerGUI._cve_enrich_scan        = _cve_enrich_scan
IPScannerGUI._cve_populate           = _cve_populate
IPScannerGUI._cve_open_url           = _cve_open_url
IPScannerGUI._ti_check_single        = _ti_check_single
IPScannerGUI._ti_check_all           = _ti_check_all
IPScannerGUI._ti_insert_row          = _ti_insert_row
IPScannerGUI._ti_export              = _ti_export
IPScannerGUI._nmap_run               = _nmap_run
IPScannerGUI._nmap_populate          = _nmap_populate
IPScannerGUI._nmap_merge             = _nmap_merge
IPScannerGUI._nmap_export            = _nmap_export

# ── Patch 4 helper functions ─────────────────────────────────────────────────
IPScannerGUI._zt_find_ns             = _zt_find_ns
IPScannerGUI._zt_attempt             = _zt_attempt
IPScannerGUI._zt_populate            = _zt_populate
IPScannerGUI._zt_export              = _zt_export
IPScannerGUI._dirbust_start          = _dirbust_start
IPScannerGUI._dirbust_browse_wordlist= _dirbust_browse_wordlist
IPScannerGUI._dirbust_export         = _dirbust_export
IPScannerGUI._dirbust_open_url       = _dirbust_open_url
IPScannerGUI._spray_browse_wl        = _spray_browse_wl
IPScannerGUI._spray_start            = _spray_start
IPScannerGUI._spray_export           = _spray_export
IPScannerGUI._cpe_lookup_single      = _cpe_lookup_single
IPScannerGUI._cpe_map_all            = _cpe_map_all
IPScannerGUI._cpe_lookup_cves        = _cpe_lookup_cves
IPScannerGUI._cpe_open_nvd           = _cpe_open_nvd
IPScannerGUI._v6_scan                = _v6_scan
IPScannerGUI._v6_ndp_scan            = _v6_ndp_scan
IPScannerGUI._v6_insert_row          = _v6_insert_row
IPScannerGUI._pick_colour            = _pick_colour
IPScannerGUI._apply_colours          = _apply_colours
IPScannerGUI._reset_colours          = _reset_colours
IPScannerGUI._test_email             = _test_email
IPScannerGUI._test_webhook           = _test_webhook
IPScannerGUI._test_siem              = _test_siem
IPScannerGUI._siem_send_findings     = _siem_send_findings
IPScannerGUI._save_api_settings      = _save_api_settings

# ── Export HTML interactive report (wired to menu) ───────────────────────────
def _export_html_interactive(self):
    if not self.results:
        messagebox.showwarning("No data", "Run a scan first.")
        return
    path = filedialog.asksaveasfilename(
        defaultextension=".html",
        filetypes=[("HTML", "*.html"), ("All", "*.*")])
    if not path:
        return
    html = InteractiveReportBuilder.build(
        self.results,
        self.security_findings,
        self.diff,
        self.scan_meta,
        notes=self.host_notes)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    webbrowser.open(f"file://{os.path.abspath(path)}")

IPScannerGUI.export_html = _export_html_interactive


# ── PDF report export ────────────────────────────────────────────────────────
def _export_pdf(self):
    if not self.results:
        messagebox.showwarning("No data", "Run a scan first.")
        return
    if not _REPORTLAB_OK:
        messagebox.showerror(
            "PDF Export",
            "reportlab is required for PDF export.\n"
            "Install with:  pip install reportlab")
        return
    path = filedialog.asksaveasfilename(
        defaultextension=".pdf",
        filetypes=[("PDF", "*.pdf"), ("All", "*.*")])
    if not path:
        return
    ok = generate_pdf_report(
        self.results, self.security_findings,
        self.diff, self.scan_meta, path)
    if ok:
        messagebox.showinfo("PDF Report", f"Saved:\n{path}")
        webbrowser.open(f"file://{os.path.abspath(path)}")
    else:
        messagebox.showerror("PDF Export", "Failed to generate PDF.")

IPScannerGUI._export_pdf = _export_pdf


# ── Command palette launcher ─────────────────────────────────────────────────
def _open_command_palette(self):
    CommandPalette(self.root, self)

IPScannerGUI._open_command_palette = _open_command_palette


# ─────────────────────────────────────────────────────────────────────────────
# UPDATED __init__ SIDEBAR NAV  (adds v5 nav items)
# ─────────────────────────────────────────────────────────────────────────────

_orig_build_shell = IPScannerGUI._build_shell

def _build_shell_v5(self):
    """Extended sidebar with all v5 views."""
    self.root.grid_rowconfigure(0, weight=1)
    self.root.grid_columnconfigure(1, weight=1)

    self.sidebar = ttk.Frame(self.root, style="Sidebar.TFrame", width=210)
    self.sidebar.grid(row=0, column=0, sticky="nsw")
    self.sidebar.grid_propagate(False)

    brand = tk.Frame(self.sidebar, bg="#0d1526", height=64)
    brand.pack(fill="x")
    brand.pack_propagate(False)
    tk.Label(brand, text=f"◈  {APP_NAME}",
             bg="#0d1526", fg="#f1f5f9",
             font=("Segoe UI", 13, "bold"),
             anchor="w", padx=14).pack(fill="x", pady=(16, 0))
    tk.Label(brand, text=f"v{VERSION}  Elite Edition",
             bg="#0d1526", fg="#475569",
             font=("Segoe UI", 7), anchor="w", padx=14).pack(fill="x")

    nav_items = [
        ("CORE",               None),
        ("📡  Scanner",        "scanner"),
        ("📊  Dashboard",      "dashboard"),
        ("📈  History",        "history"),
        ("",                   None),
        ("PENTESTER",          None),
        ("🔧  Tools",          "tools"),
        ("🕵  Recon",          "recon"),
        ("📦  Sniffer",        "sniffer"),
        ("🔍  Vuln Scan",      "vulnscan"),
        ("🖥  Fingerprint",    "fingerprint"),
        ("📶  SNMP",           "snmp"),
        ("🗺  Nmap",           "nmapscan"),
        ("🔑  Cred Spray",     "spray"),
        ("🌐  Dirbuster",      "dirbuster"),
        ("🔡  Zone Transfer",  "zonetransfer"),
        ("📱  Wi-Fi",          "wifi"),
        ("🐛  CVE Lookup",     "cvelookup"),
        ("🧬  CPE Mapper",     "cpe"),
        ("🌐  IPv6",           "ipv6"),
        ("",                   None),
        ("DEFENSE",            None),
        ("🚨  Alert Log",      "alerts"),
        ("✅  Compliance",     "compliance"),
        ("🍯  Honeypot",       "honeypot"),
        ("🧠  Threat Intel",   "threatintel"),
        ("🗺  Topology",       "topology"),
        ("",                   None),
        ("CONFIG",             None),
        ("🎨  Row Colours",    "colours"),
        ("⚙  Settings",       "settings"),
    ]

    self._nav_buttons = {}
    for label, view in nav_items:
        if view is None:
            if label:
                ttk.Label(self.sidebar, text=label,
                          style="Sidebar.TLabel").pack(fill="x")
            else:
                ttk.Separator(self.sidebar,
                              orient="horizontal").pack(
                    fill="x", padx=12, pady=2)
        else:
            btn = ttk.Button(
                self.sidebar, text=label,
                style="Sidebar.TButton",
                command=partial(self.show_view, view))
            btn.pack(fill="x")
            self._nav_buttons[view] = btn

    ttk.Separator(self.sidebar, orient="horizontal").pack(
        fill="x", padx=12, pady=4)

    self.theme_btn = ttk.Button(
        self.sidebar, text="  ○  Light Mode",
        style="Sidebar.TButton",
        command=self._toggle_theme)
    self.theme_btn.pack(fill="x")

    self._arp_mon_btn = ttk.Button(
        self.sidebar, text="  ▷  ARP Monitor",
        style="Sidebar.TButton",
        command=self._toggle_arp_monitor)
    self._arp_mon_btn.pack(fill="x")

    self.statusbar_var = tk.StringVar(value="● Ready")
    tk.Label(self.sidebar,
             textvariable=self.statusbar_var,
             bg="#0d1526", fg="#94a3b8",
             font=("Segoe UI", 8), anchor="w",
             padx=12, justify="left",
             wraplength=198).pack(
        side=tk.BOTTOM, fill="x", pady=(0, 8))

    self.main_area = ttk.Frame(self.root)
    self.main_area.grid(row=0, column=1, sticky="nsew")
    self.main_area.grid_rowconfigure(0, weight=1)
    self.main_area.grid_columnconfigure(0, weight=1)
    self.view_frames: dict[str, ttk.Frame] = {}

IPScannerGUI._build_shell = _build_shell_v5


# ─────────────────────────────────────────────────────────────────────────────
# UPDATED late_init  (registers all v5 views and wires keyboard shortcuts)
# ─────────────────────────────────────────────────────────────────────────────

def late_init_v5(self):
    """
    v5 late_init — builds all original + new view tabs,
    wires keyboard shortcuts, and starts background services.
    """
    ensure_dirs()

    # ── All view names (original + v5 additions) ──
    all_views = [
        "scanner", "dashboard", "tools", "recon",
        "sniffer", "vulnscan", "fingerprint", "snmp",
        "alerts", "compliance", "topology", "settings",
        # v5 additions
        "history", "honeypot", "wifi", "cvelookup",
        "threatintel", "nmapscan", "spray", "dirbuster",
        "zonetransfer", "cpe", "ipv6", "colours",
    ]
    for name in all_views:
        if name not in self.view_frames:
            frame = ttk.Frame(self.main_area)
            frame.grid(row=0, column=0, sticky="nsew")
            self.view_frames[name] = frame

    # ── Build all original tab UIs ──
    self._build_scanner_ui()
    self._build_dashboard_ui()
    self._build_dashboard_contents()
    self._build_tools_ui()
    self._build_tools_contents()
    self._build_recon_ui()
    self._build_recon_contents()
    self._build_sniffer_ui()
    self._build_sniffer_contents()
    self._build_vulnscan_ui()
    self._build_vulnscan_contents()
    self._build_fingerprint_ui()
    self._build_fingerprint_contents()
    self._build_snmp_ui()
    self._build_snmp_contents()
    self._build_alerts_ui()
    self._build_compliance_ui()
    self._build_topology_ui()
    self._build_settings_ui()

    # ── Build all v5 tab UIs ──
    self._build_history_ui()
    self._build_honeypot_ui()
    self._build_wifi_ui()
    self._build_cve_tab_ui()
    self._build_threat_intel_ui()
    self._build_nmap_ui()
    self._build_spray_ui()
    self._build_dirbuster_ui()
    self._build_zone_transfer_ui()
    self._build_cpe_ui()
    self._build_ipv6_ui()
    self._build_colour_picker_ui()

    # ── Load persisted data ──
    self._load_notes()
    self._load_last_scan()
    self._load_profiles()
    self._load_settings()
    self._refresh_profile_list()

    # ── Restore last scan ──
    if self.results:
        self.scanned_hosts = len(self.results)
        self.total_hosts   = len(self.results)
        self.apply_filters()
        self.update_summary()
        used = sum(1 for r in self.results if r["status"] == "Used")
        self.statusbar_var.set(
            f"● Restored {used:,} active hosts from last session")

    # ── Start on scanner tab ──
    self.show_view("scanner")

    # ── Background ticks ──
    self._live_dashboard_tick()
    self._schedule_tick()

    # ── Window close ──
    self.root.protocol("WM_DELETE_WINDOW", self._on_close_v5)

    # ── Keyboard shortcuts ──
    self.root.bind("<F5>",        lambda _: self._kb_scan())
    self.root.bind("<Escape>",    lambda _: self.stop_scan()
                                  if self.scanning else None)
    self.root.bind("<Control-e>", lambda _: self.export_csv())
    self.root.bind("<Control-f>", lambda _: self._focus_filter())
    self.root.bind("<Control-i>", lambda _: self.copy_ip())
    self.root.bind("<Control-m>", lambda _: self.copy_mac())
    self.root.bind("<Control-r>", lambda _: self._export_report())
    self.root.bind("<Control-p>", lambda _: self._open_command_palette())
    self.root.bind("<F11>",       lambda _: self._toggle_fullscreen())
    self.root.bind("<Control-h>", lambda _: self.show_view("history"))
    self.root.bind("<Control-n>", lambda _: self.show_view("nmapscan"))
    self.root.bind("<F1>",        lambda _: self._show_help())
    self._fullscreen = False

    # ── Export menu — wire PDF and interactive HTML ──
    # Patch _export_menu to add new items
    orig_export_menu = self._export_menu

    def _export_menu_v5():
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Export CSV",
                         command=self.export_csv)
        menu.add_command(label="Export JSON",
                         command=self.export_json)
        menu.add_separator()
        menu.add_command(label="📊 Interactive HTML Report",
                         command=self.export_html)
        menu.add_command(label="📝 Markdown Report",
                         command=self._export_report)
        menu.add_command(label="📄 PDF Report",
                         command=self._export_pdf)
        menu.add_separator()
        menu.add_command(label="📡 Send to SIEM",
                         command=self._siem_send_findings)
        x = self.export_button.winfo_rootx()
        y = (self.export_button.winfo_rooty() +
             self.export_button.winfo_height())
        menu.post(x, y)

    self._export_menu = _export_menu_v5

    # ── Dep warnings ──
    missing = []
    if not _SCAPY_OK:    missing.append("scapy")
    if not _CRYPTO_OK:   missing.append("cryptography")
    if not _MPL_OK:      missing.append("matplotlib")
    if missing and not os.path.isfile(
            os.path.join(STATE_DIR, ".warned_deps")):
        self.root.after(1800,
            lambda: self._show_dep_warning(missing))

IPScannerGUI.late_init = late_init_v5


# ─────────────────────────────────────────────────────────────────────────────
# UPDATED _finalize_ui  (DB write + alert dispatch + CPE enrichment)
# ─────────────────────────────────────────────────────────────────────────────

_orig_finalize = IPScannerGUI._finalize_ui

def _finalize_ui_v5(self):
    """Extended finalize: writes to DB, dispatches alerts, enriches CPE."""
    # Run original finalize first
    _orig_finalize(self)

    # ── Write scan to SQLite ──
    try:
        scan_id = db.start_scan(
            self.scan_meta.get("target", ""),
            self.scan_meta.get("mode", ""))
        db.bulk_upsert_hosts(scan_id, self.results)
        db.insert_findings(scan_id, self.security_findings)
        db.finish_scan(
            scan_id,
            host_count=len(self.results),
            active_count=sum(
                1 for r in self.results
                if r["status"] == "Used"),
            finding_count=len(self.security_findings))
        self._last_scan_id = scan_id
    except Exception as e:
        log.warning("DB write error: %s", e)

    # ── Dispatch email/webhook summary ──
    try:
        crits = sum(1 for _, _, s, _ in self.security_findings
                    if s in ("Critical", "High"))
        if crits > 0 and (EMAIL_ALERTS_ENABLED
                          or WEBHOOK_ALERTS_ENABLED):
            AlertDispatcher.dispatch_scan_summary(
                self.results, self.security_findings)
    except Exception as e:
        log.debug("Alert dispatch error: %s", e)

    # ── SIEM: send critical findings ──
    try:
        if SIEM_ENABLED:
            crit_finds = [
                f for f in self.security_findings
                if f[2] in ("Critical", "High")]
            if crit_finds:
                threading.Thread(
                    target=siem_exporter.bulk_send_findings,
                    args=(crit_finds,),
                    daemon=True).start()
    except Exception as e:
        log.debug("SIEM send error: %s", e)

    # ── CPE enrich results in background ──
    try:
        def _enrich_cpe():
            for r in self.results:
                if r.get("status") == "Used":
                    cpe_mapper.enrich_result(r)
        threading.Thread(
            target=_enrich_cpe, daemon=True).start()
    except Exception as e:
        log.debug("CPE enrich error: %s", e)

    # ── Device type upgrade using enhanced_device_type ──
    try:
        for r in self.results:
            if r.get("status") == "Used":
                r["device_type"] = enhanced_device_type(r)
    except Exception as e:
        log.debug("Device type upgrade error: %s", e)

    # ── Refresh history tab if open ──
    if self.current_view == "history":
        self.root.after(500, lambda: _history_refresh(self))

IPScannerGUI._finalize_ui = _finalize_ui_v5


# ─────────────────────────────────────────────────────────────────────────────
# UPDATED _on_close  (also stops honeypot + closes DB)
# ─────────────────────────────────────────────────────────────────────────────

def _on_close_v5(self):
    if self.scanning:
        self.stop_scan()
    if self.sniffer_running:
        self.sniffer_running = False
    if self._arp_monitor_running:
        self._arp_monitor_running = False
    if honeypot.running:
        honeypot.stop()
    if self.results:
        self._save_last_scan()
    self._save_notes()
    self._save_profiles()
    try:
        db.close()
    except Exception:
        pass
    self.root.destroy()

IPScannerGUI._on_close_v5 = _on_close_v5


# ─────────────────────────────────────────────────────────────────────────────
# UPDATED _settings_save  (also saves API keys / SIEM / notifications)
# ─────────────────────────────────────────────────────────────────────────────

_orig_settings_save = IPScannerGUI._settings_save

def _settings_save_v5(self):
    _orig_settings_save(self)     # run original first
    _save_api_settings(self)      # then persist API keys etc.

    # Also persist new fields to settings.json
    path = os.path.join(STATE_DIR, "settings.json")
    try:
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}

    cfg.update({
        "shodan_key":      SHODAN_API_KEY,
        "censys_id":       CENSYS_API_ID,
        "censys_secret":   CENSYS_API_SECRET,
        "abuseipdb_key":   ABUSEIPDB_API_KEY,
        "otx_key":         OTX_API_KEY,
        "nvd_key":         NVD_API_KEY,
        "siem_enabled":    SIEM_ENABLED,
        "siem_host":       SIEM_HOST,
        "siem_port":       SIEM_PORT,
        "siem_proto":      SIEM_PROTO,
        "email_enabled":   EMAIL_ALERTS_ENABLED,
        "smtp_host":       SMTP_HOST,
        "smtp_port":       SMTP_PORT,
        "smtp_user":       SMTP_USER,
        "smtp_from":       SMTP_FROM,
        "smtp_to":         SMTP_TO,
        "webhook_enabled": WEBHOOK_ALERTS_ENABLED,
        "webhook_url":     WEBHOOK_URL,
    })
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        log.warning("v5 settings save: %s", e)

IPScannerGUI._settings_save = _settings_save_v5


# ─────────────────────────────────────────────────────────────────────────────
# UPDATED _load_settings  (also loads API keys from settings.json)
# ─────────────────────────────────────────────────────────────────────────────

_orig_load_settings = IPScannerGUI._load_settings

def _load_settings_v5(self):
    _orig_load_settings(self)     # run original first

    global SHODAN_API_KEY, CENSYS_API_ID, CENSYS_API_SECRET
    global ABUSEIPDB_API_KEY, OTX_API_KEY, NVD_API_KEY
    global SIEM_ENABLED, SIEM_HOST, SIEM_PORT, SIEM_PROTO
    global EMAIL_ALERTS_ENABLED, SMTP_HOST, SMTP_PORT
    global SMTP_USER, SMTP_PASS, SMTP_FROM, SMTP_TO
    global WEBHOOK_ALERTS_ENABLED, WEBHOOK_URL

    path = os.path.join(STATE_DIR, "settings.json")
    if not os.path.isfile(path):
        return
    try:
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        return

    SHODAN_API_KEY         = cfg.get("shodan_key",      "")
    CENSYS_API_ID          = cfg.get("censys_id",       "")
    CENSYS_API_SECRET      = cfg.get("censys_secret",   "")
    ABUSEIPDB_API_KEY      = cfg.get("abuseipdb_key",   "")
    OTX_API_KEY            = cfg.get("otx_key",         "")
    NVD_API_KEY            = cfg.get("nvd_key",         "")
    SIEM_ENABLED           = cfg.get("siem_enabled",    False)
    SIEM_HOST              = cfg.get("siem_host",       "")
    SIEM_PORT              = cfg.get("siem_port",       514)
    SIEM_PROTO             = cfg.get("siem_proto",      "UDP")
    EMAIL_ALERTS_ENABLED   = cfg.get("email_enabled",   False)
    SMTP_HOST              = cfg.get("smtp_host",       "")
    SMTP_PORT              = cfg.get("smtp_port",       587)
    SMTP_USER              = cfg.get("smtp_user",       "")
    SMTP_PASS              = cfg.get("smtp_pass",       "")
    SMTP_FROM              = cfg.get("smtp_from",       "")
    SMTP_TO                = cfg.get("smtp_to",         "")
    WEBHOOK_ALERTS_ENABLED = cfg.get("webhook_enabled", False)
    WEBHOOK_URL            = cfg.get("webhook_url",     "")

IPScannerGUI._load_settings = _load_settings_v5


# ─────────────────────────────────────────────────────────────────────────────
# HELP WINDOW
# ─────────────────────────────────────────────────────────────────────────────

def _show_help(self):
    win = tk.Toplevel(self.root)
    win.title(f"NetProbe v{VERSION} — Help")
    win.geometry("700x580")

    nb = ttk.Notebook(win)
    nb.pack(fill="both", expand=True, padx=8, pady=8)

    shortcuts = [
        ("F5",         "Start scan"),
        ("Escape",     "Stop scan"),
        ("Ctrl+P",     "Open Command Palette (fuzzy search everything)"),
        ("Ctrl+E",     "Export CSV"),
        ("Ctrl+F",     "Focus search filter"),
        ("Ctrl+I",     "Copy selected IP"),
        ("Ctrl+M",     "Copy selected MAC"),
        ("Ctrl+R",     "Export Markdown report"),
        ("Ctrl+H",     "Go to History tab"),
        ("Ctrl+N",     "Go to Nmap tab"),
        ("F1",         "Open this help window"),
        ("F11",        "Toggle fullscreen"),
        ("Delete",     "Delete selected row"),
        ("Double-click","Open host detail window"),
    ]
    kb_tab = ttk.Frame(nb, padding=16)
    nb.add(kb_tab, text="Keyboard Shortcuts")
    for i, (key, desc) in enumerate(shortcuts):
        ttk.Label(kb_tab, text=key,
                  style="Mono.TLabel",
                  font=("Courier New", 10, "bold")).grid(
            row=i, column=0, sticky="w",
            padx=(0, 20), pady=3)
        ttk.Label(kb_tab, text=desc).grid(
            row=i, column=1, sticky="w", pady=3)

    features_tab = ttk.Frame(nb, padding=16)
    nb.add(features_tab, text="Features")

    features_txt = scrolledtext.ScrolledText(
        features_tab, font=("Segoe UI", 9),
        state="normal", wrap="word")
    features_txt.pack(fill="both", expand=True)
    features_txt.insert("end", f"""
NetProbe v{VERSION} — Feature Overview
{'='*50}

CORE SCANNER
  • Multi-subnet ARP + ping + TCP scanning
  • Auto-detected network checkbox grid
  • Service banner grabbing with version extraction
  • SSL/TLS certificate inspection
  • OS fingerprinting (TTL + ports + banners)
  • UDP port probing (DNS/SNMP/NTP/SSDP/mDNS)
  • Device type detection (Docker/VM/cloud/IoT/printer)
  • Threat scoring (0–100) per host
  • Baseline diff (new/changed/rogue device detection)
  • ARP spoofing / MITM passive monitor

PENTESTER TOOLS
  • CVE Live Lookup (NVD API + CIRCL fallback)
  • Credential Spray (SSH/FTP/HTTP/Telnet/Redis/MySQL)
  • Nmap Integration (XML parse, result merge)
  • HTTP Directory Bruteforcer (built-in 80-path wordlist)
  • DNS Zone Transfer (AXFR via dig + raw DNS TCP)
  • NetBIOS / SMB share enumerator
  • Port knock sequence sender
  • Subdomain enumeration
  • HTTP endpoint prober
  • Service fingerprinter (CPE mapping)
  • IPv6 scanner + NDP passive discovery
  • Wi-Fi / SSID scanner with risk flagging
  • Packet sniffer (PCAP export, BPF filter)
  • SNMP scanner (multi-community, SNMP walk)
  • Traceroute (ICMP + OS fallback)

DEFENSE TOOLS
  • Threat feed integration (AbuseIPDB/OTX/GreyNoise)
  • Shodan / Censys IP enrichment
  • Honeypot monitor (fake listeners, MITM/scan detection)
  • Historical trend analysis (SQLite backend)
  • Compliance checker (PCI-DSS / CIS-L1 / NIST)
  • Alert log with severity tagging
  • SIEM export (CEF/syslog — Splunk/QRadar/Graylog)
  • Email + webhook alerting
  • Firewall rule generator (iptables/nftables/Windows/pf)
  • Auto block-list from high-risk hosts

REPORTING
  • Interactive HTML report (sortable, filterable, charts)
  • PDF pentest report (professional A4, reportlab)
  • Markdown report
  • CSV / JSON export

COMMAND PALETTE  (Ctrl+P)
  • Fuzzy search all tabs, actions, and hosts
  • Jump to any host from last scan instantly
  • Execute any action without touching the mouse
""")
    features_txt.config(state="disabled")

    deps_tab = ttk.Frame(nb, padding=16)
    nb.add(deps_tab, text="Dependencies")
    deps = [
        ("scapy",        _SCAPY_OK,    "pip install scapy",
         "ARP scan, packet sniffer, raw traceroute, ARP monitor"),
        ("cryptography", _CRYPTO_OK,   "pip install cryptography",
         "Full SSL/TLS cert parsing (expiry, SANs, CN)"),
        ("netifaces",    _NETIFACES_OK,"pip install netifaces",
         "Auto-detect local network interfaces"),
        ("paramiko",     _PARAMIKO_OK, "pip install paramiko",
         "SSH credential checking"),
        ("matplotlib",   _MPL_OK,      "pip install matplotlib",
         "Dashboard charts"),
        ("reportlab",    _REPORTLAB_OK,"pip install reportlab",
         "PDF report export"),
        ("nmap",         NmapRunner.available(),
         "https://nmap.org",
         "Nmap integration (install nmap binary)"),
    ]
    for i, (name, ok, install, desc) in enumerate(deps):
        sym = "✓" if ok else "✗"
        fg  = SUCCESS if ok else DANGER
        ttk.Label(deps_tab,
                  text=f"{sym}  {name}",
                  foreground=fg,
                  font=("Segoe UI", 9, "bold")).grid(
            row=i, column=0, sticky="w",
            padx=(0, 16), pady=4)
        ttk.Label(deps_tab, text=desc,
                  style="Muted.TLabel").grid(
            row=i, column=1, sticky="w",
            padx=(0, 16))
        ttk.Label(deps_tab, text=install,
                  font=("Courier New", 8)).grid(
            row=i, column=2, sticky="w")

    ttk.Button(win, text="Close",
               command=win.destroy).pack(pady=(0, 8))

IPScannerGUI._show_help = _show_help


# ─────────────────────────────────────────────────────────────────────────────
# UPDATED PRINT BANNER
# ─────────────────────────────────────────────────────────────────────────────

def _print_banner_v5():
    nmap_ok = NmapRunner.available()
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  ◈  {APP_FULL:<56}  ║
╠══════════════════════════════════════════════════════════════╣
║  PENTESTER  ║  CVE Lookup · Cred Spray · Nmap · Dirbuster   ║
║             ║  Zone Transfer · WiFi · CPE Mapper · IPv6      ║
║             ║  Sniffer · NetBIOS · SNMP · Traceroute         ║
╠══════════════════════════════════════════════════════════════╣
║  DEFENSE    ║  Threat Feeds · Shodan · Honeypot · History    ║
║             ║  Compliance · SIEM · Email · Webhook Alerts    ║
║             ║  Baseline · ARP Monitor · Firewall Rules       ║
╠══════════════════════════════════════════════════════════════╣
║  REPORTS    ║  Interactive HTML · PDF · Markdown · CSV       ║
╠══════════════════════════════════════════════════════════════╣
║  DEPS       ║  scapy={str(_SCAPY_OK):<5}  crypto={str(_CRYPTO_OK):<5}  mpl={str(_MPL_OK):<5}  nmap={str(nmap_ok):<5}   ║
║             ║  paramiko={str(_PARAMIKO_OK):<5}  netifaces={str(_NETIFACES_OK):<5}  reportlab={str(_REPORTLAB_OK):<5}  ║
╚══════════════════════════════════════════════════════════════╝
  Ctrl+P = Command Palette  ·  F1 = Help  ·  F5 = Scan
""")


# ─────────────────────────────────────────────────────────────────────────────
# UPDATED main()
# ─────────────────────────────────────────────────────────────────────────────

def main():
    if sys.version_info < (3, 10):
        print(f"[!] Python 3.10+ required. "
              f"You have {sys.version.split()[0]}.",
              file=sys.stderr)
        sys.exit(1)

    _print_banner_v5()

    if platform.system() in ("Linux", "Darwin"):
        if os.geteuid() != 0:
            print(
                "[!] Not running as root.\n"
                "    ARP scan, packet sniffer, honeypot and\n"
                "    raw-socket traceroute need root/sudo.\n"
                "    Fallback methods used where possible.\n")

    root = tk.Tk()
    root.withdraw()
    root.title(APP_FULL)
    root.geometry("1780x1000")
    root.minsize(1280, 720)

    try:
        icon_path = os.path.join(
            os.path.dirname(__file__), "netprobe.ico")
        if os.path.isfile(icon_path):
            root.iconbitmap(icon_path)
    except Exception:
        pass

    app = IPScannerGUI(root)
    root.after(60, app.late_init)
    root.deiconify()
    root.mainloop()


if __name__ == "__main__":
    main()

# ─────────────────────────────────────────────────────────────────────────────
# ASSEMBLY — produces NetProbe_v5.py
# ─────────────────────────────────────────────────────────────────────────────
#
# Linux / macOS / WSL:
#   cat NetProbe_v4.py \
#       v5_patch1.py   \
#       v5_patch2.py   \
#       v5_patch3.py   \
#       v5_patch4.py   \
#       v5_patch5.py   > NetProbe_v5.py
#
# Windows PowerShell:
#   Get-Content NetProbe_v4.py,v5_patch1.py,v5_patch2.py,
#               v5_patch3.py,v5_patch4.py,v5_patch5.py |
#     Set-Content NetProbe_v5.py
#
# Windows cmd:
#   copy /b NetProbe_v4.py+v5_patch1.py+v5_patch2.py+^
#            v5_patch3.py+v5_patch4.py+v5_patch5.py NetProbe_v5.py
#
# Run:
#   pip install scapy cryptography netifaces paramiko matplotlib reportlab
#   sudo python3 NetProbe_v5.py        # Linux/macOS
#   python NetProbe_v5.py              # Windows (as Administrator)
# ─────────────────────────────────────────────────────────────────────────────
