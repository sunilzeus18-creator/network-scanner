"""Configuration and Constants for Network Scanner"""

import os
from enum import Enum
from typing import Dict

# ============================================================================
# SCAN PROFILES
# ============================================================================

class ScanProfile(Enum):
    """Nmap scan profile definitions"""
    QUICK = "quick"
    STANDARD = "standard"
    INTENSIVE = "intensive"

# Nmap arguments for each profile
NMAP_PROFILES: Dict[str, str] = {
    "quick": "-F -sS",
    "standard": "-sS -sV --script vuln",
    "intensive": "-sS -sV -sC -O --script vuln,default",
}

# ============================================================================
# VULNERABILITY RISK LEVELS
# ============================================================================

class RiskLevel(Enum):
    """Risk severity classification"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

RISK_COLORS: Dict[str, str] = {
    "critical": "#d32f2f",  # Red
    "high": "#f57c00",      # Orange
    "medium": "#fbc02d",    # Yellow
    "low": "#7cb342",       # Light Green
    "info": "#1976d2",      # Blue
}

# ============================================================================
# VULNERABLE SERVICES
# ============================================================================

VULNERABLE_SERVICES: Dict[str, Dict] = {
    "telnet": {
        "port": 23,
        "risk": "critical",
        "reason": "Unencrypted credentials transmission",
        "recommendation": "Use SSH instead"
    },
    "ftp": {
        "port": 21,
        "risk": "high",
        "reason": "Unencrypted data transfer",
        "recommendation": "Use SFTP or SCP"
    },
    "http": {
        "port": 80,
        "risk": "medium",
        "reason": "Unencrypted web traffic",
        "recommendation": "Use HTTPS (port 443)"
    },
    "smtp": {
        "port": 25,
        "risk": "medium",
        "reason": "Can be used for spam/relay attacks",
        "recommendation": "Restrict SMTP access, use authentication"
    },
    "snmp": {
        "port": 161,
        "risk": "high",
        "reason": "Default credentials commonly used",
        "recommendation": "Disable if not needed or use SNMPv3"
    },
    "ssh": {
        "port": 22,
        "risk": "low",
        "reason": "Often targeted by brute force attacks",
        "recommendation": "Use strong authentication, disable password auth"
    },
    "dns": {
        "port": 53,
        "risk": "medium",
        "reason": "Can be exploited for DNS amplification attacks",
        "recommendation": "Restrict DNS access, implement rate limiting"
    },
    "mysql": {
        "port": 3306,
        "risk": "high",
        "reason": "Database exposed to network",
        "recommendation": "Firewall database port, use network segmentation"
    },
    "rdp": {
        "port": 3389,
        "risk": "high",
        "reason": "Vulnerable to brute force attacks",
        "recommendation": "Disable if not needed, use VPN"
    },
    "smb": {
        "port": 445,
        "risk": "critical",
        "reason": "Target for ransomware and lateral movement",
        "recommendation": "Disable externally, patch systems"
    },
}

# ============================================================================
# PORT CATEGORIES
# ============================================================================

PORT_CATEGORIES: Dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP Alt",
    8443: "HTTPS Alt",
    27017: "MongoDB",
    6379: "Redis",
}

# ============================================================================
# OUTPUT CONFIGURATION
# ============================================================================

DEFAULT_OUTPUT_DIR = "./reports"
REPORT_DATE_FORMAT = "%Y-%m-%d_%H%M%S"

# HTML Report styling
HTML_TEMPLATE_NAME = "scan_report.html"
CSS_COLORS = {
    "primary": "#1976d2",
    "secondary": "#424242",
    "success": "#4caf50",
    "danger": "#f44336",
    "warning": "#ff9800",
    "info": "#2196f3",
    "light": "#f5f5f5",
    "dark": "#212121",
}

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

LOG_FORMAT = "[%(levelname)s] %(asctime)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# ============================================================================
# VALIDATION RULES
# ============================================================================

MAX_TARGETS = 256  # Maximum number of hosts in CIDR range
TIMEOUT_SECONDS = 300  # Scan timeout in seconds
RETRIES = 3  # Number of retries for failed scans

# ============================================================================
# ERROR MESSAGES
# ============================================================================

ERROR_MESSAGES = {
    "invalid_ip": "Invalid IP address format. Please use valid IPv4 format (e.g., 192.168.1.1)",
    "invalid_cidr": "Invalid CIDR range. Please use format like 192.168.1.0/24",
    "nmap_not_found": "Nmap is not installed or not in PATH. Please install Nmap first.",
    "permission_denied": "Permission denied. Some scans require elevated privileges. Try with sudo.",
    "network_error": "Network error during scan. Please check your target and try again.",
    "timeout": "Scan timed out. Target may be unreachable or network is slow.",
}

# ============================================================================
# SUCCESS MESSAGES
# ============================================================================

SUCCESS_MESSAGES = {
    "validation_ok": "✓ Target validation successful",
    "scan_started": "[*] Scan initiated",
    "scan_complete": "✓ Scan completed successfully",
    "report_generated": "✓ HTML report generated",
}
