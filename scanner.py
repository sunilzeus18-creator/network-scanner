"""Network Scanner Module - Core Scanning Functionality"""

import json
import logging
import nmap
import re
import socket
import subprocess
import tempfile
from ipaddress import ip_network, IPv4Network
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from pathlib import Path

from config import (
    NMAP_PROFILES,
    VULNERABLE_SERVICES,
    PORT_CATEGORIES,
    ERROR_MESSAGES,
    TIMEOUT_SECONDS,
)

# ============================================================================
# SETUP LOGGING
# ============================================================================

logger = logging.getLogger(__name__)


class IPValidator:
    """Validates IP addresses and CIDR ranges"""

    @staticmethod
    def is_valid_ipv4(ip: str) -> bool:
        """Validate single IPv4 address"""
        pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        return bool(re.match(pattern, ip))

    @staticmethod
    def is_valid_cidr(cidr: str) -> bool:
        """Validate CIDR notation"""
        try:
            ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_target(target: str) -> Tuple[bool, str]:
        """Validate target IP or CIDR range"""
        target = target.strip()

        # Check if it's a CIDR range
        if "/" in target:
            if not IPValidator.is_valid_cidr(target):
                return False, ERROR_MESSAGES["invalid_cidr"]
            return True, "CIDR range valid"

        # Check if it's a single IP
        if IPValidator.is_valid_ipv4(target):
            return True, "Single IP valid"

        # Try to resolve hostname
        try:
            socket.gethostbyname(target)
            return True, "Hostname resolved"
        except socket.gaierror:
            return False, ERROR_MESSAGES["invalid_ip"]


class NmapScanner:
    """Nmap-based network scanner"""

    def __init__(self, target: str, profile: str = "standard", verbose: bool = False):
        """
        Initialize scanner

        Args:
            target: IP address or CIDR range
            profile: Scan profile (quick, standard, intensive)
            verbose: Enable verbose logging
        """
        self.target = target
        self.profile = profile.lower()
        self.verbose = verbose
        self.nm = None
        self.results = {}
        self.start_time = None
        self.end_time = None

        if self.verbose:
            logger.setLevel(logging.DEBUG)

    def check_nmap_installed(self) -> bool:
        """Check if Nmap is installed"""
        try:
            subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                timeout=5,
            )
            return True
        except FileNotFoundError:
            logger.error(ERROR_MESSAGES["nmap_not_found"])
            return False

    def scan(self) -> bool:
        """
        Execute Nmap scan

        Returns:
            bool: True if scan successful, False otherwise
        """
        try:
            # Validate target
            is_valid, message = IPValidator.validate_target(self.target)
            if not is_valid:
                logger.error(message)
                return False

            logger.info(f"[+] {message}")

            # Check Nmap installation
            if not self.check_nmap_installed():
                return False

            # Get Nmap arguments
            nmap_args = NMAP_PROFILES.get(self.profile, NMAP_PROFILES["standard"])

            logger.info(f"[*] Starting {self.profile} scan on {self.target}")
            logger.debug(f"Nmap arguments: {nmap_args}")

            # Execute scan
            self.start_time = datetime.now()
            self.nm = nmap.PortScanner()

            # Run scan without XML output flag (python-nmap handles it internally)
            self.nm.scan(
                hosts=self.target,
                arguments=nmap_args,
                timeout=TIMEOUT_SECONDS,
            )

            self.end_time = datetime.now()
            scan_duration = (self.end_time - self.start_time).total_seconds()

            logger.info(f"[+] Scan completed in {scan_duration:.2f} seconds")
            logger.info(f"[+] Found {len(self.nm.all_hosts())} hosts")

            self._parse_results()
            return True

        except nmap.PortScannerError as e:
            logger.error(f"Nmap error: {str(e)}")
            return False
        except subprocess.TimeoutExpired:
            logger.error(ERROR_MESSAGES["timeout"])
            return False
        except Exception as e:
            logger.error(f"Unexpected error during scan: {str(e)}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return False

    def _parse_results(self) -> None:
        """Parse Nmap results into structured format"""
        try:
            hosts_data = []

            for host in self.nm.all_hosts():
                host_info = self._extract_host_info(host)
                hosts_data.append(host_info)
                logger.debug(f"Parsed host: {host} with {len(host_info['ports'])} open ports")

            self.results = {
                "scan_info": {
                    "start_time": self.start_time.isoformat(),
                    "end_time": self.end_time.isoformat(),
                    "duration": (self.end_time - self.start_time).total_seconds(),
                    "target": self.target,
                    "profile": self.profile,
                },
                "hosts": hosts_data,
                "summary": {
                    "total_hosts": len(hosts_data),
                    "total_open_ports": sum(len(h["ports"]) for h in hosts_data),
                },
            }

        except Exception as e:
            logger.error(f"Error parsing results: {str(e)}")

    def _extract_host_info(self, host: str) -> Dict:
        """Extract information for a single host"""
        host_info = {
            "ip": host,
            "hostname": self._resolve_hostname(host),
            "status": self.nm[host].state(),
            "ports": [],
            "os_info": self._extract_os_info(host),
        }

        # Extract port information
        for proto in self.nm[host].all_protocols():
            ports = self.nm[host][proto].keys()
            for port in ports:
                port_state = self.nm[host][proto][port]["state"]

                # Only include open ports
                if port_state == "open":
                    port_info = {
                        "port": port,
                        "protocol": proto,
                        "state": port_state,
                        "service": self.nm[host][proto][port].get("name", "Unknown"),
                        "product": self.nm[host][proto][port].get("product", ""),
                        "version": self.nm[host][proto][port].get("version", ""),
                        "extrainfo": self.nm[host][proto][port].get("extrainfo", ""),
                    }

                    # Assess vulnerability
                    port_info["vulnerability"] = self._assess_vulnerability(
                        port, port_info["service"]
                    )

                    host_info["ports"].append(port_info)

        return host_info

    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Attempt to resolve hostname from IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.error):
            return None

    def _extract_os_info(self, host: str) -> Dict:
        """Extract OS information if available"""
        os_info = {"detected": False, "details": []}

        try:
            if "osmatch" in self.nm[host]:
                for osmatch in self.nm[host]["osmatch"]:
                    os_info["detected"] = True
                    os_info["details"].append(
                        {"name": osmatch["name"], "accuracy": osmatch["accuracy"]}
                    )
        except Exception as e:
            logger.debug(f"Could not extract OS info: {str(e)}")

        return os_info

    def _assess_vulnerability(self, port: int, service: str) -> Dict:
        """Assess vulnerability of a service"""
        service_lower = service.lower()
        risk_level = "info"
        reason = "Service running"
        recommendation = "Ensure service is up-to-date"

        # Check against known vulnerable services
        for vuln_service, vuln_info in VULNERABLE_SERVICES.items():
            if vuln_service in service_lower or vuln_info["port"] == port:
                risk_level = vuln_info["risk"]
                reason = vuln_info["reason"]
                recommendation = vuln_info["recommendation"]
                break

        return {
            "risk_level": risk_level,
            "reason": reason,
            "recommendation": recommendation,
        }

    def get_results(self) -> Dict:
        """Get scan results"""
        return self.results

    def export_json(self, filepath: str) -> bool:
        """Export results to JSON file"""
        try:
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)

            with open(filepath, "w") as f:
                json.dump(self.results, f, indent=2)

            logger.info(f"[+] Results exported to {filepath}")
            return True

        except Exception as e:
            logger.error(f"Error exporting JSON: {str(e)}")
            return False
