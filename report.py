"""HTML Report Generation Module"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from jinja2 import Template

from config import RISK_COLORS, CSS_COLORS, REPORT_DATE_FORMAT

# ============================================================================
# SETUP LOGGING
# ============================================================================

logger = logging.getLogger(__name__)

# ============================================================================
# HTML TEMPLATE
# ============================================================================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Scan Report - {{ target }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, {{ colors.primary }}, {{ colors.secondary }});
            color: white;
            padding: 40px;
            text-align: center;
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }

        .content {
            padding: 40px;
        }

        .section {
            margin-bottom: 40px;
        }

        .section-title {
            font-size: 1.8em;
            color: {{ colors.primary }};
            border-bottom: 3px solid {{ colors.primary }};
            padding-bottom: 10px;
            margin-bottom: 20px;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .summary-card {
            background: {{ colors.light }};
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid {{ colors.primary }};
        }

        .summary-card h3 {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }

        .summary-card .value {
            font-size: 2em;
            font-weight: bold;
            color: {{ colors.primary }};
        }

        .host-section {
            background: {{ colors.light }};
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid {{ colors.info }};
        }

        .host-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #ddd;
        }

        .host-ip {
            font-size: 1.3em;
            font-weight: bold;
            color: {{ colors.primary }};
        }

        .host-status {
            display: inline-block;
            padding: 5px 15px;
            background: {{ colors.success }};
            color: white;
            border-radius: 20px;
            font-size: 0.9em;
        }

        .ports-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }

        .ports-table th {
            background: {{ colors.secondary }};
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }

        .ports-table td {
            padding: 12px;
            border-bottom: 1px solid #ddd;
        }

        .ports-table tr:hover {
            background: #f9f9f9;
        }

        .port-number {
            font-weight: bold;
            color: {{ colors.primary }};
        }

        .risk-badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 5px;
            font-weight: bold;
            font-size: 0.85em;
            color: white;
        }

        .risk-critical { background: #d32f2f; }
        .risk-high { background: #f57c00; }
        .risk-medium { background: #fbc02d; color: #333; }
        .risk-low { background: #7cb342; }
        .risk-info { background: #1976d2; }

        .recommendation {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin-top: 10px;
            border-radius: 5px;
            font-size: 0.95em;
        }

        .recommendation strong {
            color: #856404;
        }

        .vulnerability-details {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            margin-top: 5px;
            font-size: 0.9em;
            color: #555;
        }

        .footer {
            background: {{ colors.secondary }};
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 0.9em;
        }

        .timestamp {
            margin-top: 10px;
            opacity: 0.8;
        }

        @media (max-width: 768px) {
            .header h1 {
                font-size: 1.8em;
            }

            .content {
                padding: 20px;
            }

            .ports-table {
                font-size: 0.9em;
            }

            .ports-table th, .ports-table td {
                padding: 8px;
            }
        }

        @media print {
            body {
                background: white;
                padding: 0;
            }

            .container {
                box-shadow: none;
                max-width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Network Scan Report</h1>
            <p>{{ target }} | {{ scan_time }}</p>
        </div>

        <div class="content">
            <!-- Executive Summary -->
            <div class="section">
                <h2 class="section-title">Executive Summary</h2>
                <div class="summary-grid">
                    <div class="summary-card">
                        <h3>Total Hosts</h3>
                        <div class="value">{{ total_hosts }}</div>
                    </div>
                    <div class="summary-card">
                        <h3>Open Ports</h3>
                        <div class="value">{{ total_open_ports }}</div>
                    </div>
                    <div class="summary-card">
                        <h3>Scan Duration</h3>
                        <div class="value">{{ duration }}s</div>
                    </div>
                    <div class="summary-card">
                        <h3>Scan Profile</h3>
                        <div class="value" style="font-size: 1.5em; text-transform: capitalize;">{{ profile }}</div>
                    </div>
                </div>
            </div>

            <!-- Scan Details -->
            <div class="section">
                <h2 class="section-title">Scan Details</h2>
                <div style="background: {{ colors.light }}; padding: 20px; border-radius: 8px;">
                    <p><strong>Target:</strong> {{ target }}</p>
                    <p><strong>Start Time:</strong> {{ start_time }}</p>
                    <p><strong>End Time:</strong> {{ end_time }}</p>
                    <p><strong>Scan Profile:</strong> <span style="text-transform: capitalize;">{{ profile }}</span></p>
                    <p><strong>Report Generated:</strong> {{ generated_time }}</p>
                </div>
            </div>

            <!-- Host Details -->
            <div class="section">
                <h2 class="section-title">Host Analysis</h2>
                {% for host in hosts %}
                <div class="host-section">
                    <div class="host-header">
                        <div>
                            <div class="host-ip">{{ host.ip }}</div>
                            {% if host.hostname %}
                            <div style="color: #666; font-size: 0.9em;">{{ host.hostname }}</div>
                            {% endif %}
                        </div>
                        <div class="host-status">● {{ host.status|upper }}</div>
                    </div>

                    {% if host.ports %}
                    <div>
                        <strong style="color: {{ colors.primary }};">{{ host.ports|length }} Open Port(s) Detected</strong>
                        <table class="ports-table">
                            <thead>
                                <tr>
                                    <th>Port</th>
                                    <th>Service</th>
                                    <th>Version</th>
                                    <th>Risk</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for port in host.ports %}
                                <tr>
                                    <td><span class="port-number">{{ port.port }}/{{ port.protocol }}</span></td>
                                    <td>{{ port.service }}</td>
                                    <td>{% if port.version %}{{ port.product }} {{ port.version }}{% else %}Unknown{% endif %}</td>
                                    <td>
                                        <span class="risk-badge risk-{{ port.vulnerability.risk_level }}">
                                            {{ port.vulnerability.risk_level|upper }}
                                        </span>
                                    </td>
                                </tr>
                                <tr>
                                    <td colspan="4">
                                        <div class="vulnerability-details">
                                            <strong>Issue:</strong> {{ port.vulnerability.reason }}
                                        </div>
                                        <div class="recommendation">
                                            <strong>✓ Recommendation:</strong> {{ port.vulnerability.recommendation }}
                                        </div>
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    {% else %}
                    <div style="color: #666; padding: 15px; text-align: center; background: white; border-radius: 5px;">
                        ✓ No open ports detected on this host
                    </div>
                    {% endif %}
                </div>
                {% endfor %}
            </div>

            <!-- Security Recommendations -->
            <div class="section">
                <h2 class="section-title">Security Recommendations</h2>
                <div style="background: #e8f5e9; border-left: 4px solid {{ colors.success }}; padding: 20px; border-radius: 8px;">
                    <ul style="list-style: none; padding: 0;">
                        <li style="padding: 10px 0; border-bottom: 1px solid #c8e6c9;">
                            <strong>🔐 Access Control:</strong> Implement firewalls and network segmentation to restrict access to sensitive ports
                        </li>
                        <li style="padding: 10px 0; border-bottom: 1px solid #c8e6c9;">
                            <strong>🔄 Keep Systems Updated:</strong> Regularly patch and update all software and services
                        </li>
                        <li style="padding: 10px 0; border-bottom: 1px solid #c8e6c9;">
                            <strong>🔑 Strong Authentication:</strong> Use strong, unique passwords and multi-factor authentication
                        </li>
                        <li style="padding: 10px 0; border-bottom: 1px solid #c8e6c9;">
                            <strong>📊 Monitor Services:</strong> Implement logging and monitoring for all network services
                        </li>
                        <li style="padding: 10px 0;">
                            <strong>🚨 Incident Response:</strong> Develop and test incident response procedures
                        </li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="footer">
            <p>🛡️ Network Scanner - Automated Vulnerability Assessment Tool</p>
            <div class="timestamp">Report generated on {{ generated_time }}</div>
            <div class="timestamp"><em>Use this report responsibly. Scan only networks you own or have explicit permission to scan.</em></div>
        </div>
    </div>
</body>
</html>
"""


class HTMLReportGenerator:
    """Generate professional HTML reports from scan results"""

    def __init__(self, results: Dict):
        """
        Initialize report generator

        Args:
            results: Scan results dictionary from NmapScanner
        """
        self.results = results
        self.template = Template(HTML_TEMPLATE)

    def generate(self, output_filepath: str) -> bool:
        """
        Generate HTML report

        Args:
            output_filepath: Path to save HTML report

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Prepare template variables
            scan_info = self.results["scan_info"]
            summary = self.results["summary"]

            # Parse timestamps
            start_dt = datetime.fromisoformat(scan_info["start_time"])
            end_dt = datetime.fromisoformat(scan_info["end_time"])

            template_vars = {
                "target": scan_info["target"],
                "scan_time": start_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "start_time": start_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "end_time": end_dt.strftime("%Y-%m-%d %H:%M:%S"),
                "generated_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "duration": f"{scan_info['duration']:.2f}",
                "profile": scan_info["profile"],
                "total_hosts": summary["total_hosts"],
                "total_open_ports": summary["total_open_ports"],
                "hosts": self.results["hosts"],
                "colors": CSS_COLORS,
            }

            # Render template
            html_content = self.template.render(**template_vars)

            # Create output directory
            Path(output_filepath).parent.mkdir(parents=True, exist_ok=True)

            # Write to file
            with open(output_filepath, "w") as f:
                f.write(html_content)

            logger.info(f"[+] HTML report generated: {output_filepath}")
            return True

        except Exception as e:
            logger.error(f"Error generating HTML report: {str(e)}")
            return False
