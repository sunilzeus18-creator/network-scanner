"""Network Scanner - CLI Interface"""

import click
import logging
import sys
from datetime import datetime
from pathlib import Path

from scanner import NmapScanner, IPValidator
from report import HTMLReportGenerator
from config import DEFAULT_OUTPUT_DIR, REPORT_DATE_FORMAT, ERROR_MESSAGES

# ============================================================================
# SETUP LOGGING
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(asctime)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger(__name__)


@click.group()
def cli():
    """Network Scanner - Automated Vulnerability Assessment Tool"""
    pass


@cli.command()
@click.option(
    "--target",
    "-t",
    required=True,
    help="Target IP address or CIDR range (e.g., 192.168.1.1 or 192.168.1.0/24)",
)
@click.option(
    "--profile",
    "-p",
    type=click.Choice(["quick", "standard", "intensive"], case_sensitive=False),
    default="standard",
    help="Scan profile: quick (fast), standard (balanced), intensive (thorough)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default=DEFAULT_OUTPUT_DIR,
    help="Output directory for reports",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose logging",
)
@click.option(
    "--no-report",
    "-nr",
    is_flag=True,
    help="Skip HTML report generation",
)
def scan(target, profile, output, verbose, no_report):
    """
    Perform network vulnerability scan

    Example:
        python main.py scan --target 192.168.1.1 --profile standard
    """
    try:
        # Set logging level
        if verbose:
            logging.getLogger().setLevel(logging.DEBUG)
            logger.debug("Verbose mode enabled")

        # Display banner
        _display_banner()

        # Validate input
        logger.info("[*] Validating target...")
        is_valid, message = IPValidator.validate_target(target)
        if not is_valid:
            logger.error(f"[!] {message}")
            sys.exit(1)

        logger.info(f"[+] {message}")

        # Initialize scanner
        logger.info(f"[*] Initializing {profile} scan...")
        scanner = NmapScanner(target=target, profile=profile, verbose=verbose)

        # Execute scan
        logger.info("[*] Starting Nmap scan...")
        if not scanner.scan():
            logger.error("[!] Scan failed. Please check your target and try again.")
            sys.exit(1)

        # Get results
        results = scanner.get_results()

        # Export JSON
        timestamp = datetime.now().strftime(REPORT_DATE_FORMAT)
        json_filename = f"{target.replace('/', '_')}_{profile}_scan_{timestamp}.json"
        json_path = str(Path(output) / json_filename)

        logger.info("[*] Exporting results to JSON...")
        scanner.export_json(json_path)

        # Generate HTML report
        if not no_report:
            logger.info("[*] Generating HTML report...")
            html_filename = f"{target.replace('/', '_')}_{profile}_scan_{timestamp}.html"
            html_path = str(Path(output) / html_filename)

            report_generator = HTMLReportGenerator(results)
            if report_generator.generate(html_path):
                logger.info(f"[+] Report saved: {html_path}")
            else:
                logger.warning("[!] HTML report generation failed, but JSON export succeeded")

        # Print summary
        _print_summary(results)

        logger.info("[+] Scan completed successfully!")
        logger.info(f"[*] Results saved to: {output}")

    except KeyboardInterrupt:
        logger.warning("\n[!] Scan cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"[!] Unexpected error: {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@cli.command()
def validate():
    """
    Validate your system for required dependencies
    """
    logger.info("[*] Checking dependencies...")

    # Check Python version
    import sys
    if sys.version_info >= (3, 8):
        logger.info("[+] Python 3.8+: OK")
    else:
        logger.error(f"[!] Python 3.8+ required (found {sys.version})")
        sys.exit(1)

    # Check Nmap
    scanner = NmapScanner(target="127.0.0.1")
    if scanner.check_nmap_installed():
        logger.info("[+] Nmap: OK")
    else:
        logger.error("[!] Nmap not found. Please install it first.")
        sys.exit(1)

    # Check Python packages
    try:
        import nmap
        logger.info("[+] python-nmap: OK")
    except ImportError:
        logger.error("[!] python-nmap not installed")
        sys.exit(1)

    try:
        import jinja2
        logger.info("[+] jinja2: OK")
    except ImportError:
        logger.error("[!] jinja2 not installed")
        sys.exit(1)

    logger.info("[+] All dependencies OK! You're ready to scan.")


@cli.command()
@click.argument("ip_address")
def check(ip_address):
    """
    Check if an IP address or CIDR range is valid
    """
    is_valid, message = IPValidator.validate_target(ip_address)
    if is_valid:
        click.echo(click.style(f"✓ {message}", fg="green"))
        logger.info(f"[+] {ip_address} is a valid target")
    else:
        click.echo(click.style(f"✗ {message}", fg="red"))
        logger.error(f"[!] {ip_address} is not valid")
        sys.exit(1)


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================


def _display_banner():
    """Display application banner"""
    banner = """
╔════════════════════════════════════════════════════════════════════════════╗
║                  🔍 NETWORK SCANNER v1.0                       ║
║              Automated Vulnerability Assessment               ║
╚════════════════════════════════════════════════════════════════════════════╝
    """
    click.echo(click.style(banner, fg="cyan"))


def _print_summary(results: dict):
    """Print scan summary"""
    click.echo("\n" + "=" * 60)
    click.echo("SCAN SUMMARY")
    click.echo("=" * 60)

    scan_info = results["scan_info"]
    summary = results["summary"]

    click.echo(f"Target:          {scan_info['target']}")
    click.echo(f"Profile:         {scan_info['profile'].upper()}")
    click.echo(f"Duration:        {scan_info['duration']:.2f} seconds")
    click.echo(f"Hosts Found:     {summary['total_hosts']}")
    click.echo(f"Open Ports:      {summary['total_open_ports']}")
    click.echo("=" * 60 + "\n")


if __name__ == "__main__":
    cli()
