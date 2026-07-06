# Network Scanner - Automated Vulnerability Assessment Tool

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)

## 📋 Overview

Network Scanner is an intermediate-level Python tool that automates network reconnaissance, service enumeration, and vulnerability assessment using Nmap. It streamlines security audits by scanning networks, identifying open ports, detecting running services, and generating comprehensive HTML reports with vulnerability analysis.

## 🎯 Features

- **IP Address Validation**: Comprehensive input validation for single IPs and CIDR ranges
- **Nmap Integration**: Leverages powerful Nmap for accurate port scanning
- **Service Detection**: Identifies services running on open ports with version information
- **Vulnerability Assessment**: Classifies risks and provides security recommendations
- **HTML Report Generation**: Professional, exportable reports with detailed findings
- **Multiple Scan Profiles**: Quick, Standard, and Intensive scanning options
- **Progress Tracking**: Real-time scan progress indicators
- **Error Handling**: Robust exception handling and logging
- **CLI Interface**: User-friendly command-line interface

## 📦 Requirements

- Python 3.8+
- Nmap (must be installed on your system)
- Linux/Unix/MacOS/Windows with Nmap support

### System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get install nmap
```

**MacOS:**
```bash
brew install nmap
```

**Windows:**
- Download from https://nmap.org/download
- Or use: `choco install nmap`

## 🚀 Installation

1. **Clone the repository:**
```bash
git clone https://github.com/sunilzeus18-creator/network-scanner.git
cd network-scanner
```

2. **Create virtual environment:**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\\Scripts\\activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

## 💻 Usage

### Basic Scan
```bash
python main.py scan --target 192.168.1.1
```

### Standard Scan with Service Detection
```bash
python main.py scan --target 192.168.1.0/24 --profile standard
```

### Intensive Scan
```bash
python main.py scan --target 192.168.1.1 --profile intensive
```

### Custom Output Directory
```bash
python main.py scan --target 192.168.1.1 --output ./reports
```

### View Help
```bash
python main.py --help
```

## 📊 Command Line Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|----------|
| `--target` | `-t` | Target IP/CIDR range | Required |
| `--profile` | `-p` | Scan profile (quick/standard/intensive) | standard |
| `--output` | `-o` | Output directory for reports | ./reports |
| `--verbose` | `-v` | Enable verbose logging | False |
| `--no-report` | `-nr` | Skip HTML report generation | False |

## 📁 Project Structure

```
network-scanner/
├── main.py                 # CLI entry point
├── scanner.py              # Core scanning module
├── report.py               # HTML report generator
├── config.py               # Configuration & constants
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── LICENSE                # MIT License
├── .gitignore             # Git ignore rules
└── examples/
    ├── sample_scan.json   # Example scan output
    └── sample_report.html # Example HTML report
```

## 🔍 How It Works

### 1. Input Validation
Validates IP addresses and CIDR ranges using regex and ipaddress module

### 2. Nmap Scanning
Executes Nmap with appropriate flags based on selected profile:
- **Quick**: `-F` (Fast mode, top 100 ports)
- **Standard**: `-sS -sV` (Stealth scan with service detection)
- **Intensive**: `-sS -sV -sC -O` (Full scan with OS detection)

### 3. Data Parsing
Parses Nmap XML output to extract:
- Open/closed/filtered ports
- Service names and versions
- OS information
- Host availability

### 4. Vulnerability Assessment
Classifies risks based on:
- Known vulnerable services
- Service versions
- Open ports exposure
- Default credentials risks

### 5. Report Generation
Generates interactive HTML reports with:
- Executive summary
- Port analysis
- Service details
- Risk classification
- Remediation recommendations

## 📈 Example Output

### Console Output
```
[*] Starting Network Scan...
[+] Target: 192.168.1.1
[+] Profile: standard
[*] Validating target address...
[+] Target validation successful
[*] Initializing Nmap scan...
[+] Scan started at 2024-01-15 10:30:45
[*] Scanning in progress...
[+] Found 5 open ports
[*] Analyzing results...
[+] Generating HTML report...
[+] Report saved: ./reports/192.168.1.1_scan_2024-01-15_103045.html
[+] Scan completed successfully!
```

### HTML Report Features
- 📊 Interactive port listing
- 🔴 Risk severity indicators
- 📝 Detailed service information
- 💡 Security recommendations
- 📅 Scan metadata
- 🎨 Print-friendly layout

## 🔐 Security Considerations

⚠️ **Important:** Only scan networks and systems you own or have explicit permission to scan. Unauthorized network scanning may be illegal.

- Always obtain proper authorization before scanning
- Use responsibly in testing environments
- Respect rate limiting and network resources
- Keep Nmap and Python dependencies updated

## 🛠️ Troubleshooting

### "Nmap not found"
```bash
# Ensure Nmap is installed and in PATH
which nmap
# or on Windows
where nmap
```

### "Permission denied" errors
```bash
# Some Nmap features require elevated privileges
sudo python main.py scan --target 192.168.1.1
```

### "Invalid IP address"
```bash
# Ensure proper IP format
# Valid: 192.168.1.1, 192.168.1.0/24, 10.0.0.1
# Invalid: 192.168.1, 999.999.999.999
```

## 📚 Dependencies

| Package | Version | Purpose |
|---------|---------|----------|
| python-nmap | >=0.0.1 | Nmap integration |
| jinja2 | >=3.0 | HTML templating |
| click | >=8.0 | CLI framework |

## 📝 License

MIT License - See LICENSE file for details

## 👨‍💻 Author

**Sunil Zeus**
- GitHub: [@sunilzeus18-creator](https://github.com/sunilzeus18-creator)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## 📞 Support

For issues and questions, please open an issue on GitHub.

## 🎓 Learning Resources

- [Nmap Documentation](https://nmap.org/book/)
- [Python-Nmap Tutorial](https://xael.org/pages/python-nmap-en.html)
- [Network Security Basics](https://www.cisco.com/c/en/us/support/docs/)

---

**Made with ❤️ for cybersecurity professionals and enthusiasts**
