# OSINT Reconnaissance Tool

Automated OSINT (Open Source Intelligence) reconnaissance tool for security assessments and penetration testing.

## Features

- 🔍 IP address resolution
- 📋 DNS record enumeration (A, AAAA, MX, NS, TXT, SOA)
- 🌐 HTTP header analysis
- 🔧 Technology detection
- 📄 Automated report generation

## Installation
```bash
# Clone the repository
git clone https://github.com/Moescodez/OSINT-Recon-Tool.git
cd OSINT-Recon-Tool

# Install dependencies
pip3 install -r requirements.txt
```

## Usage
```bash
# Basic scan
python3 recon.py example.com

# Scan any domain
python3 recon.py target-domain.com
```

## Example Output
```
============================================================
OSINT RECONNAISSANCE TOOL
============================================================

[*] Resolving IP address...
[+] IP Address: 93.184.216.34

[*] Fetching DNS records...
[+] A Records: 93.184.216.34
[+] NS Records: a.iana-servers.net., b.iana-servers.net.

[*] Checking HTTP headers...
[+] Detected: Web Server: ECS (dcb/7EA3)

[*] Generating report...
[+] Report saved to: recon_report_example.com_20241210_214500.txt
```

## Legal Disclaimer

This tool is for educational and authorized security testing only. Always obtain proper authorization before scanning any targets you do not own.

## License

MIT License - See LICENSE file for details

## Author

**Moescodez** - Cybersecurity Student & Developer

[GitHub Profile](https://github.com/Moescodez)
