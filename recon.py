#!/usr/bin/env python3
"""
OSINT Reconnaissance Tool
Automated information gathering for security assessments
"""

import sys
import requests
import socket
import dns.resolver
from urllib.parse import urlparse
import argparse
from datetime import datetime

class OSINTRecon:
    def __init__(self, target):
        self.target = target
        self.results = {
            'target': target,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'ip_address': None,
            'subdomains': [],
            'dns_records': {},
            'http_headers': {},
            'technologies': []
        }
    
    def resolve_ip(self):
        """Resolve target domain to IP address"""
        try:
            ip = socket.gethostbyname(self.target)
            self.results['ip_address'] = ip
            print(f"[+] IP Address: {ip}")
            return ip
        except socket.gaierror:
            print(f"[-] Could not resolve {self.target}")
            return None
    
    def get_dns_records(self):
        """Fetch DNS records for target"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                records = [str(rdata) for rdata in answers]
                self.results['dns_records'][record_type] = records
                print(f"[+] {record_type} Records: {', '.join(records)}")
            except Exception as e:
                print(f"[-] No {record_type} records found")
    
    def check_http_headers(self):
        """Fetch HTTP headers from target"""
        protocols = ['https', 'http']
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{self.target}"
                response = requests.get(url, timeout=5, allow_redirects=True)
                self.results['http_headers'] = dict(response.headers)
                
                print(f"\n[+] HTTP Headers from {url}:")
                for header, value in response.headers.items():
                    print(f"    {header}: {value}")
                
                # Detect technologies from headers
                self.detect_technologies(response.headers)
                break
            except requests.exceptions.RequestException as e:
                continue
    
    def detect_technologies(self, headers):
        """Detect technologies from HTTP headers"""
        tech_signatures = {
            'Server': 'Web Server',
            'X-Powered-By': 'Backend Technology',
            'X-AspNet-Version': 'ASP.NET',
            'X-AspNetMvc-Version': 'ASP.NET MVC'
        }
        
        for header, tech_type in tech_signatures.items():
            if header in headers:
                tech = f"{tech_type}: {headers[header]}"
                self.results['technologies'].append(tech)
                print(f"[+] Detected: {tech}")
    
    def generate_report(self):
        """Generate a text report of findings"""
        report_filename = f"recon_report_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(report_filename, 'w') as f:
            f.write("="*60 + "\n")
            f.write("OSINT RECONNAISSANCE REPORT\n")
            f.write("="*60 + "\n\n")
            f.write(f"Target: {self.results['target']}\n")
            f.write(f"Scan Time: {self.results['timestamp']}\n\n")
            
            f.write("-"*60 + "\n")
            f.write("IP ADDRESS\n")
            f.write("-"*60 + "\n")
            f.write(f"{self.results['ip_address']}\n\n")
            
            if self.results['dns_records']:
                f.write("-"*60 + "\n")
                f.write("DNS RECORDS\n")
                f.write("-"*60 + "\n")
                for record_type, records in self.results['dns_records'].items():
                    f.write(f"{record_type}: {', '.join(records)}\n")
                f.write("\n")
            
            if self.results['technologies']:
                f.write("-"*60 + "\n")
                f.write("DETECTED TECHNOLOGIES\n")
                f.write("-"*60 + "\n")
                for tech in self.results['technologies']:
                    f.write(f"- {tech}\n")
                f.write("\n")
            
            if self.results['http_headers']:
                f.write("-"*60 + "\n")
                f.write("HTTP HEADERS\n")
                f.write("-"*60 + "\n")
                for header, value in self.results['http_headers'].items():
                    f.write(f"{header}: {value}\n")
        
        print(f"\n[+] Report saved to: {report_filename}")
        return report_filename

def main():
    parser = argparse.ArgumentParser(
        description='OSINT Reconnaissance Tool - Automated information gathering',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recon.py example.com
  python recon.py google.com
        """
    )
    parser.add_argument('target', help='Target domain (e.g., example.com)')
    
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("OSINT RECONNAISSANCE TOOL")
    print("="*60 + "\n")
    
    # Initialize reconnaissance
    recon = OSINTRecon(args.target)
    
    # Run reconnaissance modules
    print("[*] Resolving IP address...")
    recon.resolve_ip()
    
    print("\n[*] Fetching DNS records...")
    recon.get_dns_records()
    
    print("\n[*] Checking HTTP headers...")
    recon.check_http_headers()
    
    # Generate report
    print("\n[*] Generating report...")
    recon.generate_report()
    
    print("\n[+] Reconnaissance complete!\n")

if __name__ == "__main__":
    main()
```

---

### **STEP 2: Create requirements.txt**

Create new file called `requirements.txt` and paste:
```
requests==2.31.0
dnspython==2.4.2