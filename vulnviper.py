#!/usr/bin/env python3
# VulnViper - Web Server Vulnerability Scanner
# By koreyhacks_

import argparse
import concurrent.futures
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime
from pathlib import Path

try:
    import requests
    from colorama import Fore, Back, Style, init
    from tqdm import tqdm
    from art import text2art
except ImportError:
    print("[!] Missing required packages. Installing...")
    subprocess.call([sys.executable, "-m", "pip", "install", "requests", "colorama", "tqdm", "art"])
    import requests
    from colorama import Fore, Back, Style, init
    from tqdm import tqdm
    from art import text2art

# Initialize colorama
init(autoreset=True)

# ASCII art and banner display
def display_banner():
    os.system('cls' if platform.system() == 'Windows' else 'clear')
    
    # Create pixel-style "VulnViper" logo with emerald and cream colors
    # Emerald to cream gradient for the text
    logo = [
        Fore.GREEN + "██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗   ██╗██╗██████╗ ███████╗██████╗ ",
        Fore.GREEN + "██║   ██║██║   ██║██║     ████╗  ██║██║   ██║██║██╔══██╗██╔════╝██╔══██╗",
        Fore.GREEN + "██║   ██║██║   ██║██║     ██╔██╗ ██║██║   ██║██║██████╔╝█████╗  ██████╔╝",
        Fore.WHITE + "╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚██╗ ██╔╝██║██╔═══╝ ██╔══╝  ██╔══██╗",
        Fore.WHITE + " ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║ ╚████╔╝ ██║██║     ███████╗██║  ██║",
        Fore.WHITE + "  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝  ╚═══╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝"
    ]
    
    # Print the logo
    for line in logo:
        print(line)
    
    # Print the cyan horizontal line
    print(Fore.CYAN + "═" * 80)
    
    # Print subtitle and author
    print(Fore.CYAN + "            Web Server Vulnerability Scanner v1.0")
    print(Fore.GREEN + "                      By koreyhacks_")
    
    # Print another cyan horizontal line
    print(Fore.CYAN + "═" * 80)
    
    # Cybersecurity-themed terminal animation
    animation_frames = [
        # Scanning phase
        f"{Fore.GREEN}[{Fore.WHITE}INITIALIZING SCAN{Fore.GREEN}]",
        f"{Fore.GREEN}[{Fore.WHITE}INITIALIZING SCAN.{Fore.GREEN}]",
        f"{Fore.GREEN}[{Fore.WHITE}INITIALIZING SCAN..{Fore.GREEN}]",
        f"{Fore.GREEN}[{Fore.WHITE}INITIALIZING SCAN...{Fore.GREEN}]",
        
        # Target acquisition 
        f"{Fore.GREEN}[{Fore.WHITE}TARGET ACQUISITION{Fore.GREEN}]                     {Fore.WHITE}▒",
        f"{Fore.GREEN}[{Fore.WHITE}TARGET ACQUISITION.{Fore.GREEN}]                   {Fore.WHITE}▒ ▒",
        f"{Fore.GREEN}[{Fore.WHITE}TARGET ACQUISITION..{Fore.GREEN}]                 {Fore.WHITE}▒   ▒",
        f"{Fore.GREEN}[{Fore.WHITE}TARGET ACQUISITION...{Fore.GREEN}]               {Fore.WHITE}▒     ▒",
        f"{Fore.GREEN}[{Fore.WHITE}TARGET ACQUIRED{Fore.GREEN}]                     {Fore.WHITE}▒▒▒▒▒▒▒",
        
        # System breach animation
        f"{Fore.GREEN}[{Fore.WHITE}SYSTEM BREACH{Fore.GREEN}] {Fore.WHITE}|{' ' * 20}|",
        f"{Fore.GREEN}[{Fore.WHITE}SYSTEM BREACH{Fore.GREEN}] {Fore.WHITE}|{Fore.GREEN}▓{Fore.WHITE}{' ' * 19}|",
        f"{Fore.GREEN}[{Fore.WHITE}SYSTEM BREACH{Fore.GREEN}] {Fore.WHITE}|{Fore.GREEN}▓▓▓{Fore.WHITE}{' ' * 17}|",
        f"{Fore.GREEN}[{Fore.WHITE}SYSTEM BREACH{Fore.GREEN}] {Fore.WHITE}|{Fore.GREEN}▓▓▓▓▓{Fore.WHITE}{' ' * 15}|",
        f"{Fore.GREEN}[{Fore.WHITE}SYSTEM BREACH{Fore.GREEN}] {Fore.WHITE}|{Fore.GREEN}▓▓▓▓▓▓▓▓{Fore.WHITE}{' ' * 12}|",
        f"{Fore.GREEN}[{Fore.WHITE}SYSTEM BREACH{Fore.GREEN}] {Fore.WHITE}|{Fore.GREEN}▓▓▓▓▓▓▓▓▓▓▓{Fore.WHITE}{' ' * 9}|",
        f"{Fore.GREEN}[{Fore.WHITE}SYSTEM BREACH{Fore.GREEN}] {Fore.WHITE}|{Fore.GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▓▓{Fore.WHITE}{' ' * 6}|",
        f"{Fore.GREEN}[{Fore.WHITE}SYSTEM BREACH{Fore.GREEN}] {Fore.WHITE}|{Fore.GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓{Fore.WHITE}{' ' * 3}|",
        f"{Fore.GREEN}[{Fore.WHITE}SYSTEM BREACH{Fore.GREEN}] {Fore.WHITE}|{Fore.GREEN}▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓{Fore.WHITE}|",
        
        # Access gained
        f"{Fore.GREEN}[{Fore.WHITE}ACCESS GRANTED{Fore.GREEN}] {Fore.GREEN}VULNERABILITY SCAN READY",
    ]
    
    for frame in animation_frames:
        sys.stdout.write('\r' + frame + ' ' * 20)  # Extra spaces to clear longer previous lines
        sys.stdout.flush()
        time.sleep(0.2)
    print("\n")

class VulnViper:
    def __init__(self, target, output=None, port=80, ssl_port=443, threads=10, 
                 timeout=10, user_agent=None, follow_redirects=True, verbose=False):
        self.target = target
        self.output_file = output
        self.port = port
        self.ssl_port = ssl_port
        self.threads = threads
        self.timeout = timeout
        self.user_agent = user_agent or "VulnViper/1.0"
        self.follow_redirects = follow_redirects
        self.verbose = verbose
        self.vulnerabilities = []
        self.scan_time = None
        
        # Load vulnerability databases
        self.load_databases()
    
    def load_databases(self):
        """Load vulnerability databases from JSON files"""
        # This would normally load from files, but we'll define inline for simplicity
        self.header_checks = {
            "X-Frame-Options": {
                "missing": "Missing X-Frame-Options header makes the site vulnerable to clickjacking",
                "risk": "medium"
            },
            "X-XSS-Protection": {
                "missing": "Missing X-XSS-Protection header may increase XSS risk",
                "risk": "medium"
            },
            "Content-Security-Policy": {
                "missing": "Missing Content-Security-Policy header increases risk of XSS and data injection",
                "risk": "high"
            },
            "Strict-Transport-Security": {
                "missing": "Missing HSTS header allows SSL stripping attacks",
                "risk": "high"
            },
            "X-Content-Type-Options": {
                "missing": "Missing X-Content-Type-Options header allows MIME sniffing",
                "risk": "low"
            }
        }
        
        self.server_signatures = {
            "Apache": {
                "2.2": {"eol": True, "cves": ["CVE-2017-9798", "CVE-2016-8743"]},
                "2.4.1": {"eol": True, "cves": ["CVE-2014-0226", "CVE-2013-6438"]},
            },
            "nginx": {
                "1.10": {"eol": True, "cves": ["CVE-2016-0742", "CVE-2016-0746"]},
                "1.12": {"eol": True, "cves": ["CVE-2017-7529"]}
            },
            "Microsoft-IIS": {
                "7.0": {"eol": True, "cves": ["CVE-2010-1256", "CVE-2010-2731"]},
                "7.5": {"eol": True, "cves": ["CVE-2010-3972"]}
            }
        }
        
        # Common misconfigurations to check
        self.common_paths = [
            "/admin", "/login", "/wp-admin", "/phpinfo.php", "/test.php", 
            "/.git/", "/.env", "/backup", "/config", "/debug"
        ]
    
    def scan(self):
        """Main scanning function to orchestrate all checks"""
        start_time = time.time()
        print(f"{Fore.CYAN}[*] Starting scan of {self.target}...")
        
        try:
            # Test basic connectivity
            if not self.connect_to_target():
                print(f"{Fore.RED}[!] Cannot connect to target. Aborting scan.")
                return False
            
            # Run various checks
            self.check_headers()
            self.check_server_info()
            self.scan_common_paths()
            if self.ssl_port:
                self.check_ssl_tls()
            
            self.scan_time = time.time() - start_time
            
            # Generate report
            self.generate_report()
            return True
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
            self.scan_time = time.time() - start_time
            self.generate_report(interrupted=True)
            return False
        except Exception as e:
            print(f"{Fore.RED}[!] Error during scan: {str(e)}")
            return False
    
    def connect_to_target(self):
        """Test basic connectivity to the target"""
        try:
            # Clean up the target URL if it includes protocol
            target = self.target
            if target.startswith("http://") or target.startswith("https://"):
                # Extract just the hostname and port if included
                parsed = urllib.parse.urlparse(target)
                target = parsed.netloc
                if not target:  # Handle case where netloc might be empty
                    target = parsed.path
            
            http_url = f"http://{target}"
            if self.verbose:
                print(f"{Fore.CYAN}[*] Testing connection to {http_url}")
            
            response = requests.get(http_url, 
                                   headers={"User-Agent": self.user_agent},
                                   timeout=self.timeout,
                                   allow_redirects=self.follow_redirects,
                                   verify=False)
            return True
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] HTTP connection failed: {str(e)}")
            
            # Try HTTPS if HTTP fails
            if self.ssl_port:
                try:
                    https_url = f"https://{target}"
                    if self.verbose:
                        print(f"{Fore.CYAN}[*] Testing connection to {https_url}")
                    
                    response = requests.get(https_url, 
                                          headers={"User-Agent": self.user_agent},
                                          timeout=self.timeout,
                                          allow_redirects=self.follow_redirects,
                                          verify=False)
                    return True
                except requests.exceptions.RequestException as e2:
                    print(f"{Fore.RED}[!] HTTPS connection failed: {str(e2)}")
            
            return False
    
    def check_headers(self):
        """Check for missing or insecure HTTP headers"""
        print(f"{Fore.CYAN}[*] Checking HTTP security headers...")
        
        try:
            # Clean up the target URL if it includes protocol
            target = self.target
            if target.startswith("http://") or target.startswith("https://"):
                # Extract just the hostname and port if included
                parsed = urllib.parse.urlparse(target)
                target = parsed.netloc
                if not target:  # Handle case where netloc might be empty
                    target = parsed.path
                    
            http_url = f"http://{target}"
            response = requests.get(http_url, 
                                  headers={"User-Agent": self.user_agent},
                                  timeout=self.timeout,
                                  allow_redirects=self.follow_redirects,
                                  verify=False)
            
            headers = response.headers
            
            for header, check in self.header_checks.items():
                if header not in headers:
                    vuln = {
                        "type": "missing_header",
                        "header": header,
                        "description": check["missing"],
                        "risk": check["risk"]
                    }
                    self.vulnerabilities.append(vuln)
                    risk_color = Fore.RED if check["risk"] == "high" else (Fore.YELLOW if check["risk"] == "medium" else Fore.BLUE)
                    print(f"{risk_color}[!] {check['missing']}")
            
            # Check for Server header disclosure
            if "Server" in headers:
                server = headers["Server"]
                vuln = {
                    "type": "information_disclosure",
                    "header": "Server",
                    "value": server,
                    "description": f"Server header discloses version information: {server}",
                    "risk": "low"
                }
                self.vulnerabilities.append(vuln)
                print(f"{Fore.BLUE}[*] Server header reveals: {server}")
            
            print(f"{Fore.GREEN}[+] Header check completed")
            
        except requests.exceptions.RequestException as e:
            print(f"{Fore.YELLOW}[!] Error checking headers: {str(e)}")
    
    def check_server_info(self):
        """Check for vulnerable server software versions"""
        print(f"{Fore.CYAN}[*] Checking server software...")
        
        try:
            # Clean up the target URL if it includes protocol
            target = self.target
            if target.startswith("http://") or target.startswith("https://"):
                # Extract just the hostname and port if included
                parsed = urllib.parse.urlparse(target)
                target = parsed.netloc
                if not target:  # Handle case where netloc might be empty
                    target = parsed.path
                    
            http_url = f"http://{target}"
            response = requests.get(http_url, 
                                  headers={"User-Agent": self.user_agent},
                                  timeout=self.timeout,
                                  allow_redirects=self.follow_redirects,
                                  verify=False)
            
            if "Server" in response.headers:
                server = response.headers["Server"]
                
                # Check for known vulnerable server versions
                for server_type, versions in self.server_signatures.items():
                    if server_type in server:
                        for version, info in versions.items():
                            if version in server:
                                vuln = {
                                    "type": "outdated_software",
                                    "software": server_type,
                                    "version": version,
                                    "description": f"Outdated {server_type} version {version} has known vulnerabilities",
                                    "risk": "high" if info["eol"] else "medium",
                                    "cves": info["cves"]
                                }
                                self.vulnerabilities.append(vuln)
                                print(f"{Fore.RED}[!] Outdated {server_type} version {version} detected")
                                print(f"{Fore.YELLOW}    Associated CVEs: {', '.join(info['cves'])}")
                
            print(f"{Fore.GREEN}[+] Server software check completed")
            
        except requests.exceptions.RequestException as e:
            print(f"{Fore.YELLOW}[!] Error checking server info: {str(e)}")
    
    def scan_common_paths(self):
        """Scan for common files, directories and misconfigurations"""
        print(f"{Fore.CYAN}[*] Scanning for common misconfigurations...")
        
        # Clean up the target URL if it includes protocol
        target = self.target
        if target.startswith("http://") or target.startswith("https://"):
            # Extract just the hostname and port if included
            parsed = urllib.parse.urlparse(target)
            target = parsed.netloc
            if not target:  # Handle case where netloc might be empty
                target = parsed.path
                
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for path in self.common_paths:
                http_url = f"http://{target}{path}"
                futures.append(executor.submit(self.check_path, http_url, path))
            
            for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Progress"):
                # Results are handled in check_path
                pass
        
        print(f"{Fore.GREEN}[+] Misconfiguration scan completed")
    
    def check_path(self, url, path):
        """Check a single path for accessibility"""
        try:
            response = requests.get(url, 
                                   headers={"User-Agent": self.user_agent},
                                   timeout=self.timeout,
                                   allow_redirects=self.follow_redirects,
                                   verify=False)
            
            # Check for successful responses (200 OK)
            if response.status_code == 200:
                vuln = {
                    "type": "exposed_path",
                    "path": path,
                    "status_code": response.status_code,
                    "description": f"Potentially sensitive path {path} is accessible",
                    "risk": "medium"
                }
                self.vulnerabilities.append(vuln)
                if self.verbose:
                    print(f"{Fore.YELLOW}[!] Found accessible path: {path} (Status: {response.status_code})")
            
            # Check for interesting redirects (30x responses)
            elif 300 <= response.status_code < 400:
                vuln = {
                    "type": "redirect",
                    "path": path,
                    "status_code": response.status_code,
                    "location": response.headers.get("Location", "Unknown"),
                    "description": f"Path {path} redirects to {response.headers.get('Location', 'Unknown')}",
                    "risk": "low"
                }
                self.vulnerabilities.append(vuln)
                if self.verbose:
                    print(f"{Fore.BLUE}[*] Path {path} redirects to {response.headers.get('Location', 'Unknown')}")
                
        except requests.exceptions.RequestException:
            # Ignore connection errors for individual paths
            pass
    
    def check_ssl_tls(self):
        """Check for SSL/TLS misconfigurations"""
        print(f"{Fore.CYAN}[*] Checking SSL/TLS configuration...")
        
        try:
            # Clean up the target URL if it includes protocol
            target = self.target
            if target.startswith("http://") or target.startswith("https://"):
                # Extract just the hostname and port if included
                parsed = urllib.parse.urlparse(target)
                target = parsed.netloc
                if not target:  # Handle case where netloc might be empty
                    target = parsed.path
                
            # Extract hostname without port if port is included
            if ":" in target:
                target = target.split(":")[0]
                
            context = ssl.create_default_context()
            conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=target)
            conn.settimeout(self.timeout)
            conn.connect((target, self.ssl_port))
            
            # Get certificate info
            cert = conn.getpeercert()
            
            # Check certificate expiration
            not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
            if not_after < datetime.now():
                vuln = {
                    "type": "expired_cert",
                    "description": "SSL certificate has expired",
                    "expiry": cert['notAfter'],
                    "risk": "high"
                }
                self.vulnerabilities.append(vuln)
                print(f"{Fore.RED}[!] SSL certificate has expired!")
            
            # Check for weak SSL version
            version = conn.version()
            if "TLSv1.0" in version or "TLSv1.1" in version or "SSLv3" in version:
                vuln = {
                    "type": "weak_ssl",
                    "description": f"Server uses outdated SSL/TLS protocol: {version}",
                    "version": version,
                    "risk": "high"
                }
                self.vulnerabilities.append(vuln)
                print(f"{Fore.RED}[!] Server uses outdated SSL/TLS protocol: {version}")
            
            # Extract certificate information
            if self.verbose:
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                print(f"{Fore.GREEN}[+] SSL Certificate:")
                print(f"    Issuer: {issuer.get('organizationName', 'Unknown')}")
                print(f"    Subject: {subject.get('commonName', 'Unknown')}")
                print(f"    Expiry: {cert['notAfter']}")
            
            conn.close()
            print(f"{Fore.GREEN}[+] SSL/TLS check completed")
            
        except ssl.SSLError as e:
            vuln = {
                "type": "ssl_error",
                "description": f"SSL error: {str(e)}",
                "risk": "medium"
            }
            self.vulnerabilities.append(vuln)
            print(f"{Fore.YELLOW}[!] SSL Error: {str(e)}")
        except (socket.error, socket.timeout, socket.gaierror) as e:
            print(f"{Fore.YELLOW}[!] Error connecting for SSL check: {str(e)}")
    
    def generate_report(self, interrupted=False):
        """Generate a report of findings"""
        if not self.vulnerabilities and not interrupted:
            print(f"{Fore.GREEN}[+] No vulnerabilities found!")
            return
        
        print(f"\n{Fore.CYAN}[*] Scan Results for {self.target}:")
        print(f"{Fore.CYAN}{'=' * 60}")
        
        if interrupted:
            print(f"{Fore.YELLOW}[!] Scan was interrupted - results may be incomplete\n")
        
        # Group vulnerabilities by risk
        high_risk = [v for v in self.vulnerabilities if v.get("risk") == "high"]
        medium_risk = [v for v in self.vulnerabilities if v.get("risk") == "medium"]
        low_risk = [v for v in self.vulnerabilities if v.get("risk") == "low"]
        
        # Print summary
        print(f"{Fore.RED}High Risk: {len(high_risk)}")
        print(f"{Fore.YELLOW}Medium Risk: {len(medium_risk)}")
        print(f"{Fore.BLUE}Low Risk: {len(low_risk)}")
        print(f"\nTotal vulnerabilities: {len(self.vulnerabilities)}")
        print(f"Scan duration: {self.scan_time:.2f} seconds\n")
        
        # Print detailed findings
        if high_risk:
            print(f"{Fore.RED}HIGH RISK FINDINGS:")
            for vuln in high_risk:
                print(f"{Fore.RED}[!] {vuln['description']}")
            print()
        
        if medium_risk:
            print(f"{Fore.YELLOW}MEDIUM RISK FINDINGS:")
            for vuln in medium_risk:
                print(f"{Fore.YELLOW}[!] {vuln['description']}")
            print()
        
        if low_risk:
            print(f"{Fore.BLUE}LOW RISK FINDINGS:")
            for vuln in low_risk:
                print(f"{Fore.BLUE}[*] {vuln['description']}")
            print()
        
        # Save to file if output is specified
        if self.output_file:
            try:
                report = {
                    "target": self.target,
                    "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "duration": f"{self.scan_time:.2f}",
                    "vulnerabilities": self.vulnerabilities,
                    "summary": {
                        "high_risk": len(high_risk),
                        "medium_risk": len(medium_risk),
                        "low_risk": len(low_risk),
                        "total": len(self.vulnerabilities)
                    }
                }
                
                with open(self.output_file, 'w') as f:
                    json.dump(report, f, indent=4)
                
                print(f"{Fore.GREEN}[+] Report saved to {self.output_file}")
            except Exception as e:
                print(f"{Fore.RED}[!] Error saving report: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="VulnViper - Web Server Vulnerability Scanner by koreyhacks_")
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument("-p", "--port", type=int, default=80, help="HTTP port (default: 80)")
    parser.add_argument("-s", "--ssl-port", type=int, default=443, help="HTTPS port (default: 443)")
    parser.add_argument("-o", "--output", help="Output file for report (JSON format)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-m", "--timeout", type=int, default=10, help="Connection timeout in seconds (default: 10)")
    parser.add_argument("-a", "--user-agent", default="VulnViper/1.0", help="Custom User-Agent string")
    parser.add_argument("-f", "--follow-redirects", action="store_true", help="Follow redirects")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    # Display banner
    display_banner()
    
    # Create and run scanner
    scanner = VulnViper(
        target=args.target,
        output=args.output,
        port=args.port,
        ssl_port=args.ssl_port,
        threads=args.threads,
        timeout=args.timeout,
        user_agent=args.user_agent,
        follow_redirects=args.follow_redirects,
        verbose=args.verbose
    )
    
    scanner.scan()

if __name__ == "__main__":
    main()
