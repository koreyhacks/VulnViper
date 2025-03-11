# VulnViper

![2025-03-11 15_17_52-KALI  Running  - Oracle VirtualBox _ 1](https://github.com/user-attachments/assets/4ac1d21d-4e69-4cd4-9eb6-581cdd5fd661)


## Features

VulnViper is a powerful, customizable web server vulnerability scanner written in Python that helps ethical hackers, penetration testers, and security professionals identify security issues in web servers. Drawing inspiration from tools like Nikto, VulnViper offers a modern implementation with an enhanced user experience.

- **Security Header Analysis**: Detect missing or misconfigured HTTP security headers
- **Server Software Detection**: Identify outdated web server versions with known vulnerabilities
- **Common Path Discovery**: Scan for sensitive directories and files that shouldn't be publicly accessible
- **SSL/TLS Assessment**: Check for weak protocols, expired certificates, and other TLS vulnerabilities
- **Risk-Based Reporting**: Issues categorized by risk level (High, Medium, Low)
- **Threading Support**: Fast scanning with configurable thread count
- **JSON Reports**: Export findings to structured JSON for integration with other tools
- **User-Friendly Interface**: Terminal-based UI with color-coded output and progress indicators

## Installation

### Requirements
- Python 3.6+
- Kali Linux (recommended) or any Linux/macOS/Windows system

### Quick Install

```bash
# Clone the repository
git clone https://github.com/koreyhacks_/vulnviper.git
cd vulnviper

# Make the script executable
chmod +x vulnviper.py

# Install required packages
pip3 install requests colorama tqdm art
```

### Dependencies
VulnViper will attempt to install its dependencies automatically if they're not found:
- requests: For HTTP/HTTPS communication
- colorama: For colored terminal output
- tqdm: For progress bars
- art: For ASCII art generation

## Usage

### Basic Usage

```bash
./vulnviper.py example.com
```

### Testing with OWASP Juice Shop

For testing purposes, you can use OWASP Juice Shop, a deliberately vulnerable web application:

#### Prerequisites
- Docker installed on your system

```bash
# Install Docker on Kali Linux (if not already installed)
sudo apt update
sudo apt install -y docker.io
sudo systemctl enable docker --now
sudo usermod -aG docker $USER
# Log out and back in, or run: newgrp docker

# Launch OWASP Juice Shop in a new terminal
docker run --rm -it -p 3000:3000 bkimminich/juice-shop
```

Once Juice Shop is running, you can scan it with VulnViper:

```bash
./vulnviper.py localhost:3000
```

This provides a safe, legal environment for testing VulnViper's capabilities without risking unauthorized scanning of external systems.

### Options

```
usage: vulnviper.py [-h] [-p PORT] [-s SSL_PORT] [-o OUTPUT] [-t THREADS]
                   [-m TIMEOUT] [-a USER_AGENT] [-f] [-v] target

VulnViper - Web Server Vulnerability Scanner by koreyhacks_

positional arguments:
  target                Target hostname or IP address

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  HTTP port (default: 80)
  -s SSL_PORT, --ssl-port SSL_PORT
                        HTTPS port (default: 443)
  -o OUTPUT, --output OUTPUT
                        Output file for report (JSON format)
  -t THREADS, --threads THREADS
                        Number of threads (default: 10)
  -m TIMEOUT, --timeout TIMEOUT
                        Connection timeout in seconds (default: 10)
  -a USER_AGENT, --user-agent USER_AGENT
                        Custom User-Agent string
  -f, --follow-redirects
                        Follow redirects
  -v, --verbose         Enable verbose output
```

### Examples

Scan a website with verbose output and save results to a file:
```bash
./vulnviper.py example.com -v -o results.json
```

Scan a specific port:
```bash
./vulnviper.py example.com -p 8080
```

Increase thread count for faster scanning:
```bash
./vulnviper.py example.com -t 20
```

Use a custom user agent:
```bash
./vulnviper.py example.com -a "Mozilla/5.0 (X11; Linux x86_64)"
```
## Sample Results

When scanning a vulnerable application like OWASP Juice Shop, VulnViper identifies security issues and presents them in an organized, color-coded format:

![2025-03-11 15_14_33-KALI  Running  - Oracle VirtualBox _ 1](https://github.com/user-attachments/assets/64aa28e3-bbdb-417f-b801-bf4a45c377ed)


As shown in the results above, VulnViper detected:
- 2 High Risk vulnerabilities (missing Content-Security-Policy and HSTS headers)
- 11 Medium Risk vulnerabilities
- 13 Total vulnerabilities

The tool completes comprehensive scans quickly (this scan finished in just 0.24 seconds) and clearly categorizes findings by severity to help prioritize remediation efforts.

## Risk Assessment

VulnViper categorizes findings into three risk levels:

### High Risk
Critical security issues that require immediate attention, such as:
- Expired SSL certificates
- Outdated server software with known vulnerabilities
- Missing critical security headers (CSP, HSTS)

### Medium Risk
Significant vulnerabilities that should be addressed promptly:
- Missing X-Frame-Options headers (clickjacking risk)
- Missing X-XSS-Protection headers
- Exposed sensitive paths

### Low Risk
Minor issues that may indicate security weaknesses:
- Information disclosure via server headers
- Redirects to potentially sensitive resources
- Missing non-critical security headers

## Contributing

Contributions are always welcome! If you'd like to contribute, please:

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add some amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## Ethical Use

VulnViper is designed for ethical security testing with proper authorization. Always ensure you have permission to scan any systems or networks. The developers assume no liability for misuse of this tool.

## Acknowledgments

- Inspired by Nikto and other web vulnerability scanners
- Created by koreyhacks_
- Special thanks to the open-source security community
