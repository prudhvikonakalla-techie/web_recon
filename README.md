# Advanced Security Recon & Exploitation Toolkit

A comprehensive suite of Python scripts designed for reconnaissance, vulnerability detection, and penetration testing automation. Each script targets a specific security testing aspect with modularity and extensibility.

---

## Table of Contents

- [Advanced_url.py](#advanced_urlpy)  
- [url.py](#urlpy)  
- [directory_traversal.py](#directory_traversalpy)  
- [sqli_proxy.py](#sqli_proxypy)  
- [advanced_sub.py](#advanced_subpy)  
- [xss_to.py](#xss_topy)  
- [fuzz.py](#fuzzpy)  
- [Requirements](#requirements)  
- [Notes](#notes)

---

## advanced_url.py

Extracts URLs embedded in HTML, JavaScript, CSS, and performs passive/active OSINT reconnaissance using sources like Google Dorking, Wayback Machine, crt.sh with multithreaded crawling.

python3 Advanced_url.py [-f SUBDOMAINS_FILE] [-d HOST] [--proxy PROXY]

- `-d, --host <domain>`: Target domain to crawl.  
- `-f, --file <subdomains_file>`: File containing subdomains for enumeration.  
- `--proxy <proxy_url>`: Optional HTTP proxy for requests.

### Examples

python3 Advanced_url.py -d example.com

---

## url.py

Scrapes all links from HTML, JavaScript, and CSS of provided domains or subdomains.

### Usage

python3 url.py [-f SUBDOMAINS_FILE] [-d HOST] [--proxy PROXY]

---

## directory_traversal.py

Tests directory traversal vulnerabilities by injecting payload strings into target URLs.

### Usage

python3 directory_traversal.py <URL> <PAYLOAD_FILE> [--proxy PROXY]

- `<URL>` should include the injectable parameter spot, e.g. `http://site/file.php?file=`.  
- `<PAYLOAD_FILE>` expects traversal payloads like `../../etc/passwd`.

### Example

    
    same for every tool
### Usage


---

## Requirements

- Python 3.x runtime environment
- Required Python packages (install via pip):


---

## Notes

- Proxy support is available for anonymizing traffic where specified.
- Use the flags `-h` or `--help` on any script to discover additional customizable parameters.
- Most tools support output to files for logging and reporting.
- Customize payload and wordlist files to align with your target scope.
- These tools are intended to aid professional penetration testers and cybersecurity specialists by accelerating common enumeration and vulnerability scanning tasks.

---

*This documentation and toolkit were created to streamline and automate complex security testing workflows efficiently.*



