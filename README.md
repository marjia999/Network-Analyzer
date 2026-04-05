# Network Analyzer

An web-based network intelligence tool that gathers publicly available information about domains and IP addresses. Built with Flask and modern web technologies.

## Features

- **Domain & IP Analysis** - Analyze both domain names and IP addresses
- **WHOIS Lookup** - Get registrar, creation date, expiration date, and owner information
- **DNS Records** - View A, AAAA, MX, NS, TXT, CNAME, and SOA records
- **SSL Certificate Analysis** - Check certificate issuer, validity period, and subject details
- **Geolocation** - Find IP location, country, city, ISP, and organization
- **Port Scanner** - Check common open ports (HTTP, HTTPS, SSH, FTP, MySQL, etc.)
- **Ping Test** - Test connectivity and measure response times
- **Traceroute** - Map the network path to the target
- **Technology Detection** - Identify web servers, frameworks, and CMS platforms
- **Subdomain Discovery** - Find active subdomains like www, mail, admin, api, etc.
- **Export Results** - Save analysis as JSON or copy to clipboard

## Legal & Ethical Use

This tool only collects **publicly available information** through:
- Standard DNS queries
- Public WHOIS databases
- SSL certificate transparency logs
- Public geolocation APIs
- Standard ICMP ping and traceroute

**No active exploitation, brute force, or intrusive scanning is performed.**

## Tech Stack

- **Backend**: Python Flask
- **Frontend**: HTML5, CSS3, JavaScript

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

### Step 1: Clone the Repository

git clone https://github.com/yourusername/network-analyzer.git
cd network-analyzer

### Step 2: Install Dependencies
pip install flask flask-cors dnspython python-whois requests

### Step 3: Run the Application
python app.py

## Contact
- **Email**: marjiakhatun.my@gmail.com
- **LinkedIn**: https://www.linkedin.com/in/marjia-khatun/
