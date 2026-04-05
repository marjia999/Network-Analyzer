from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import socket
import dns.resolver
import whois
import requests
import ssl
import ipaddress
import subprocess
import platform
from datetime import datetime
import re

app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return send_file('index.html')

@app.route('/style.css')
def css():
    return send_file('style.css')

def is_ip_address(target):
    """Check if target is an IP address"""
    try:
        ipaddress.ip_address(target)
        return True
    except:
        return False

def get_dns_records(domain):
    """Get all DNS records for a domain"""
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    
    for record_type in record_types:
        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(domain, record_type)
            records[record_type] = [str(answer) for answer in answers]
        except:
            records[record_type] = []
    
    return records

def get_ptr_record(ip):
    """Get PTR record (reverse DNS) for IP address"""
    try:
        resolver = dns.resolver.Resolver()
        reverse_ip = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'
        answers = resolver.resolve(reverse_ip, 'PTR')
        return [str(answer) for answer in answers]
    except:
        return []

def get_whois_info(target):
    """Get WHOIS information for domain or IP"""
    try:
        w = whois.whois(target)
        info = {
            "registrar": str(w.registrar) if w.registrar else "N/A",
            "creation_date": str(w.creation_date) if w.creation_date else "N/A",
            "expiration_date": str(w.expiration_date) if w.expiration_date else "N/A",
            "name_servers": w.name_servers if w.name_servers else [],
            "org": str(w.org) if w.org else "N/A",
            "country": str(w.country) if w.country else "N/A",
            "emails": w.emails if w.emails else []
        }
        return info
    except Exception as e:
        return {"error": str(e), "note": "WHOIS may not be available for this IP"}

def get_ssl_info(target):
    """Get SSL certificate information (domains only)"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                return {
                    "issuer": dict(x[0] for x in cert['issuer']),
                    "subject": dict(x[0] for x in cert['subject']),
                    "expiry": cert['notAfter'],
                    "start": cert['notBefore'],
                    "serial": cert['serialNumber'],
                    "version": cert['version']
                }
    except:
        return None

def get_geolocation(target):
    """Get server geolocation"""
    try:
        if not is_ip_address(target):
            ip = socket.gethostbyname(target)
        else:
            ip = target
        
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        data = response.json()
        if data['status'] == 'success':
            return {
                "ip": ip,
                "country": data['country'],
                "city": data['city'],
                "region": data['regionName'],
                "isp": data['isp'],
                "org": data['org'],
                "lat": data['lat'],
                "lon": data['lon'],
                "timezone": data['timezone'],
                "as": data['as']
            }
        return {"ip": ip, "error": "Location not found"}
    except Exception as e:
        return {"error": str(e)}

def get_technologies(target):
    """Detect technologies used (domains only)"""
    techs = []
    try:
        response = requests.get(f'https://{target}', timeout=5, verify=False)
        headers = response.headers
        
        if 'Server' in headers:
            techs.append(f"Server: {headers['Server']}")
        
        if 'X-Powered-By' in headers:
            techs.append(f"Powered by: {headers['X-Powered-By']}")
        
        if 'Content-Type' in headers:
            techs.append(f"Content-Type: {headers['Content-Type']}")
        
        if 'wordpress' in response.text.lower():
            techs.append("WordPress")
        if 'drupal' in response.text.lower():
            techs.append("Drupal")
        if 'joomla' in response.text.lower():
            techs.append("Joomla")
        
        if not techs:
            techs.append("Basic HTML/CSS/JS")
    except:
        techs.append("Unable to detect (site may block requests or this is an IP)")
    
    return techs

def get_subdomains(domain):
    """Get common subdomains (domains only)"""
    common_subdomains = ['www', 'mail', 'ftp', 'blog', 'shop', 'admin', 'api', 'dev', 'test']
    found = []
    
    for sub in common_subdomains:
        try:
            test_domain = f"{sub}.{domain}"
            socket.gethostbyname(test_domain)
            found.append(test_domain)
        except:
            pass
    
    return found

def reverse_dns_lookup(ip):
    """Get hostname from IP address"""
    try:
        hostname = socket.gethostbyaddr(ip)
        return hostname[0]
    except:
        return None

def get_open_ports(target):
    """Check common open ports (basic, non-intrusive)"""
    common_ports = [80, 443, 22, 21, 25, 3306, 5432, 3389, 8080, 8443]
    open_ports = []
    
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = ""
                if port == 80: service = "HTTP"
                elif port == 443: service = "HTTPS"
                elif port == 22: service = "SSH"
                elif port == 21: service = "FTP"
                elif port == 25: service = "SMTP"
                elif port == 3306: service = "MySQL"
                elif port == 5432: service = "PostgreSQL"
                elif port == 3389: service = "RDP"
                elif port == 8080: service = "HTTP-Alt"
                elif port == 8443: service = "HTTPS-Alt"
                else: service = "Unknown"
                open_ports.append({"port": port, "service": service})
            sock.close()
        except:
            pass
    
    return open_ports

def ping_host(target):
    """Perform ping test to target"""
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '4', target]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            if platform.system().lower() == 'windows':
                times = re.findall(r'time[=|<](\d+)ms', result.stdout)
            else:
                times = re.findall(r'time=(\d+\.?\d*) ms', result.stdout)
            
            return {
                "success": True,
                "output": result.stdout,
                "packets_sent": 4,
                "packets_received": len(times),
                "packet_loss": f"{((4 - len(times)) / 4 * 100):.0f}%",
                "times": times
            }
        else:
            return {
                "success": False,
                "output": result.stdout,
                "error": "Host unreachable"
            }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Ping timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def traceroute_host(target):
    """Perform traceroute to target"""
    try:
        if platform.system().lower() == 'windows':
            command = ['tracert', '-d', '-h', '15', target]
        else:
            command = ['traceroute', '-m', '15', target]
        
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            hops = []
            if platform.system().lower() == 'windows':
                for line in result.stdout.split('\n'):
                    match = re.match(r'\s*(\d+)\s+(\d+)\s+ms\s+(\d+)\s+ms\s+(\d+)\s+ms\s+(.+)', line)
                    if match:
                        hops.append({
                            "hop": int(match.group(1)),
                            "ip": match.group(5).strip(),
                            "times": [match.group(2), match.group(3), match.group(4)]
                        })
            else:
                for line in result.stdout.split('\n'):
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].isdigit():
                        hops.append({
                            "hop": int(parts[0]),
                            "ip": parts[1],
                            "times": parts[2:5] if len(parts) > 2 else []
                        })
            return {"success": True, "hops": hops, "output": result.stdout}
        else:
            return {"success": False, "error": "Traceroute failed", "output": result.stderr}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Traceroute timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.route('/lookup', methods=['POST'])
def lookup():
    try:
        data = request.get_json()
        target = data.get('target', '').strip().lower()
        
        target = target.replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]
        
        if not target:
            return jsonify({"error": "Please enter a domain name or IP address"}), 400
        
        target_type = "IP Address" if is_ip_address(target) else "Domain Name"
        
        info = {
            "target": target,
            "target_type": target_type,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        
        if not is_ip_address(target):
            info["dns_records"] = get_dns_records(target)
            info["whois"] = get_whois_info(target)
            info["ssl"] = get_ssl_info(target)
            info["technologies"] = get_technologies(target)
            info["subdomains"] = get_subdomains(target)
            info["open_ports"] = get_open_ports(target)
            
            try:
                ip = socket.gethostbyname(target)
                info["geolocation"] = get_geolocation(ip)
            except:
                info["geolocation"] = {"error": "Could not resolve domain"}
        else:
            info["reverse_dns"] = reverse_dns_lookup(target)
            info["ptr_records"] = get_ptr_record(target)
            info["whois"] = get_whois_info(target)
            info["geolocation"] = get_geolocation(target)
            info["open_ports"] = get_open_ports(target)
            info["technologies"] = ["Technology detection only available for domains"]
            info["subdomains"] = []
            info["ssl"] = None
            info["dns_records"] = {}
        
        info["ping"] = ping_host(target)
        info["traceroute"] = traceroute_host(target)
        
        return jsonify(info)
    
    except Exception as e:
        return jsonify({"error": f"Error: {str(e)}"}), 500

if __name__ == '__main__':
    print("=" * 50)
    print("NETWORK ANALYZER")
    print("=" * 50)
    print("Server running at: http://localhost:5000")
    print("Enter any domain name or IP address to analyze")
    print("Features: WHOIS, DNS, Geolocation, Ping, Traceroute")
    print("=" * 50)
    print("\nPress CTRL+C to stop\n")
    app.run(debug=True, port=5000)