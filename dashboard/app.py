import os
import sqlite3
import concurrent.futures
import ipaddress
import subprocess
import re
from flask import Flask, render_template, jsonify, request
import socket
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup

app = Flask(__name__)
mac_lookup = MacLookup()

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'database')
DB_PATH = os.path.join(DB_DIR, 'network_data.db')

def init_db():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY,
            status TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

try:
    mac_lookup.update_vendors()
except Exception:
    pass

def get_vendor(mac):
    import urllib.request
    try:
        first_octet = int(mac.replace('-', ':').split(':')[0], 16)
        if first_octet & 2:
            return "RANDOMIZED (PRIVACY MAC)"
    except Exception:
        pass

    try:
        return mac_lookup.lookup(mac)
    except Exception:
        pass

    try:
        url = f"https://api.macvendors.com/{mac}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=1.5) as response:
            result = response.read().decode('utf-8').strip()
            if result and "error" not in result.lower() and "not found" not in result.lower():
                return result
    except Exception:
        pass
        
    return "UNKNOWN"

def get_device_status(mac):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT status FROM devices WHERE mac = ?", (mac,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else "unknown"

def infer_device_type(vendor, hostname):
    """Infers the type of device based on its MAC vendor and Hostname."""
    v_low = vendor.lower()
    
    # Heuristics for IoT, Mobiles, Consoles, PCs, and Routers
    if any(x in v_low for x in ['espressif', 'tuya', 'philips', 'wyze', 'xiaomi', 'liteon', 'shenzhen']):
        return {"icon": "fas fa-lightbulb", "label": "IOT / SMART HOME"}
    elif any(x in v_low for x in ['apple', 'samsung', 'google', 'oneplus', 'motorola', 'huawei']):
        return {"icon": "fas fa-mobile-alt", "label": "MOBILE / TABLET"}
    elif any(x in v_low for x in ['nintendo', 'sony interactive', 'microsoft']):
        return {"icon": "fas fa-gamepad", "label": "GAMING CONSOLE"}
    elif any(x in v_low for x in ['amazon', 'roku']):
        return {"icon": "fas fa-tv", "label": "SMART TV / MEDIA"}
    elif any(x in v_low for x in ['intel', 'dell', 'lenovo', 'asustek', 'acer', 'gigabyte', 'micro-star']):
        return {"icon": "fas fa-laptop", "label": "PC / LAPTOP"}
    elif any(x in v_low for x in ['cisco', 'netgear', 'tp-link', 'ubiquiti', 'd-link', 'aruba']):
        return {"icon": "fas fa-network-wired", "label": "ROUTER / SWITCH"}
    elif 'randomized' in v_low:
        return {"icon": "fas fa-user-secret", "label": "HIDDEN DEVICE"}
        
    return {"icon": "fas fa-microchip", "label": "NETWORK DEVICE"}

def get_ping_latency(ip):
    """Measures network latency to the device in ms."""
    try:
        # Send 1 ping with a 500ms timeout
        out = subprocess.check_output(["ping", "-n", "1", "-w", "500", ip], universal_newlines=True, stderr=subprocess.STDOUT)
        match = re.search(r'[=<>](\d+)\s*ms', out, re.IGNORECASE)
        if match:
            return float(match.group(1))
        return -1.0
    except Exception:
        return -1.0

def scan_ports(ip):
    """Mini X-Ray port scanner for common services."""
    open_services = []
    ports = {
        22: ("fas fa-terminal", "SSH"),
        80: ("fas fa-globe", "HTTP"),
        443: ("fas fa-lock", "HTTPS"),
        445: ("fas fa-folder-open", "SMB"),
        3389: ("fas fa-desktop", "RDP")
    }
    for port, (icon, name) in ports.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2) # Very short timeout to keep scans fast
            if s.connect_ex((ip, port)) == 0:
                open_services.append({"port": port, "icon": icon, "name": name})
            s.close()
        except Exception:
            pass
    return open_services

def get_local_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        octets = local_ip.split('.')
        return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
    except Exception:
        return "192.168.1.0/24"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/device/status', methods=['POST'])
def update_status():
    data = request.json
    mac = data.get('mac')
    status = data.get('status')
    
    if not mac or status not in ['trusted', 'rogue', 'unknown']:
        return jsonify({"error": "Invalid data provided"}), 400
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("REPLACE INTO devices (mac, status) VALUES (?, ?)", (mac, status))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route('/api/scan')
def api_scan():
    ip_range = get_local_subnet()
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request

    try:
        result = srp(packet, timeout=5, verbose=0)[0]
        
        temp_devices = []
        for sent, received in result:
            temp_devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc
            })
            
        def enrich_device_info(dev):
            mac = dev["mac"]
            ip = dev["ip"]
            dev["vendor"] = get_vendor(mac)
            dev["status"] = get_device_status(mac)
            try:
                dev["hostname"] = socket.gethostbyaddr(ip)[0]
            except Exception:
                dev["hostname"] = "Unknown Device"
            
            # Use the inference engine to add Smart Tags
            dev["device_type"] = infer_device_type(dev["vendor"], dev["hostname"])
            
            # Perform X-Ray Service Discovery
            dev["open_services"] = scan_ports(ip)
            
            # Measure Latency (Network Health)
            dev["latency"] = get_ping_latency(ip)
            return dev
            
        devices = []
        if temp_devices:
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                results = executor.map(enrich_device_info, temp_devices)
                devices = list(results)
                
        devices.sort(key=lambda d: ipaddress.IPv4Address(d["ip"]))
        
        return jsonify({"status": "success", "subnet": ip_range, "devices": devices})
    except PermissionError:
        return jsonify({
            "status": "error", 
            "message": "Administrator privileges required to send raw packets."
        }), 403
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
