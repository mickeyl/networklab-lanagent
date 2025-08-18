#!/usr/bin/env python3
"""
ARP Scanner Service
Exposes network scan results via JSON API and publishes via Zeroconf
"""

import json
import socket
import struct
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, List, Optional, Tuple

try:
    from zeroconf import ServiceInfo, Zeroconf
except ImportError:
    print("Please install zeroconf: pip3 install zeroconf")
    sys.exit(1)

try:
    import netifaces
except ImportError:
    print("Please install netifaces: pip3 install netifaces")
    sys.exit(1)

class ARPScanner:
    """Handles ARP scanning to discover devices on the local network"""
    
    def __init__(self):
        self.cache: List[Dict[str, str]] = []
        self.lock = threading.Lock()
        
    def get_local_network(self) -> Optional[Tuple[str, str]]:
        """Get the local network address and netmask"""
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    if 'addr' in addr and addr['addr'] != '127.0.0.1':
                        return addr['addr'], addr.get('netmask', '255.255.255.0')
        return None
    
    def get_local_machine_info(self) -> Optional[Dict[str, str]]:
        """Get the local machine's IP and MAC address"""
        for interface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(interface)
            
            # Skip loopback and virtual interfaces
            if interface.startswith(('lo', 'docker', 'br-', 'veth')):
                continue
                
            # Get IP address
            ip_addr = None
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    if 'addr' in addr and addr['addr'] != '127.0.0.1':
                        ip_addr = addr['addr']
                        break
            
            # Get MAC address
            mac_addr = None
            if netifaces.AF_LINK in addrs:
                for addr in addrs[netifaces.AF_LINK]:
                    if 'addr' in addr and self.is_valid_mac(addr['addr']):
                        mac_addr = addr['addr'].upper()
                        break
            
            # If we found both IP and MAC for this interface, return it
            if ip_addr and mac_addr:
                return {"ip": ip_addr, "mac": mac_addr}
        
        return None
    
    def ip_to_int(self, ip: str) -> int:
        """Convert IP address string to integer"""
        return struct.unpack('!I', socket.inet_aton(ip))[0]
    
    def int_to_ip(self, num: int) -> str:
        """Convert integer to IP address string"""
        return socket.inet_ntoa(struct.pack('!I', num))
    
    def get_network_range(self, ip: str, netmask: str) -> List[str]:
        """Calculate all IPs in the network range"""
        ip_int = self.ip_to_int(ip)
        mask_int = self.ip_to_int(netmask)
        network = ip_int & mask_int
        broadcast = network | (~mask_int & 0xFFFFFFFF)
        
        # Generate IPs excluding network and broadcast addresses
        ips = []
        for i in range(network + 1, broadcast):
            ips.append(self.int_to_ip(i))
        return ips
    
    def ping_ip(self, ip: str) -> bool:
        """Ping an IP to populate ARP cache"""
        try:
            # Use different ping command based on OS
            if sys.platform == "darwin":  # macOS
                cmd = ["ping", "-c", "1", "-W", "1", "-t", "1", ip]
            else:  # Linux
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            
            result = subprocess.run(cmd, 
                                  stdout=subprocess.DEVNULL, 
                                  stderr=subprocess.DEVNULL,
                                  timeout=2)
            return result.returncode == 0
        except:
            return False
    
    def parse_arp_output(self, output: str) -> List[Dict[str, str]]:
        """Parse ARP/ip neigh command output"""
        devices = []
        lines = output.strip().split('\n')
        
        for line in lines:
            if sys.platform == "darwin":  # macOS
                # Example: gateway (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
                parts = line.split()
                if len(parts) >= 4 and parts[2] == "at":
                    ip = parts[1].strip('()')
                    mac = parts[3]
                    if mac != "(incomplete)" and self.is_valid_mac(mac):
                        devices.append({"ip": ip, "mac": mac.upper()})
            else:  # Linux ip neigh output
                # Example: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE
                parts = line.split()
                if len(parts) >= 5 and "lladdr" in parts:
                    ip = parts[0]
                    lladdr_idx = parts.index("lladdr")
                    if lladdr_idx + 1 < len(parts):
                        mac = parts[lladdr_idx + 1]
                        if self.is_valid_mac(mac):
                            devices.append({"ip": ip, "mac": mac.upper()})
        
        return devices
    
    def is_valid_mac(self, mac: str) -> bool:
        """Validate MAC address format"""
        if mac == "(incomplete)" or mac == "<incomplete>":
            return False
        parts = mac.split(":")
        if len(parts) != 6:
            return False
        for part in parts:
            if len(part) != 2:
                return False
            try:
                int(part, 16)
            except ValueError:
                return False
        return True
    
    def scan(self) -> List[Dict[str, str]]:
        """Perform ARP scan of the local network"""
        network_info = self.get_local_network()
        if not network_info:
            return []
        
        local_ip, netmask = network_info
        ips = self.get_network_range(local_ip, netmask)
        
        # Limit scan to first 254 hosts for performance
        ips = ips[:254]
        
        # Ping IPs in parallel to populate ARP cache
        threads = []
        for ip in ips:
            t = threading.Thread(target=self.ping_ip, args=(ip,))
            t.daemon = True
            t.start()
            threads.append(t)
            
            # Limit concurrent threads
            if len(threads) >= 50:
                for t in threads:
                    t.join(timeout=0.1)
                threads = []
        
        # Wait for remaining threads
        for t in threads:
            t.join(timeout=0.1)
        
        # Get ARP table
        try:
            if sys.platform == "darwin":  # macOS
                result = subprocess.run(["arp", "-a"], 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=5)
            else:  # Linux - use ip neigh instead of arp (no root required)
                result = subprocess.run(["ip", "neigh", "show"], 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=5)
            
            if result.returncode == 0:
                devices = self.parse_arp_output(result.stdout)
                
                # Add local machine to the results
                local_info = self.get_local_machine_info()
                if local_info:
                    # Check if local machine is already in the results (shouldn't be, but just in case)
                    local_found = any(device['ip'] == local_info['ip'] for device in devices)
                    if not local_found:
                        devices.append(local_info)
                
                with self.lock:
                    self.cache = devices
                return devices
        except Exception as e:
            print(f"Error reading ARP table: {e}")
            
        return []
    
    def get_cached_results(self) -> List[Dict[str, str]]:
        """Get cached scan results"""
        with self.lock:
            return self.cache.copy()

class ScanHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the scan API"""
    
    scanner: ARPScanner = None
    
    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/scan':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            results = self.scanner.get_cached_results()
            response = {
                "status": "success",
                "count": len(results),
                "devices": results
            }
            self.wfile.write(json.dumps(response, indent=2).encode())
        else:
            self.send_error(404, "Endpoint not found")
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass

class ARPScannerService:
    """Main service class that manages HTTP server and Zeroconf"""
    
    def __init__(self, port: int = 0):
        self.scanner = ARPScanner()
        self.port = port
        self.server = None
        self.zeroconf = None
        self.service_info = None
        
    def find_free_port(self) -> int:
        """Find an available TCP port"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port
    
    def start_http_server(self):
        """Start the HTTP server"""
        if self.port == 0:
            self.port = self.find_free_port()
        
        ScanHandler.scanner = self.scanner
        self.server = HTTPServer(('0.0.0.0', self.port), ScanHandler)
        
        print(f"HTTP server started on port {self.port}")
        print(f"Access the API at: http://0.0.0.0:{self.port}/scan")
        
        # Start server in a separate thread
        server_thread = threading.Thread(target=self.server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
    
    def register_zeroconf(self):
        """Register the service with Zeroconf"""
        self.zeroconf = Zeroconf()
        
        # Get actual network IP (not localhost)
        network_info = self.scanner.get_local_network()
        if network_info:
            local_ip = network_info[0]
        else:
            # Fallback to hostname lookup
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
        
        # Create service info with cleaner name (no spaces to avoid escaping)
        service_type = "_lanagent._tcp.local."
        hostname = socket.gethostname().split('.')[0]  # Just the short hostname
        service_name = f"lanagent-{hostname}-{self.port}"
        
        self.service_info = ServiceInfo(
            service_type,
            f"{service_name}.{service_type}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties={
                "version": "1.0",
                "path": "/scan",
                "description": "LAN Agent network scanner with JSON API",
                "hostname": hostname
            }
        )
        
        self.zeroconf.register_service(self.service_info)
        print(f"Service registered via Zeroconf as: {service_name}")
        print(f"Service type: {service_type}")
        print(f"IP address: {local_ip}")
    
    def periodic_scan(self):
        """Perform periodic network scans"""
        while True:
            print("Performing network scan...")
            devices = self.scanner.scan()
            print(f"Found {len(devices)} devices")
            time.sleep(60)  # Scan every minute
    
    def run(self):
        """Main service loop"""
        try:
            # Start HTTP server
            self.start_http_server()
            
            # Register with Zeroconf
            self.register_zeroconf()
            
            # Do initial scan
            print("Performing initial scan...")
            devices = self.scanner.scan()
            print(f"Initial scan found {len(devices)} devices")
            
            # Start periodic scanning
            scan_thread = threading.Thread(target=self.periodic_scan)
            scan_thread.daemon = True
            scan_thread.start()
            
            # Keep running
            print("\nService is running. Press Ctrl+C to stop.")
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            if self.server:
                self.server.shutdown()
            if self.zeroconf and self.service_info:
                self.zeroconf.unregister_service(self.service_info)
                self.zeroconf.close()