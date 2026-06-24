#!/usr/bin/env python3
"""
ARP Scanner Service
Exposes network scan results via JSON API and publishes via Zeroconf
"""

import ipaddress
import json
import logging
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from .presence import PresenceMonitor

log = logging.getLogger("lanagent")

try:
    from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf
except ImportError:
    print("Please install zeroconf: pip3 install zeroconf")
    sys.exit(1)

try:
    import netifaces
except ImportError:
    print("Please install netifaces: pip3 install netifaces")
    sys.exit(1)


class BonjourPresenceBrowser:
    """Collects IPv4 addresses seen through Bonjour/mDNS service browsing."""

    SERVICE_TYPES = (
        "_device-info._tcp.local.",
        "_rfb._tcp.local.",
        "_smb._tcp.local.",
        "_ssh._tcp.local.",
        "_afpovertcp._tcp.local.",
        "_companion-link._tcp.local.",
        "_airplay._tcp.local.",
        "_raop._tcp.local.",
        "_homekit._tcp.local.",
        "_hap._tcp.local.",
        "_http._tcp.local.",
        "_ipp._tcp.local.",
        "_printer._tcp.local.",
        "_googlecast._tcp.local.",
        "_hue._tcp.local.",
        "_adisk._tcp.local.",
        "_sleep-proxy._udp.local.",
    )

    def __init__(self, zeroconf: Zeroconf, service_types: Optional[Tuple[str, ...]] = None):
        self.zeroconf = zeroconf
        self.service_types = service_types or self.SERVICE_TYPES
        self.instances: Dict[Tuple[str, str], List[Dict[str, object]]] = {}
        self.browsers: List[ServiceBrowser] = []
        self.errors: List[str] = []
        self.lock = threading.RLock()

        for service_type in self.service_types:
            try:
                self.browsers.append(ServiceBrowser(self.zeroconf, service_type, self))
            except Exception as e:
                self._record_error(f"{service_type}: {e}")

    def add_service(self, zeroconf: Zeroconf, service_type: str, name: str) -> None:
        self._refresh_service(zeroconf, service_type, name)

    def update_service(self, zeroconf: Zeroconf, service_type: str, name: str) -> None:
        self._refresh_service(zeroconf, service_type, name)

    def remove_service(self, zeroconf: Zeroconf, service_type: str, name: str) -> None:
        with self.lock:
            self.instances.pop((service_type, name), None)

    def _refresh_service(self, zeroconf: Zeroconf, service_type: str, name: str) -> None:
        try:
            info = zeroconf.get_service_info(service_type, name, timeout=1000)
        except Exception as e:
            self._record_error(f"{service_type} {name}: {e}")
            return
        if not info:
            return

        devices = []
        hostname = str(getattr(info, "server", "") or name).rstrip(".")
        for address in self._parsed_ipv4_addresses(info):
            devices.append({
                "ip": address,
                "mac": "",
                "hostname": hostname,
                "source": "bonjour",
            })

        with self.lock:
            if devices:
                self.instances[(service_type, name)] = devices
            else:
                self.instances.pop((service_type, name), None)

    def _parsed_ipv4_addresses(self, info: ServiceInfo) -> List[str]:
        addresses: List[str] = []
        try:
            parsed = info.parsed_addresses()
        except Exception:
            parsed = []
            for raw in getattr(info, "addresses", []) or []:
                if len(raw) == 4:
                    try:
                        parsed.append(socket.inet_ntoa(raw))
                    except OSError:
                        pass

        for address in parsed:
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                continue
            if not isinstance(ip, ipaddress.IPv4Address):
                continue
            if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
                continue
            addresses.append(str(ip))
        return sorted(set(addresses))

    def snapshot(self) -> List[Dict[str, object]]:
        with self.lock:
            by_ip: Dict[str, Dict[str, object]] = {}
            for devices in self.instances.values():
                for device in devices:
                    ip = str(device.get("ip", ""))
                    if ip:
                        by_ip[ip] = device.copy()
            return sorted(by_ip.values(), key=lambda device: str(device.get("ip", "")))

    def diagnostics(self) -> Dict[str, object]:
        with self.lock:
            return {
                "enabled": True,
                "serviceTypes": len(self.service_types),
                "activeServices": len(self.instances),
                "devices": len(self.snapshot()),
                "errors": self.errors[-10:],
            }

    def close(self) -> None:
        for browser in self.browsers:
            cancel = getattr(browser, "cancel", None)
            if callable(cancel):
                try:
                    cancel()
                except Exception:
                    pass

    def _record_error(self, message: str) -> None:
        log.debug("Bonjour browser error: %s", message)
        with self.lock:
            self.errors.append(message)
            self.errors = self.errors[-50:]


class ARPScanner:
    """Handles ARP scanning to discover devices on the local network"""
    
    def __init__(self):
        self.cache: Dict[str, Dict[str, object]] = {}
        self.last_scan: Optional[Dict[str, object]] = None
        self.last_observed_devices: List[Dict[str, object]] = []
        self.lock = threading.Lock()
        self.cache_ttl = 30 * 60
        
    def get_local_network(self) -> Optional[Tuple[str, str, str]]:
        """Get the local network address and netmask from the default-route interface.

        Anchoring on the default route avoids picking up docker/bridge/VPN
        interfaces that happen to sort earlier than the real LAN NIC.
        """
        default_iface = None
        try:
            gws = netifaces.gateways()
            default = gws.get('default', {}).get(netifaces.AF_INET)
            if default:
                default_iface = default[1]
        except Exception as e:
            log.warning("Could not determine default route: %s", e)

        candidates = [default_iface] if default_iface else []
        for iface in netifaces.interfaces():
            if iface == default_iface:
                continue
            if iface.startswith(('lo', 'docker', 'br-', 'veth', 'tun', 'tap', 'wg')):
                continue
            candidates.append(iface)

        for iface in candidates:
            if not iface:
                continue
            try:
                addrs = netifaces.ifaddresses(iface)
            except ValueError:
                continue
            for addr in addrs.get(netifaces.AF_INET, []):
                ip = addr.get('addr')
                if ip and ip != '127.0.0.1':
                    return ip, addr.get('netmask', '255.255.255.0'), iface
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
        """Ping an IP to populate ARP cache."""
        if sys.platform == "darwin":
            cmd = ["ping", "-c", "1", "-W", "1", "-t", "1", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]
        try:
            result = subprocess.run(cmd,
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL,
                                  timeout=2)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    def arp_probe_device(self, ip: str, interface: Optional[str]) -> Optional[Dict[str, str]]:
        """Actively probe one IPv4 address for a MAC address.

        Prefer arping when available because ICMP can be filtered while ARP is
        still answered on the local link. Fall back to ping so the agent remains
        useful without extra privileges or packages.
        """
        arping = shutil.which("arping")
        if arping:
            cmd = [arping, "-c", "1", "-w", "1"]
            if interface:
                cmd.extend(["-I", interface])
            cmd.append(ip)
            try:
                result = subprocess.run(cmd,
                                      capture_output=True,
                                      text=True,
                                      timeout=2)
                mac = self.parse_arping_mac(result.stdout)
                if mac:
                    return {"ip": ip, "mac": mac}
            except (subprocess.TimeoutExpired, OSError):
                pass

        if self.ping_ip(ip):
            return {"ip": ip, "mac": ""}

        return None

    def arp_probe_ip(self, ip: str, interface: Optional[str]) -> bool:
        """Actively probe one IPv4 address, returning whether it answered."""
        return self.arp_probe_device(ip, interface) is not None

    def parse_arping_mac(self, output: str) -> Optional[str]:
        """Extract a MAC address from common arping output formats."""
        for match in re.finditer(r"\[([0-9A-Fa-f:]{11,17})\]", output):
            mac = self.normalize_mac(match.group(1))
            if mac:
                return mac

        for match in re.finditer(r"\b([0-9A-Fa-f]{1,2}(?::[0-9A-Fa-f]{1,2}){5})\b", output):
            mac = self.normalize_mac(match.group(1))
            if mac:
                return mac

        return None
    
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
                    mac = self.normalize_mac(parts[3])
                    if mac:
                        devices.append({"ip": ip, "mac": mac})
            else:  # Linux ip neigh output
                # Example: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE
                parts = line.split()
                if len(parts) >= 5 and "lladdr" in parts:
                    ip = parts[0]
                    lladdr_idx = parts.index("lladdr")
                    if lladdr_idx + 1 < len(parts):
                        mac = self.normalize_mac(parts[lladdr_idx + 1])
                        if mac:
                            devices.append({"ip": ip, "mac": mac})
        
        return devices

    def normalize_mac(self, mac: str) -> Optional[str]:
        """Normalize MAC addresses, accepting macOS ARP's non-padded octets."""
        if mac == "(incomplete)" or mac == "<incomplete>":
            return None

        parts = mac.split(":")
        if len(parts) != 6:
            return None

        normalized = []
        for part in parts:
            if not 1 <= len(part) <= 2:
                return None
            try:
                value = int(part, 16)
            except ValueError:
                return None
            normalized.append(f"{value:02X}")

        return ":".join(normalized)

    def is_valid_mac(self, mac: str) -> bool:
        """Validate MAC address format"""
        return self.normalize_mac(mac) is not None

    def read_neighbor_table(self) -> List[Dict[str, str]]:
        """Read the operating system's neighbor/ARP table."""
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

        if result.returncode != 0:
            return []

        return self.parse_arp_output(result.stdout)

    def remember_devices(self, devices: List[Dict[str, str]], source: str) -> None:
        """Merge scan results into the TTL cache."""
        now = time.time()
        with self.lock:
            for device in devices:
                cached = self.cache.get(device["ip"], {})
                self.cache[device["ip"]] = {
                    "ip": device["ip"],
                    "mac": device["mac"],
                    "firstSeen": cached.get("firstSeen", now),
                    "lastSeen": now,
                    "source": source,
                }
            self.expire_cache_locked(now)

    def dedupe_devices(self, devices: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Collapse duplicate observations from neighbor table and active probes."""
        by_key: Dict[str, Dict[str, str]] = {}
        for device in devices:
            ip = device.get("ip", "")
            mac = device.get("mac", "")
            key = mac or ip
            if not key:
                continue
            existing = by_key.get(key)
            if existing and existing.get("mac"):
                continue
            by_key[key] = {"ip": ip, "mac": mac}
        return list(by_key.values())

    def expire_cache_locked(self, now: Optional[float] = None) -> None:
        now = now or time.time()
        expired = [
            ip for ip, device in self.cache.items()
            if now - float(device.get("lastSeen", 0)) > self.cache_ttl
        ]
        for ip in expired:
            self.cache.pop(ip, None)

    def scan(self) -> List[Dict[str, object]]:
        """Perform ARP scan of the local network"""
        started = time.time()
        network_info = self.get_local_network()
        if not network_info:
            with self.lock:
                self.last_observed_devices = []
            return []

        local_ip, netmask, interface = network_info
        all_ips = self.get_network_range(local_ip, netmask)

        # Cap scan size; warn so users know when they're on a larger subnet
        # than we cover (typical home /24 fits in 254).
        SCAN_CAP = 254
        if len(all_ips) > SCAN_CAP:
            log.warning("Network %s/%s has %d hosts; scanning first %d only",
                        local_ip, netmask, len(all_ips), SCAN_CAP)
        ips = all_ips[:SCAN_CAP]

        # Parallel pings with real bounded concurrency. shutdown(wait=True)
        # ensures the ARP cache has had a chance to populate before we read it.
        with ThreadPoolExecutor(max_workers=64, thread_name_prefix="probe") as pool:
            probe_results = list(pool.map(lambda ip: self.arp_probe_device(ip, interface), ips))

        # Get ARP table
        try:
            probed_devices = [
                device for device in probe_results
                if device and device.get("mac")
            ]
            devices = self.read_neighbor_table() + probed_devices

            # Add local machine to the results
            local_info = self.get_local_machine_info()
            if local_info:
                local_found = any(device['ip'] == local_info['ip'] for device in devices)
                if not local_found:
                    devices.append(local_info)

            devices = self.dedupe_devices(devices)
            self.remember_devices(devices, "scan")
            with self.lock:
                self.last_observed_devices = [
                    {
                        "ip": device["ip"],
                        "mac": device["mac"],
                        "source": "scan",
                    }
                    for device in devices
                ]
                self.last_scan = {
                    "timestamp": time.time(),
                    "duration": round(time.time() - started, 3),
                    "interface": interface,
                    "localIP": local_ip,
                    "netmask": netmask,
                    "probed": len(ips),
                    "probeReplies": sum(1 for result in probe_results if result),
                    "neighbors": len(devices),
                    "cacheSize": len(self.cache),
                    "method": "arping+neighbor" if shutil.which("arping") else "ping+neighbor",
                }
            return self.get_cached_results()
        except Exception as e:
            print(f"Error reading ARP table: {e}")
            with self.lock:
                self.last_observed_devices = []
            
        return []

    def lookup(self, ip: str) -> Optional[Dict[str, object]]:
        """Resolve a single IP address, probing before reading the cache."""
        try:
            socket.inet_aton(ip)
        except OSError:
            return None

        network_info = self.get_local_network()
        interface = network_info[2] if network_info else None
        probed_device = self.arp_probe_device(ip, interface)

        try:
            devices = [device for device in self.read_neighbor_table() if device["ip"] == ip]
        except Exception as e:
            log.warning("Failed reading neighbor table for lookup %s: %s", ip, e)
            devices = []

        if probed_device and probed_device.get("mac"):
            devices.append(probed_device)

        if devices:
            self.remember_devices(devices, "lookup")

        with self.lock:
            self.expire_cache_locked()
            return self.cache.get(ip)
    
    def get_cached_results(self) -> List[Dict[str, object]]:
        """Get cached scan results"""
        with self.lock:
            self.expire_cache_locked()
            return sorted(
                (device.copy() for device in self.cache.values()),
                key=lambda device: str(device["ip"])
            )

    def get_last_observed_results(self) -> List[Dict[str, object]]:
        """Get the devices observed by the latest probe, without TTL cache smoothing."""
        with self.lock:
            return [device.copy() for device in self.last_observed_devices]

    def diagnostics(self) -> Dict[str, object]:
        """Return service diagnostics useful to clients and troubleshooting."""
        network_info = self.get_local_network()
        with self.lock:
            self.expire_cache_locked()
            return {
                "network": {
                    "ip": network_info[0] if network_info else None,
                    "netmask": network_info[1] if network_info else None,
                    "interface": network_info[2] if network_info else None,
                },
                "cacheSize": len(self.cache),
                "cacheTTL": self.cache_ttl,
                "lastScan": self.last_scan,
                "hasArping": shutil.which("arping") is not None,
            }

class ScanHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the scan API"""
    
    scanner: ARPScanner = None
    service = None
    
    def do_GET(self):
        """Handle GET requests"""
        parsed = urlparse(self.path)

        if parsed.path == '/scan':
            query = parse_qs(parsed.query)
            force = query.get("force", ["0"])[0].lower() in ("1", "true", "yes")
            results = self.service.scan_once() if force else self.scanner.get_cached_results()
            diagnostics = self.service.diagnostics()

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            response = {
                "status": "success",
                "count": len(results),
                "devices": results,
                "diagnostics": diagnostics,
            }
            self.wfile.write(json.dumps(response, indent=2).encode())
        elif parsed.path == '/presence':
            query = parse_qs(parsed.query)
            include_absent = query.get("includeAbsent", ["0"])[0].lower() in ("1", "true", "yes")
            results = self.service.presence.snapshot(include_absent=include_absent)

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            response = {
                "status": "success",
                "count": len(results),
                "devices": results,
                "diagnostics": self.service.diagnostics(),
            }
            self.wfile.write(json.dumps(response, indent=2).encode())
        elif parsed.path == '/events':
            query = parse_qs(parsed.query)
            try:
                since = int(query.get("since", ["0"])[0])
            except ValueError:
                since = 0
            try:
                limit = int(query.get("limit", ["200"])[0])
            except ValueError:
                limit = 200
            events = self.service.presence.events_since(since=since, limit=limit)

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            response = {
                "status": "success",
                "count": len(events),
                "events": events,
                "diagnostics": self.service.diagnostics(),
            }
            self.wfile.write(json.dumps(response, indent=2).encode())
        elif parsed.path == '/lookup':
            query = parse_qs(parsed.query)
            ip = query.get("ip", [""])[0]
            result = self.scanner.lookup(ip) if ip else None

            self.send_response(200 if result else 404)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            response = {
                "status": "success" if result else "not_found",
                "device": result,
                "diagnostics": self.service.diagnostics(),
            }
            self.wfile.write(json.dumps(response, indent=2).encode())
        elif parsed.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            response = {
                "status": "ok",
                "diagnostics": self.service.diagnostics(),
            }
            self.wfile.write(json.dumps(response, indent=2).encode())
        else:
            self.send_error(404, "Endpoint not found")
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass

class ARPScannerService:
    """Main service class that manages HTTP server and Zeroconf"""
    
    def __init__(
        self,
        port: int = 0,
        scan_interval: int = 60,
        presence_grace: float = 1800,
        sleep_grace: float = 12 * 3600,
        miss_count: int = 3,
        min_probe_completeness: float = 0.35,
        resume_gap: float = 300,
    ):
        self.scanner = ARPScanner()
        self.presence = PresenceMonitor(
            grace=presence_grace,
            sleep_grace=sleep_grace,
            miss_count=miss_count,
            min_probe_completeness=min_probe_completeness,
            resume_gap=resume_gap,
            cadence=scan_interval,
        )
        self.port = port
        self.scan_interval = scan_interval
        self.server = None
        self.zeroconf = None
        self.service_info = None
        self.bonjour: Optional[BonjourPresenceBrowser] = None
        
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
        ScanHandler.service = self
        self.server = ThreadingHTTPServer(('0.0.0.0', self.port), ScanHandler)
        
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
                "presencePath": "/presence",
                "eventsPath": "/events",
                "description": "LAN Agent network scanner with JSON API",
                "hostname": hostname
            }
        )
        
        self.zeroconf.register_service(self.service_info)
        self.bonjour = BonjourPresenceBrowser(self.zeroconf)
        print(f"Service registered via Zeroconf as: {service_name}")
        print(f"Service type: {service_type}")
        print(f"IP address: {local_ip}")
        print(f"Browsing {len(self.bonjour.service_types)} Bonjour types for presence")

    def scan_once(self) -> List[Dict[str, object]]:
        """Run one scan cycle and feed ARP plus Bonjour observations into presence state."""
        results = self.scanner.scan()
        observed = self.scanner.get_last_observed_results()
        if self.bonjour:
            observed.extend(self.bonjour.snapshot())
        self.presence.update(observed)
        return results

    def diagnostics(self) -> Dict[str, object]:
        return {
            "scanner": self.scanner.diagnostics(),
            "presence": self.presence.diagnostics(),
            "bonjour": self.bonjour.diagnostics() if self.bonjour else {"enabled": False},
            "scanInterval": self.scan_interval,
        }
    
    def periodic_scan(self):
        """Perform periodic network scans.

        Each iteration is wrapped so a transient failure (e.g. ``ip neigh``
        missing, DNS hang) does not kill the worker thread and freeze the
        cache forever.
        """
        while True:
            try:
                log.info("Performing network scan...")
                devices = self.scan_once()
                log.info("Found %d devices", len(devices))
            except Exception:
                log.exception("Periodic scan failed; keeping previous cache")
            time.sleep(self.scan_interval)
    
    def run(self):
        """Main service loop"""
        if not logging.getLogger().handlers:
            logging.basicConfig(
                level=logging.INFO,
                format="%(asctime)s %(levelname)s %(name)s: %(message)s",
            )
        try:
            # Start HTTP server
            self.start_http_server()
            
            # Register with Zeroconf
            self.register_zeroconf()
            
            # Do initial scan
            print("Performing initial scan...")
            devices = self.scan_once()
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
            if self.bonjour:
                self.bonjour.close()
            if self.zeroconf and self.service_info:
                self.zeroconf.unregister_service(self.service_info)
                self.zeroconf.close()
