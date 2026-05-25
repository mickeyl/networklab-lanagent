# LANAgent

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/downloads/)

LANAgent is a lightweight network discovery service that scans your local network for connected devices and exposes the results via a JSON API. It also advertises itself using Zeroconf/mDNS for automatic discovery.

## Features

- 🔍 **Network Discovery**: Automatically discovers devices on your local network using ARP
- 🌐 **JSON API**: HTTP endpoints for cached scans, forced scans, targeted MAC lookups, and health diagnostics
- 📡 **Zeroconf/mDNS**: Automatic service discovery via Bonjour/Avahi
- 🔄 **Periodic Scanning**: Continuously updates device list every 60 seconds
- 🖥️ **Cross-Platform**: Works on macOS and Linux
- 🚀 **Lightweight**: Minimal dependencies and resource usage

## Installation

### Using pipx (Recommended)

Install directly from GitHub using pipx for isolated environment:

```bash
pipx install git+https://github.com/mickeyl/networklab-lanagent
```

### From PyPI (when published)

```bash
pip install lanagent
```

### From Source

```bash
git clone https://github.com/mickeyl/networklab-lanagent.git
cd lanagent
pip install -e .
```

### Dependencies

- Python 3.7+
- `zeroconf` - For mDNS/Bonjour service discovery
- `netifaces` - For network interface enumeration

## Usage

### Command Line

Start the service:

```bash
lanagent
```

Or run with a specific port:

```bash
lanagent --port 8080
```

The service will:
1. Start an HTTP server (on a random port if not specified)
2. Register itself via Zeroconf as `_lanagent._tcp.local.`
3. Perform an initial network scan
4. Continue scanning every 60 seconds

### API Endpoints

Once running, access the scan results:

```bash
curl http://localhost:<port>/scan
```

Force a fresh scan:

```bash
curl http://localhost:<port>/scan?force=1
```

Resolve one IP address immediately:

```bash
curl "http://localhost:<port>/lookup?ip=192.168.1.100"
```

Inspect the agent health and scan diagnostics:

```bash
curl http://localhost:<port>/health
```

Response format:
```json
{
  "status": "success",
  "count": 5,
  "devices": [
    {
      "ip": "192.168.1.1",
      "mac": "AA:BB:CC:DD:EE:FF"
    },
    {
      "ip": "192.168.1.100",
      "mac": "11:22:33:44:55:66",
      "firstSeen": 1779700123.0,
      "lastSeen": 1779700123.0,
      "source": "scan"
    }
  ],
  "diagnostics": {
    "network": {
      "ip": "192.168.1.20",
      "netmask": "255.255.255.0",
      "interface": "eth0"
    },
    "cacheSize": 5,
    "cacheTTL": 1800,
    "lastScan": {
      "duration": 2.431,
      "probed": 254,
      "probeReplies": 42,
      "neighbors": 5,
      "method": "arping+neighbor"
    },
    "hasArping": true
  }
}
```

### Python API

You can also use LANAgent as a Python library:

```python
from lanagent import ARPScanner

scanner = ARPScanner()
devices = scanner.scan()

for device in devices:
    print(f"Found device: {device['ip']} ({device['mac']})")
```

## Service Discovery

LANAgent advertises itself via Zeroconf/mDNS. You can discover running instances using:

### macOS
```bash
dns-sd -B _lanagent._tcp
```

### Linux (with Avahi)
```bash
avahi-browse -t _lanagent._tcp
```

### Python
```python
from zeroconf import Zeroconf, ServiceBrowser

class Listener:
    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            print(f"Found LANAgent at {info.parsed_addresses()[0]}:{info.port}")

zeroconf = Zeroconf()
browser = ServiceBrowser(zeroconf, "_lanagent._tcp.local.", Listener())
```

## How It Works

1. **Network Detection**: Identifies the local network interface and subnet
2. **ARP Population**: Uses `arping` when available, falling back to ICMP ping, to populate the neighbor cache
3. **ARP Table Reading**: 
   - On macOS: Uses `arp -a` command
   - On Linux: Uses `ip neigh show` command
4. **Targeted Lookup**: `/lookup?ip=...` actively probes one host before reading the neighbor cache
5. **Result Caching**: Maintains a thread-safe TTL cache of discovered devices so transient weak scans do not erase recent MAC mappings
6. **API Serving**: Exposes results via HTTP with CORS enabled for web access

## Platform Support

- **macOS**: Full support using native `arp` and `ping` commands
- **Linux**: Full support using `ip neigh` and `arping` when installed, falling back to `ping`
- **Windows**: Not currently supported (PRs welcome!)

## Security Considerations

- The service binds to `0.0.0.0` by default, making it accessible from any network interface
- No authentication is required to access the `/scan` endpoint
- Only performs read-only network discovery (no active exploitation)
- For production use, consider:
  - Binding to localhost only (`127.0.0.1`)
  - Adding authentication
  - Using HTTPS
  - Implementing rate limiting

## Development

### Setup Development Environment

```bash
git clone https://github.com/yourusername/lanagent.git
cd lanagent
pip install -e .
pip install -r requirements-dev.txt  # If you have dev dependencies
```

### Running Tests

```bash
python -m pytest tests/
```

### Building Package

```bash
python -m build
```

## Running Under systemd

The repository ships with a hardened systemd unit that runs LANAgent as the dedicated `lanagent` user.

1. Install the Python package (e.g. `pip install .` or via the Debian package described below).
2. Deploy the service unit and default configuration:
   ```bash
   sudo ./scripts/install-systemd.sh
   ```
3. Adjust `/etc/lanagent/lanagent.conf` if you need to pin the HTTP port (defaults to automatic port selection).
4. Check the status via `systemctl status lanagent` and view logs via `journalctl -u lanagent`.

The unit file lives in `systemd/lanagent.service` if you want to customize hardening directives or add more environment variables.
It grants `CAP_NET_RAW` so `arping` can send raw ARP probes while the service continues to run as the dedicated `lanagent` user.

## Building a Debian Package

Basic packaging metadata lives in the `debian/` directory so you can build a `.deb` directly from this repository.

1. Install the build toolchain and dependencies:
   ```bash
   sudo apt update
   sudo apt install build-essential debhelper dh-python python3-all python3-setuptools
   ```
2. Build the package:
   ```bash
   dpkg-buildpackage -us -uc
   ```
3. Install the resulting package from the parent directory (for example `sudo dpkg -i ../lanagent_0.1.0-1_all.deb`).

The Debian package automatically installs and enables the systemd service, creates the `lanagent` system user, and drops a configurable `/etc/lanagent/lanagent.conf`.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Dr. Mickey Lauer

## Acknowledgments

- Thanks to the `zeroconf` and `netifaces` maintainers for their excellent libraries
- Inspired by various network discovery tools like `arp-scan` and `nmap`
