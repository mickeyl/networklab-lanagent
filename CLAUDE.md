# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

LANAgent is a Python package that provides a network discovery service. It scans the local network for connected devices and exposes the results via a JSON API. The service also advertises itself using Zeroconf/mDNS for automatic discovery.

## Package Structure

```
lanagent/
├── __init__.py       - Package initialization, exports main classes
├── __main__.py       - Module execution support (python -m lanagent)
├── cli.py           - Command-line interface entry point
├── scanner.py       - Core scanning logic and service implementation
└── py.typed         - PEP 561 type hint marker
```

## Installation

```bash
# Install from source (development)
pip install -e .

# Install normally
pip install .

# Dependencies (automatically installed)
- zeroconf>=0.38.0
- netifaces>=0.11.0
```

## Running the Service

```bash
# Via installed command
lanagent
lanagent --port 8080

# Via Python module
python -m lanagent

# Programmatically
from lanagent import ARPScannerService
service = ARPScannerService(port=8080)
service.run()
```

## Architecture

The core scanning functionality is in `lanagent/scanner.py` with three main components:

### ARPScanner Class (scanner.py:29-223)
- Handles network scanning using ARP table lookups
- Cross-platform support (macOS uses `arp -a`, Linux uses `ip neigh`)
- Performs parallel pinging to populate ARP cache before scanning
- Includes local machine information in scan results
- Maintains thread-safe cache of discovered devices

### ScanHandler Class (scanner.py:225-250)
- HTTP request handler for the `/scan` endpoint
- Returns JSON with discovered devices (IP and MAC addresses)
- CORS-enabled for web client access

### ARPScannerService Class (scanner.py:252-361)
- Main service orchestrator
- Manages HTTP server lifecycle
- Registers service via Zeroconf as `_lanagent._tcp.local.`
- Performs periodic network scans every 60 seconds
- Handles graceful shutdown on Ctrl+C

## API Endpoint

`GET /scan` - Returns JSON with network devices:
```json
{
  "status": "success",
  "count": <number>,
  "devices": [
    {"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:FF"},
    ...
  ]
}
```

## Platform-Specific Behavior

The service adapts to the operating system:
- **macOS**: Uses `ping -c 1 -W 1 -t 1` and `arp -a`
- **Linux**: Uses `ping -c 1 -W 1` and `ip neigh show`

## Service Discovery

The service registers itself via Zeroconf with:
- Service type: `_lanagent._tcp.local.`
- Service name: `lanagent-<hostname>-<port>`
- Properties include version, path, description, and hostname