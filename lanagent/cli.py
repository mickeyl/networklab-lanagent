#!/usr/bin/env python3
"""
Command-line interface for LANAgent service.
"""

import argparse
import sys
from .scanner import ARPScannerService


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='LANAgent - Network discovery service with JSON API',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  lanagent                    # Start with auto-selected port
  lanagent --port 8080        # Start on specific port
  lanagent -p 8080           # Short form

The service will:
  - Start HTTP server on the specified port (or auto-select)
  - Register via Zeroconf as _lanagent._tcp.local.
  - Scan the network every 60 seconds
  - Expose results at http://localhost:<port>/scan
        """
    )
    
    parser.add_argument(
        '-p', '--port',
        type=int,
        default=0,
        help='Port to run the HTTP server on (default: auto-select)'
    )
    
    parser.add_argument(
        '-v', '--version',
        action='version',
        version='%(prog)s 0.1.0'
    )
    
    args = parser.parse_args()
    
    try:
        service = ARPScannerService(port=args.port)
        service.run()
    except KeyboardInterrupt:
        print("\nShutdown complete.")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()