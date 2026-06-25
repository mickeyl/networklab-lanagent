#!/usr/bin/env python3
"""
Command-line interface for LANAgent service.
"""

import argparse
import sys
from importlib.metadata import PackageNotFoundError, version
from .monitor import main as monitor_main
from .scanner import ARPScannerService


def package_version() -> str:
    try:
        return version("lanagent")
    except PackageNotFoundError:
        return "0.0.0"


def build_serve_parser(prog: str = "lanagent") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='LANAgent - Network discovery service with JSON API',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  lanagent                    # Start with auto-selected port
  lanagent serve              # Explicitly start the service
  lanagent monitor            # Follow presence events from a discovered LANAgent
  lanagent --port 8080        # Start on specific port
  lanagent -p 8080           # Short form

The service will:
  - Start HTTP server on the specified port (or auto-select)
  - Register via Zeroconf as _lanagent._tcp.local.
  - Scan the network on a fixed interval
  - Expose scan, presence, event, lookup, and health JSON APIs
        """
    )
    parser.prog = prog
    
    parser.add_argument(
        '-p', '--port',
        type=int,
        default=0,
        help='Port to run the HTTP server on (default: auto-select)'
    )

    parser.add_argument(
        '--scan-interval',
        type=int,
        default=60,
        help='Seconds between periodic network scans (default: 60)'
    )

    parser.add_argument(
        '--presence-grace',
        type=float,
        default=1800,
        help='Seconds absent before ordinary devices are marked gone (default: 1800)'
    )

    parser.add_argument(
        '--sleep-grace',
        type=float,
        default=12 * 3600,
        help='Seconds absent before sleep-tolerant devices are marked gone (default: 43200)'
    )

    parser.add_argument(
        '--miss-count',
        type=int,
        default=3,
        help='Consecutive missed scans required before a device may be marked gone (default: 3)'
    )

    parser.add_argument(
        '--min-probe-completeness',
        type=float,
        default=0.35,
        help='Suppress leave events when a scan sees less than this fraction of expected devices (default: 0.35)'
    )

    parser.add_argument(
        '--resume-gap',
        type=float,
        default=300,
        help='Seconds of service inactivity treated as local suspend/resume (default: 300)'
    )
    
    parser.add_argument(
        '-v', '--version',
        action='version',
        version=f'%(prog)s {package_version()}'
    )
    return parser


def build_monitor_parser(prog: str = "lanagent monitor") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        description="Follow LANAgent presence events",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  lanagent monitor
  lanagent monitor --url http://meteor:38335
  lanagent monitor --host meteor --port 38335 --replay

By default, the monitor discovers _lanagent._tcp.local. via Zeroconf and starts
at the current event sequence. Use --replay or --since to print historical events.
        """,
    )
    parser.add_argument("--url", help="LANAgent base URL, for example http://meteor:38335")
    parser.add_argument("--host", help="LANAgent host when not using --url or Zeroconf discovery")
    parser.add_argument("--port", type=int, help="LANAgent port when using --host")
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=5,
        help="Seconds between event polls (default: 5)",
    )
    parser.add_argument(
        "--since",
        type=int,
        help="Only print events after this sequence number",
    )
    parser.add_argument(
        "--replay",
        action="store_true",
        help="Replay stored events from sequence 0 instead of starting at the current tail",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Print currently available events and exit",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=500,
        help="Maximum events to fetch per poll (default: 500)",
    )
    parser.add_argument(
        "--discover-timeout",
        type=float,
        default=5,
        help="Seconds to wait for Zeroconf discovery when no URL is provided (default: 5)",
    )
    return parser


def main():
    """Main CLI entry point."""
    argv = sys.argv[1:]
    if argv and argv[0] == "monitor":
        parser = build_monitor_parser()
        args = parser.parse_args(argv[1:])
        sys.exit(monitor_main(args))

    if argv and argv[0] == "serve":
        parser = build_serve_parser("lanagent serve")
        args = parser.parse_args(argv[1:])
    else:
        parser = build_serve_parser()
        args = parser.parse_args(argv)

    try:
        service = ARPScannerService(
            port=args.port,
            scan_interval=args.scan_interval,
            presence_grace=args.presence_grace,
            sleep_grace=args.sleep_grace,
            miss_count=args.miss_count,
            min_probe_completeness=args.min_probe_completeness,
            resume_gap=args.resume_gap,
        )
        service.run()
    except KeyboardInterrupt:
        print("\nShutdown complete.")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
