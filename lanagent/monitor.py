"""
Human-facing LANAgent monitor client.
"""

import json
import socket
import sys
import time
from typing import Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import urlopen

from zeroconf import ServiceBrowser, Zeroconf


class LANAgentHTTPClient:
    def __init__(self, base_url: str, timeout: float = 5):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def get_json(self, path: str, query: Optional[Dict[str, object]] = None) -> Dict[str, object]:
        url = f"{self.base_url}{path}"
        if query:
            url = f"{url}?{urlencode(query)}"
        try:
            with urlopen(url, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as e:
            raise RuntimeError(f"LANAgent returned HTTP {e.code} for {path}") from e
        except URLError as e:
            raise RuntimeError(f"Could not reach LANAgent at {self.base_url}: {e.reason}") from e
        except json.JSONDecodeError as e:
            raise RuntimeError(f"LANAgent returned invalid JSON for {path}") from e

    def health(self) -> Dict[str, object]:
        return self.get_json("/health")

    def presence(self, include_absent: bool = False) -> Dict[str, object]:
        return self.get_json("/presence", {"includeAbsent": "1" if include_absent else "0"})

    def events(self, since: int = 0, limit: int = 200) -> Dict[str, object]:
        return self.get_json("/events", {"since": since, "limit": limit})


class LANAgentDiscovery:
    def __init__(self):
        self.base_url: Optional[str] = None

    def add_service(self, zeroconf: Zeroconf, service_type: str, name: str) -> None:
        self._resolve(zeroconf, service_type, name)

    def update_service(self, zeroconf: Zeroconf, service_type: str, name: str) -> None:
        self._resolve(zeroconf, service_type, name)

    def remove_service(self, zeroconf: Zeroconf, service_type: str, name: str) -> None:
        pass

    def _resolve(self, zeroconf: Zeroconf, service_type: str, name: str) -> None:
        if self.base_url:
            return
        info = zeroconf.get_service_info(service_type, name, timeout=1000)
        if not info or not info.port:
            return
        for address in info.parsed_addresses():
            try:
                ip = socket.gethostbyname(address)
            except OSError:
                continue
            self.base_url = f"http://{ip}:{info.port}"
            return


def discover_base_url(timeout: float = 5) -> str:
    listener = LANAgentDiscovery()
    zeroconf = Zeroconf()
    browser = None
    try:
        browser = ServiceBrowser(zeroconf, "_lanagent._tcp.local.", listener)
        deadline = time.time() + timeout
        while time.time() < deadline:
            if listener.base_url:
                return listener.base_url
            time.sleep(0.1)
    finally:
        if browser:
            cancel = getattr(browser, "cancel", None)
            if callable(cancel):
                cancel()
        zeroconf.close()
    raise RuntimeError("No LANAgent service found via Zeroconf; pass --url or --host/--port")


def base_url_from_args(url: Optional[str], host: Optional[str], port: Optional[int], discover_timeout: float) -> str:
    if url:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise RuntimeError("--url must include scheme and host, for example http://meteor:38335")
        return url.rstrip("/")
    if host and port:
        return f"http://{host}:{port}"
    if host or port:
        raise RuntimeError("--host and --port must be provided together")
    return discover_base_url(timeout=discover_timeout)


def run_monitor(
    base_url: str,
    poll_interval: float = 5,
    since: Optional[int] = None,
    replay: bool = False,
    once: bool = False,
    limit: int = 500,
) -> None:
    client = LANAgentHTTPClient(base_url)
    health = client.health()
    diagnostics = dict(health.get("diagnostics") or {})
    presence_diag = dict(diagnostics.get("presence") or {})
    scanner_diag = dict(diagnostics.get("scanner") or {})
    scan_interval = diagnostics.get("scanInterval")
    grace = presence_diag.get("grace")
    sleep_grace = presence_diag.get("sleepGrace")

    if since is None:
        since = 0 if replay else int(presence_diag.get("lastEventSequence") or 0)

    print(
        "monitoring - LANAgent "
        f"{base_url} - cadence {int(scan_interval or 0)}s - "
        f"gone after {int(grace or 0)}s absent; sleep-tolerant after {int(sleep_grace or 0)}s",
        flush=True,
    )
    presence = client.presence()
    devices = list(presence.get("devices") or [])
    via_bonjour_only = sum(1 for device in devices if str(device.get("source", "")) == "bonjour")
    print(
        f"baseline: {sum(1 for device in devices if device.get('present', True))} devices present "
        f"({via_bonjour_only} via Bonjour while ARP-silent)",
        flush=True,
    )
    if scanner_diag.get("lastScan"):
        last_scan = dict(scanner_diag["lastScan"])
        print(
            "last scan: "
            f"{last_scan.get('neighbors', 0)} neighbors, "
            f"{last_scan.get('probeReplies', 0)} probe replies, "
            f"{last_scan.get('duration', 0)}s",
            flush=True,
        )

    while True:
        payload = client.events(since=since, limit=limit)
        events = list(payload.get("events") or [])
        for event in events:
            print(format_event(event), flush=True)
            since = max(since, int(event.get("sequence", since)))
        if once:
            return
        time.sleep(poll_interval)


def format_event(event: Dict[str, object]) -> str:
    event_type = str(event.get("type", ""))
    timestamp = float(event.get("timestamp", time.time()))
    prefix = time.strftime("%H:%M:%S", time.localtime(timestamp))
    device = dict(event.get("device") or {})

    if event_type == "joined":
        suffix = " (Bonjour)" if "bonjour" in str(device.get("source", "")) else ""
        return f"{prefix}  + {format_device(device)} joined{suffix}"
    if event_type == "back_online":
        suffix = " (Bonjour)" if "bonjour" in str(device.get("source", "")) else ""
        return f"{prefix}  + {format_device(device)} back online (was away {int(device.get('awayFor', 0))}s){suffix}"
    if event_type == "left":
        return f"{prefix}  - {format_device(device)} left (gone {int(device.get('goneFor', 0))}s)"
    if event_type == "probe_degraded":
        return (
            f"{prefix}  ! probe degraded: saw {event.get('seen', 0)}/"
            f"{event.get('expected', 0)} expected devices; suppressing leave events"
        )
    if event_type == "probe_recovered":
        return f"{prefix}  ! probe recovered: saw {event.get('seen', 0)}/{event.get('expected', 0)} expected devices"
    if event_type == "monitor_resumed":
        return (
            f"{prefix}  ! monitor resumed after {int(event.get('pause', 0))}s pause; "
            f"ignoring {int(event.get('ignored', 0))}s local sleep in absence timers"
        )
    return f"{prefix}  ! {event_type} {json.dumps(event, sort_keys=True)}"


def format_device(device: Dict[str, object]) -> str:
    ip = str(device.get("ip", "")).ljust(15)
    parts = [ip]
    hostname = str(device.get("hostname", ""))
    mac = str(device.get("mac", ""))
    if hostname:
        parts.append(hostname)
    if mac:
        parts.append(f"[{mac}]")
    return "  ".join(parts)


def main(args) -> int:
    base_url = base_url_from_args(args.url, args.host, args.port, args.discover_timeout)
    try:
        run_monitor(
            base_url=base_url,
            poll_interval=args.poll_interval,
            since=args.since,
            replay=args.replay,
            once=args.once,
            limit=args.limit,
        )
        return 0
    except KeyboardInterrupt:
        print("Stopping monitor.", file=sys.stderr)
        return 130
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
