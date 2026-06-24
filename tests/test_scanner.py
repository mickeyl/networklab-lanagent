import time
import sys
import threading
import types
import unittest

sys.modules.setdefault(
    "netifaces",
    types.SimpleNamespace(
        AF_INET=2,
        AF_LINK=18,
        gateways=lambda: {},
        interfaces=lambda: [],
        ifaddresses=lambda interface: {},
    )
)
sys.modules.setdefault(
    "zeroconf",
    types.SimpleNamespace(ServiceBrowser=object, ServiceInfo=object, Zeroconf=object)
)

from lanagent.presence import PresenceMonitor
from lanagent.scanner import ARPScanner, BonjourPresenceBrowser


class ARPScannerTests(unittest.TestCase):

    def test_cache_merges_and_expires_by_ttl(self):
        scanner = ARPScanner()
        scanner.cache_ttl = 1

        scanner.remember_devices([{"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"}], "scan")
        first = scanner.get_cached_results()

        self.assertEqual(first[0]["ip"], "192.168.1.10")
        self.assertEqual(first[0]["source"], "scan")
        self.assertIn("firstSeen", first[0])
        self.assertIn("lastSeen", first[0])

        scanner.remember_devices([{"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"}], "lookup")
        second = scanner.get_cached_results()

        self.assertEqual(second[0]["firstSeen"], first[0]["firstSeen"])
        self.assertGreaterEqual(second[0]["lastSeen"], first[0]["lastSeen"])
        self.assertEqual(second[0]["source"], "lookup")

        with scanner.lock:
            scanner.cache["192.168.1.10"]["lastSeen"] = time.time() - 2

        self.assertEqual(scanner.get_cached_results(), [])

    def test_lookup_probes_and_updates_cache(self):
        class FakeScanner(ARPScanner):
            def get_local_network(self):
                return "192.168.1.20", "255.255.255.0", "eth0"

            def arp_probe_device(self, ip, interface):
                self.probed = (ip, interface)
                return {"ip": ip, "mac": "11:22:33:44:55:66"}

            def read_neighbor_table(self):
                return [
                    {"ip": "192.168.1.30", "mac": "11:22:33:44:55:66"},
                    {"ip": "192.168.1.31", "mac": "22:33:44:55:66:77"},
                ]

        scanner = FakeScanner()
        result = scanner.lookup("192.168.1.30")

        self.assertEqual(scanner.probed, ("192.168.1.30", "eth0"))
        self.assertEqual(result["mac"], "11:22:33:44:55:66")
        self.assertEqual(result["source"], "lookup")

    def test_normalizes_macos_arp_mac_addresses(self):
        scanner = ARPScanner()
        output = "? (192.168.1.129) at 9c:76:e:52:10:38 on en0 ifscope [ethernet]"

        original_platform = sys.platform
        try:
            sys.platform = "darwin"
            devices = scanner.parse_arp_output(output)
        finally:
            sys.platform = original_platform

        self.assertEqual(devices, [{"ip": "192.168.1.129", "mac": "9C:76:0E:52:10:38"}])

    def test_parses_arping_mac_addresses(self):
        scanner = ARPScanner()
        output = "Unicast reply from 192.168.1.109 [A8:51:AB:10:FC:28]  0.798ms"

        self.assertEqual(scanner.parse_arping_mac(output), "A8:51:AB:10:FC:28")

    def test_diagnostics_report_network_and_arping(self):
        class FakeScanner(ARPScanner):
            def get_local_network(self):
                return "192.168.1.20", "255.255.255.0", "eth0"

        scanner = FakeScanner()
        diagnostics = scanner.diagnostics()

        self.assertEqual(diagnostics["network"]["ip"], "192.168.1.20")
        self.assertEqual(diagnostics["network"]["interface"], "eth0")
        self.assertIn("cacheTTL", diagnostics)
        self.assertIn("hasArping", diagnostics)


class PresenceMonitorTests(unittest.TestCase):

    def test_presence_emits_join_leave_and_back_online(self):
        monitor = PresenceMonitor(grace=10, sleep_grace=100, miss_count=1)
        device = {"ip": "192.168.1.20", "mac": "00:11:22:33:44:55", "source": "scan"}

        monitor.update([device], now=100)
        self.assertEqual(monitor.snapshot()[0]["present"], True)
        self.assertEqual(monitor.events_since()[0]["type"], "joined")

        monitor.update([], now=111)
        self.assertEqual(monitor.snapshot(include_absent=True)[0]["present"], False)
        self.assertEqual(monitor.events_since()[-1]["type"], "left")

        monitor.update([device], now=120)
        self.assertEqual(monitor.snapshot()[0]["present"], True)
        self.assertEqual(monitor.events_since()[-1]["type"], "back_online")

    def test_sleep_tolerant_devices_use_sleep_grace(self):
        monitor = PresenceMonitor(grace=10, sleep_grace=100, miss_count=1)
        device = {"ip": "192.168.1.30", "mac": "02:42:C0:A8:01:03", "source": "scan"}

        monitor.update([device], now=100)
        monitor.update([], now=111)
        self.assertEqual(monitor.snapshot()[0]["present"], True)

        monitor.update([], now=201)
        self.assertEqual(monitor.snapshot(include_absent=True)[0]["present"], False)

    def test_degraded_probe_suppresses_leave_events(self):
        monitor = PresenceMonitor(grace=10, miss_count=1, min_probe_completeness=0.5)
        devices = [
            {"ip": f"192.168.1.{index}", "mac": f"AA:BB:CC:DD:EE:{index:02X}", "source": "scan"}
            for index in range(1, 11)
        ]

        monitor.update(devices, now=100)
        monitor.update(devices[:1], now=200)

        self.assertEqual(len(monitor.snapshot()), 10)
        self.assertEqual(monitor.events_since()[-1]["type"], "probe_degraded")
        self.assertEqual(monitor.diagnostics()["probeDegraded"], True)

        monitor.update(devices, now=260)
        self.assertEqual(monitor.events_since()[-1]["type"], "probe_recovered")
        self.assertEqual(monitor.diagnostics()["probeDegraded"], False)

    def test_resume_gap_shifts_absence_timers(self):
        monitor = PresenceMonitor(grace=120, miss_count=1, resume_gap=300, cadence=60)
        device = {"ip": "192.168.1.40", "mac": "AA:BB:CC:DD:EE:40", "source": "scan"}

        monitor.update([device], now=100)
        monitor.update([], now=500)

        self.assertEqual(monitor.events_since()[-1]["type"], "monitor_resumed")
        self.assertEqual(monitor.snapshot()[0]["present"], True)

    def test_bonjour_observation_merges_with_same_cycle_arp_record(self):
        monitor = PresenceMonitor(grace=10, sleep_grace=100, miss_count=1)

        monitor.update([
            {"ip": "192.168.1.20", "mac": "00:11:22:33:44:55", "source": "scan"},
            {"ip": "192.168.1.20", "mac": "", "source": "bonjour", "hostname": "host.local"},
        ], now=100)

        snapshot = monitor.snapshot()
        self.assertEqual(len(snapshot), 1)
        self.assertEqual(snapshot[0]["key"], "00:11:22:33:44:55")
        self.assertEqual(snapshot[0]["mac"], "00:11:22:33:44:55")
        self.assertEqual(snapshot[0]["source"], "scan+bonjour")
        self.assertEqual(snapshot[0]["sleepTolerant"], True)

    def test_bonjour_observation_merges_with_existing_ip_record(self):
        monitor = PresenceMonitor(grace=10, sleep_grace=100, miss_count=1)
        device = {"ip": "192.168.1.30", "mac": "AA:BB:CC:DD:EE:30", "source": "scan"}

        monitor.update([device], now=100)
        monitor.update([
            {"ip": "192.168.1.30", "mac": "", "source": "bonjour", "hostname": "host.local"},
        ], now=110)

        snapshot = monitor.snapshot()
        self.assertEqual(len(snapshot), 1)
        self.assertEqual(snapshot[0]["key"], "AA:BB:CC:DD:EE:30")
        self.assertEqual(snapshot[0]["mac"], "AA:BB:CC:DD:EE:30")
        self.assertEqual(snapshot[0]["source"], "bonjour")
        self.assertEqual(snapshot[0]["sleepTolerant"], True)


class BonjourPresenceBrowserTests(unittest.TestCase):

    def test_snapshot_deduplicates_by_ip(self):
        browser = BonjourPresenceBrowser.__new__(BonjourPresenceBrowser)
        browser.instances = {
            ("_ssh._tcp.local.", "one"): [
                {"ip": "192.168.1.20", "mac": "", "hostname": "one.local", "source": "bonjour"},
            ],
            ("_smb._tcp.local.", "two"): [
                {"ip": "192.168.1.20", "mac": "", "hostname": "two.local", "source": "bonjour"},
                {"ip": "192.168.1.21", "mac": "", "hostname": "two.local", "source": "bonjour"},
            ],
        }
        browser.lock = threading.RLock()

        snapshot = browser.snapshot()

        self.assertEqual([device["ip"] for device in snapshot], ["192.168.1.20", "192.168.1.21"])


if __name__ == "__main__":
    unittest.main()
