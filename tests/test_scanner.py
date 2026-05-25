import time
import sys
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
    types.SimpleNamespace(ServiceInfo=object, Zeroconf=object)
)

from lanagent.scanner import ARPScanner


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


if __name__ == "__main__":
    unittest.main()
