
import socket
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner.network_scanner import (
    parse_ports,
    validate_target,
    scan_port,
    scan_host,
    save_report,
)

import json


class TestValidation(unittest.TestCase):

    def test_valid_loopback(self):
        self.assertEqual(validate_target("127.0.0.1"), "127.0.0.1")

    def test_valid_private_ip(self):
        self.assertEqual(
            validate_target("192.168.56.10"), "192.168.56.10"
        )

    def test_invalid_ip(self):
        with self.assertRaises(ValueError):
            validate_target("not-an-ip")

    def test_public_ip_rejected(self):
        with self.assertRaises(ValueError):
            validate_target("8.8.8.8")

    def test_single_ports(self):
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])

    def test_port_range(self):
        self.assertEqual(parse_ports("20-23"), [20, 21, 22, 23])

    def test_duplicate_ports(self):
        self.assertEqual(parse_ports("80,80,443"), [80, 443])

    def test_invalid_port(self):
        with self.assertRaises(ValueError):
            parse_ports("70000")

    def test_invalid_range(self):
        with self.assertRaises(ValueError):
            parse_ports("100-20")

    def test_too_many_ports(self):
        with self.assertRaises(ValueError):
            parse_ports("1-2000")


class TestScanner(unittest.TestCase):

    def test_open_local_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]
            self.assertEqual(
                scan_port("127.0.0.1", port), "OPEN"
            )

    def test_closed_local_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("127.0.0.1", 0))
            port = server.getsockname()[1]

        self.assertNotEqual(
            scan_port("127.0.0.1", port), "OPEN"
        )

    def test_sorted_results(self):
        results = scan_host("127.0.0.1", [443, 22, 80])
        self.assertEqual(
            [item["port"] for item in results],
            [22, 80, 443]
        )

    def test_unknown_service(self):
        results = scan_host("127.0.0.1", [65000])
        self.assertEqual(results[0]["service"], "UNKNOWN")

    def test_report_generation(self):
        results = [{
            "port": 8080,
            "protocol": "tcp",
            "state": "OPEN",
            "service": "HTTP-ALT",
        }]

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "scan.json"
            save_report("127.0.0.1", results, output)

            report = json.loads(output.read_text())

            self.assertEqual(report["open_ports"], 1)
            self.assertEqual(report["total_ports"], 1)
            self.assertEqual(report["version"], "2.0")


if __name__ == "__main__":
    unittest.main()

