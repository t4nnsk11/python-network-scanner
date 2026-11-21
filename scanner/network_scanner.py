
import argparse
import ipaddress
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

SERVICES = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}

MAX_PORTS = 1024
MAX_WORKERS = 32


def validate_target(target):
    """Accept only IPv4 loopback or private addresses."""
    try:
        address = ipaddress.IPv4Address(target)
    except ipaddress.AddressValueError as exc:
        raise ValueError("Target must be a valid IPv4 address") from exc

    if not (address.is_private or address.is_loopback):
        raise ValueError(
            "This lab scanner only accepts private or loopback IPv4 targets"
        )

    # Exclude special-purpose addresses that are not suitable hosts.
    if address.is_multicast or address.is_unspecified:
        raise ValueError("Target must be a usable host address")

    return str(address)


def parse_ports(port_string):
    """Parse comma-separated ports and ranges."""
    ports = set()

    for part in port_string.split(","):
        part = part.strip()

        if not part:
            raise ValueError("Empty port entry")

        if "-" in part:
            bounds = part.split("-")

            if len(bounds) != 2:
                raise ValueError("Invalid port range")

            try:
                start, end = map(int, bounds)
            except ValueError as exc:
                raise ValueError("Port range must contain integers") from exc

            if start > end:
                raise ValueError("Port range start exceeds end")

            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError("Ports must be between 1 and 65535")

            if end - start + 1 > MAX_PORTS:
                raise ValueError("Port range exceeds safety limit")

            ports.update(range(start, end + 1))
        else:
            try:
                port = int(part)
            except ValueError as exc:
                raise ValueError("Port must be an integer") from exc

            if not 1 <= port <= 65535:
                raise ValueError("Ports must be between 1 and 65535")

            ports.add(port)

        if len(ports) > MAX_PORTS:
            raise ValueError(f"Maximum {MAX_PORTS} unique ports allowed")

    return sorted(ports)


def scan_port(target, port, timeout=1.0):
    """Attempt one TCP connection to a target port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            return "OPEN" if result == 0 else "CLOSED/FILTERED"
    except OSError:
        return "ERROR"


def scan_host(target, ports, timeout=1.0, workers=10):
    """Scan ports concurrently and return sorted results."""
    results = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(scan_port, target, port, timeout): port
            for port in ports
        }

        for future in as_completed(futures):
            port = futures[future]

            try:
                state = future.result()
            except Exception:
                state = "ERROR"

            results.append({
                "port": port,
                "protocol": "tcp",
                "state": state,
                "service": SERVICES.get(port, "UNKNOWN"),
            })

    return sorted(results, key=lambda item: item["port"])


def save_report(target, results, output_path):
    """Save a structured JSON scan report."""
    report = {
        "tool": "Python Network Scanner",
        "version": "2.0",
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_ports": len(results),
        "open_ports": sum(
            item["state"] == "OPEN" for item in results
        ),
        "results": results,
    }

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8"
    )

    return output


def main():
    parser = argparse.ArgumentParser(
        description="Authorized IPv4 TCP connect scanner"
    )

    parser.add_argument("--target", required=True)
    parser.add_argument(
        "--ports", default="21,22,80,443,8080"
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0
    )
    parser.add_argument(
        "--workers", type=int, default=10
    )
    parser.add_argument(
        "--output", default="results/scan.json"
    )

    args = parser.parse_args()

    try:
        target = validate_target(args.target)
        ports = parse_ports(args.ports)

        if not 0.1 <= args.timeout <= 10.0:
            raise ValueError("Timeout must be between 0.1 and 10 seconds")

        if not 1 <= args.workers <= MAX_WORKERS:
            raise ValueError(
                f"Workers must be between 1 and {MAX_WORKERS}"
            )

    except ValueError as exc:
        parser.error(str(exc))

    print("\nPYTHON NETWORK SCANNER v2.0")
    print(f"Target: {target}")
    print(f"Ports: {len(ports)}")
    print(f"Workers: {args.workers}\n")

    results = scan_host(
        target, ports,
        timeout=args.timeout,
        workers=args.workers
    )

    print(f"{'PORT':<12}{'STATE':<18}SERVICE")
    print("-" * 42)

    for item in results:
        print(
            f"{item['port']:<12}"
            f"{item['state']:<18}"
            f"{item['service']}"
        )

    try:
        output = save_report(target, results, args.output)
    except OSError as exc:
        parser.exit(1, f"Failed to save report: {exc}\n")

    print(f"\nOpen ports: {sum(r['state'] == 'OPEN' for r in results)}")
    print(f"Report saved: {output}")


if __name__ == "__main__":
    main()

