# Python Network Scanner

**A lightweight, multithreaded TCP port scanner built with Python for authorized network security assessments.**


\


## Overview

Python Network Scanner is a command-line cybersecurity tool that checks TCP port connectivity on authorized private IPv4 hosts.

The project demonstrates practical knowledge of Python socket programming, networking fundamentals, concurrent execution, input validation, automated testing, and structured reporting.

## Features

- TCP connect scanning using Python sockets
- Concurrent scanning with `ThreadPoolExecutor`
- Individual ports and port ranges
- Configurable connection timeout
- Configurable worker threads
- Common TCP service-name mapping
- Private and loopback IPv4 target validation
- JSON report generation
- Automated unit testing
- GitHub Actions continuous integration

## Technologies

| Technology         | Purpose                   |
| ------------------ | ------------------------- |
| Python 3           | Core programming language |
| Socket             | TCP connection testing    |
| ThreadPoolExecutor | Concurrent scanning       |
| ipaddress          | IPv4 address validation   |
| JSON               | Structured scan reports   |
| unittest           | Automated testing         |
| GitHub Actions     | Continuous integration    |

## Installation

Clone the repository:

```bash
git clone https://github.com/t4nnsk11/python-network-scanner.git
cd python-network-scanner
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

The application uses only Python standard-library modules, so no third-party Python packages are required.

## Usage

Scan selected ports on your local machine:

```bash
python3 scanner/network_scanner.py --target 127.0.0.1 --ports 22,80,443,8080
```

Scan a range of ports:

```bash
python3 scanner/network_scanner.py --target 127.0.0.1 --ports 20-100
```

Customize concurrency and timeout:

```bash
python3 scanner/network_scanner.py --target 127.0.0.1 --ports 20-100,443,8080 --workers 10 --timeout 0.5
```

Generate a custom JSON report:

```bash
python3 scanner/network_scanner.py --target 127.0.0.1 --ports 22,80,443,8080 --output results/my_scan.json
```

## Screenshots

### Scanner output



### Automated tests



## Automated Testing

Run the test suite:

```bash
python3 -m unittest discover -s tests -v
```

The current suite includes 15 automated tests covering target validation, port parsing, TCP scanning, sorted results, and report generation.

GitHub Actions automatically executes the test suite on pushes and pull requests.

## Security and Limitations

This project is intended exclusively for educational purposes and authorized security assessments.

- Only private or loopback IPv4 targets are accepted.
- Scanning is limited to 1,024 unique ports per execution.
- The maximum concurrency is 32 workers.
- Service labels are inferred from common port assignments, not confirmed by protocol fingerprinting.
- Unsuccessful connections are reported as `CLOSED/FILTERED`; the tool does not reliably distinguish those conditions.
- The tool does not perform vulnerability exploitation or vulnerability assessment.
- Private IP address validation does not establish permission to scan a system.

## Future Improvements

- IPv6 support
- CSV export
- Optional service banner identification
- Improved socket error classification
- Performance benchmarking
- Additional unit tests

## Author

Cybersecurity portfolio project demonstrating Python programming, network security fundamentals, and secure software development practices.

## License

MIT License.

