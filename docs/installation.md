# Installation Guide

## Requirements

- Python 3.10 or newer
- Linux operating system
- Git (for cloning the repository)

## Setup

1. Clone the repository.
2. Enter the project directory.
3. Create a Python virtual environment.
4. Activate the virtual environment.
5. Run the scanner.

## Example

```bash
python3 scanner/network_scanner.py \
  --target 127.0.0.1 \
  --ports 22,80,443,8080
```

## Testing

```bash
python3 -m unittest discover -s tests -v
```

## Troubleshooting

If Python reports a missing file, confirm you are
running commands from the project root.

If a port appears CLOSED/FILTERED, verify that
a service is listening on that port.

Use only systems you own or have permission to scan.
