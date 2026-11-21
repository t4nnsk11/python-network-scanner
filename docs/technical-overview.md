# Technical Overview

## Architecture

CLI arguments
    |
    v
Target and port validation
    |
    v
ThreadPoolExecutor
    |
    v
TCP socket connections
    |
    v
Results collection and sorting
    |
    v
Terminal output + JSON report

## Core Functions

- validate_target(): checks IPv4 target eligibility
- parse_ports(): parses port numbers and ranges
- scan_port(): attempts a TCP connection
- scan_host(): runs concurrent port checks
- save_report(): writes JSON results
- main(): handles command-line execution

## TCP Connect Scanning

The scanner uses socket.connect_ex() to attempt
a full TCP connection.

A successful connection returns OPEN.

An unsuccessful connection returns CLOSED/FILTERED,
while socket exceptions return ERROR.

## Concurrency

ThreadPoolExecutor distributes independent port
checks across a configurable number of workers.

The default is 10 workers and the maximum is 32.

## Limitations

The scanner does not identify vulnerabilities,
fingerprint service versions, or perform stealth scans.
