# MorriganEye

MorriganEye is an network reconnaissance tool designed for educational purposes, penetration testing, and network analysis.

## Features

- **Packet Sniffer**: Captures and analyzes network packets.
- **DNS Information Gathering**: Gathers detailed DNS records for a specified domain.
- **WHOIS Lookup**: Retrieves WHOIS information for domains.
- **Port Scanner**: Scans for open ports on a target IP.
- **Service Detection**: Identifies running services on open ports.
- **Network Scanner**: Discovers devices on the local network.
- **Logging**: Maintains a log of all activities for future analysis.
- **User-Friendly Interface**: Simple text-based menu for navigation.

## Requirements

- Python 3.x
- Required libraries:
  - `scapy`
  - `dnspython`
  - `python-whois`
  - `prettytable`
  - `colorama`

## Installation

1. **Install Python and Pip**:
   If you don't have Python 3 and Pip installed, run:
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip
