# Network Scanner
A Python script that scans a local network to detect active devices and display their IP and MAC addresses.

## Instructions

### Install Dependencies
This script uses the `scapy` library for ARP requests, so install it with:

pip install scapy

Run the Script
To execute the script, use the following command:

python network_scanner.py

The script will print active devices with their IP and MAC addresses in the console output.

Requirements
Npcap (required for Windows): Ensure Npcap is installed to allow packet sniffing and ARP requests.
Download Npcap here
During installation, enable the option "Install Npcap in WinPcap API-compatible Mode" for compatibility.

Example
Scanning network: 192.168.1.0/24

Active Devices:
IP Address          MAC Address
-------------------------------
192.168.1.1         aa:bb:cc:dd:ee:ff
192.168.1.2         11:22:33:44:55:66