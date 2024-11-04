import socket
import struct
import sys
import ipaddress
from scapy.all import ARP, Ether, srp

def get_local_ip():
    """Get the local IP address of the device."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't have to be reachable, just used to get local IP
        s.connect(('10.254.254.254', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def scan_network(network):
    """Scan the specified network for active devices."""
    print(f"Scanning network: {network}")
    arp_request = ARP(pdst=str(network))
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp_request

    result = srp(packet, timeout=2, verbose=0)[0]
    devices = []
    
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

def display_devices(devices):
    """Display a list of discovered devices with IP and MAC addresses."""
    print("\nActive Devices:")
    print("IP Address\t\tMAC Address")
    print("-" * 40)
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")

if __name__ == "__main__":
    local_ip = get_local_ip()
    ip_network = ipaddress.ip_network(local_ip + '/24', strict=False)
    devices = scan_network(ip_network)

    if devices:
        display_devices(devices)
    else:
        print("No active devices found on the network.")
