import socket
from scapy.all import ARP, Ether, srp

def network_scan(interface):
    # Create an ARP request packet
    arp = ARP(pdst="10.0.0.3")
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    
    # Send the packet and capture the response
    result = srp(packet, timeout=3, iface=interface, verbose=0)[0]
    
    # Process the response
    devices = []
    for sent, received in result:
        devices.append({'IP': received.psrc, 'MAC': received.hwsrc})
    
    # Display the discovered devices
    print("Discovered devices:")
    print("-------------------")
    for device in devices:
        print(f"IP: {device['IP']}\t MAC: {device['MAC']}")
        scan_ports(device['IP'])


def scan_ports(ip):
    open_ports = []
    common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3389]  # Add more ports as needed
    
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    
    # Display the open ports for the current device
    if len(open_ports) > 0:
        print("Open ports:")
        print(", ".join(map(str, open_ports)))
    else:
        print("No open ports found.")


# Specify the network interface to use for scanning
interface = "eth0"  # Replace with your network interface (e.g., "eth0", "wlan0", etc.)

# Perform the network scan
network_scan(interface)