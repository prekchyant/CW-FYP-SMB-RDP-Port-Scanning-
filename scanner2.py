import socket
from scapy.all import ARP, Ether, srp
import subprocess

def is_windows(target_ip):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)  # Set a timeout for the connection attempt
            s.connect((target_ip, 445))  # Attempt to connect to port 445 (Windows SMB)
            return True
    except (socket.timeout, ConnectionRefusedError):
        return False

def is_linux(ip_address):
    try:
        response = subprocess.run(["ping", "-c", "1", ip_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if response.returncode == 0:
            return True
        else:
            return False
    except subprocess.CalledProcessError:
        return False

def detect_os(target_ip):
    if is_windows(target_ip):
        return "Windows"
    elif is_linux(target_ip):
        return "Linux"
    else:
        return "Unknown"

def detect_smb_version(ip):
    try:
        # Create an SMB request to get the SMB version
        smb_request = b"\x00\x00\x00\x90" + b"\xff\x53\x4d\x42" + b"\x72\x00\x00\x00\x00\x18\x53\xc8" + \
                      b"\x00\x26\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((ip, 445))
            s.send(smb_request)
            smb_response = s.recv(1024)

        # Analyze the SMB response to get the SMB version
        if smb_response[3:7] == b"\x72\x00\x00\x00":
            smb_version = ord(smb_response[38:39])
            return f"SMBv{int(smb_version)}"
        else:
            return None

    except (socket.timeout, ConnectionRefusedError, OSError):
        return None

def network_scan(interface):
    # Create an ARP request packet
    arp = ARP(pdst="10.0.0.1/24")
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    
    # Send the packet and capture the response
    result = srp(packet, timeout=3, iface=interface, verbose=0)[0]
    
    # Display the sent and received packets for debugging purposes
    print("Sent packets:")
    print("----------------")
    for sent, received in result:
        print(sent.summary())

    print("Received packets:")
    print("-------------------")
    for sent, received in result:
        print(received.summary())


    # Process the response
    devices = []
    for sent, received in result:
    	if received.psrc != "10.0.0.2":  # Skip IP address 10.0.0.2
        	devices.append({'IP': received.psrc, 'MAC': received.hwsrc})
    
    # Display the discovered devices
    print("Discovered devices:")
    print("-------------------")
    for device in devices:
        print(f"IP: {device['IP']}\t MAC: {device['MAC']}")
        
         # Detect SMB version for Windows and Linux systems
        smb_version = detect_smb_version(device['IP'])
        if smb_version is not None:
            print(f"SMB Version: {smb_version}")
        
        os_detected = detect_os(device['IP'])
        print(f"The detected OS for {device['IP']} is: {os_detected}")
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




