import openpyxl
import socket
from scapy.all import ARP, Ether, srp
import subprocess
from impacket.smbconnection import SMBConnection
from vulnerabilities_data import vulnerabilities

# Function to detect SMB version
def detect_smb_version(ip):
    try:
        smb_connection = SMBConnection(ip, ip)  # Provide the same IP as target_name
        smb_connection.login('', '')  # Empty username and password for anonymous login
        
        smb_version = smb_connection.getDialect()
        smb_connection.close()
        
        return smb_version
    except Exception as e:
        return None

def determine_smb_version(detected_smb_version):
    if detected_smb_version == "NT LM 0.12":
        return "SMBv1"
    elif detected_smb_version == "2.0.2" or detected_smb_version == "2.1":
        return "SMBv2"
    elif detected_smb_version == "3.0" or detected_smb_version == "3.0.2" or detected_smb_version == "3.1.1":
        return "SMBv3"
    else:
        return "Unknown"

# Function to perform network scan and generate Excel report
def network_scan(ip_range, interface, excel_filename):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=3, iface=interface, verbose=0)[0]

    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.title = "SMB Vulnerabilities"
    header = ["IP Address", "SMB Version", "Operating System", "Vulnerability with CVE", "Vulnerable"]
    sheet.append(header)

    for sent, received in result:
        if received.psrc != "192.168.61.45":
            detected_ip = received.psrc
            detected_os = "Unknown"
            
            if is_windows(detected_ip):
                detected_os = "Windows"
            elif is_linux(detected_ip):
                detected_os = "Linux"
            
            detected_smb_version = detect_smb_version(detected_ip)
            smb_version = determine_smb_version(detected_smb_version)
            
            
            for vuln in vulnerabilities:
                smb_version = vuln["SMB"]
                if detected_smb_version == smb_version:
                    row = [detected_ip, detected_smb_version, detected_os,
                           vuln["Name"] + f" (CVE-{vuln['CVE']})", vuln["Windows Impact"]]
                    sheet.append(row)
            
            #print(f"IP: {detected_ip}\t MAC: {received.hwsrc}")
            #print(f"The detected OS for {detected_ip} is: {detected_os}")
            detected_smb_version = detect_smb_version(detected_ip)
            print(f"Detected SMB version for {detected_ip}: {detected_smb_version}")  # Debug print
            smb_version = determine_smb_version(detected_smb_version)
            print(f"Determined SMB version for {detected_ip}: {smb_version}")  # Debug prin
            print(f"SMB Version for {detected_ip}: {detected_smb_version}")

            row = [detected_ip, smb_version, detected_os]
            sheet.append(row)

    # Using ws.append to add IP addresses to the Excel table
    # for sent, received in result:
    #     if received.psrc != "192.168.61.45":
    #         detected_ip = received.psrc
    #         sheet.append([detected_ip])  # Appending only the IP address
        
    workbook.save(excel_filename)
    print(f"Excel report '{excel_filename}' generated successfully.")

# Function to check if the target is Windows
def is_windows(target_ip):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((target_ip, 445))
            return True
    except (socket.timeout, ConnectionRefusedError):
        return False

# Function to check if the target is Linux
def is_linux(ip_address):
    try:
        response = subprocess.run(["ping", "-c", "1", ip_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if response.returncode == 0:
            return True
        else:
            return False
    except subprocess.CalledProcessError:
        return False

# Ask user for IP range to scan
ip_range = input("Enter IP range to scan (e.g., 192.168.1.0/24): ")
interface = "eth0"  # Replace with your network interface (e.g., "eth0", "wlan0", etc.)
excel_filename = input("Enter the desired Excel filename (e.g., smb_vulnerabilities.xlsx): ")

network_scan(ip_range, interface, excel_filename)
