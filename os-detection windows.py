import socket

def check_os(target_ip):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)  # Set a timeout for the connection attempt
            s.connect((target_ip, 445))  # Attempt to connect to port 445 (Windows SMB)
            return "Windows"
    except (socket.timeout, ConnectionRefusedError):
        pass

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)  # Set a timeout for the connection attempt
            s.connect((target_ip, 22))  # Attempt to connect to port 22 (SSH on Linux)
            return "Linux"
    except (socket.timeout, ConnectionRefusedError):
        pass

    return "Unknown"

if __name__ == "__main__":
    target_ip = "10.0.0.4"  # Replace this with the IP address you want to check
    os_type = check_os(target_ip)
    print(f"IP: {target_ip} | OS: {os_type}")

