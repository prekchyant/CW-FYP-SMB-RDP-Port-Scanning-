

import os
import platform
import subprocess

def is_windows(ip_address):
    try:
        response = subprocess.run(["ping", "-n", "1", ip_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if response.returncode == 0:
            return True
        else:
            return False
    except subprocess.CalledProcessError:
        return False

def is_linux(ip_address):
    try:
        response = subprocess.run(["ping", "-c", "1", ip_address], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if "ttl" in response.stdout.lower():  # Check for the TTL value in the ping response (Windows systems have TTL)
            return False
        else:
            return True
    except subprocess.CalledProcessError:
        return False

def main():
    specific_ip = "10.0.0.4"  # Replace this with the specific IP address you want to search

    if is_windows(specific_ip):
        print(f"The system at {specific_ip} is a Windows system.")
    elif is_linux(specific_ip):
        print(f"The system at {specific_ip} is a Linux system.")
    else:
        print(f"Unable to determine the operating system for {specific_ip}.")

if __name__ == "__main__":
    main()

