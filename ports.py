import socket
import nmap

# Ask the user for the IP address or domain name
target = input("Enter the IP address or domain name: ")

# Check if the target is an IP address or a domain name
if target.replace('.', '').isdigit():
    ip_address = target
else:
    # Resolve the domain name to an IP address
    ip_address = socket.gethostbyname(target)

# Create an instance of the nmap.PortScanner class
scanner = nmap.PortScanner()

# Perform a scan on the target
scan_results = scanner.scan(ip_address, arguments='-sS -sV')

# Extract the scan results
scan_info = scanner[ip_address]

# Print the open and closed ports
print(f"Open Ports: {scan_info['tcp']}")
print(f"Closed Ports: {scan_info['tcp'].difference(scan_info['tcp'].values())}")