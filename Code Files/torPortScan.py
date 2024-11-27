'''
Eshaan Prakash(0303204p)
torPortScan.py

This script monitors network traffic to identify potential Tor network activity by scanning for common Tor ports and performing WHOIS lookups.

Functions:
    get_whois_info(ip: str, detailed: bool = False) -> str:
        Performs a WHOIS lookup for the given IP address and returns the result. If detailed is True, returns the full WHOIS output; otherwise, returns a summary.

    packet_callback(packet) -> None:
        Callback function for processing captured packets. Checks if the packet is an IP/TCP packet and if the destination port is a common Tor port. If so, performs a WHOIS lookup on the destination IP.

Main Execution:
    - Defines a list of common ports used by the Tor network.
    - Sets a flag to control scanning.
    - Defines functions for WHOIS lookups and packet processing.
    - (Further implementation details would include starting packet capture and handling threading for continuous monitoring.)
'''

from scapy.all import sniff, IP, TCP
import subprocess
import re
import threading

# Expanded list of common ports used by Tor
tor_ports = [9001, 9030, 443, 80, 9051, 9050, 9150]

scanning = True

def get_whois_info(ip, detailed=False):
    try:
        result = subprocess.run(['whois', ip], capture_output=True, text=True)
        if result.returncode == 0:
            whois_output = result.stdout
            if detailed:
                return whois_output
            else:
                org_name = re.search(r'OrgName:\s*(.*)', whois_output)
                country = re.search(r'Country:\s*(.*)', whois_output)
                person = re.search(r'person:\s*(.*)', whois_output)
                comment = re.search(r'Comment:\s*(.*)', whois_output)
                org_name = org_name.group(1) if org_name else "N/A"
                country = country.group(1) if country else "N/A"
                person = person.group(1) if person else "N/A"
                comment = comment.group(1) if comment else "N/A"
                return f"OrgName: {org_name}\nCountry: {country}\nPerson: {person}\nComment: {comment}\n"
        else:
            return f"WHOIS lookup failed for {ip}: {result.stderr}"
    except Exception as e:
        return f"WHOIS lookup failed for {ip}: {e}"

def packet_callback(packet):
    if IP in packet and TCP in packet:
        dst_port = packet[TCP].dport
        if dst_port in tor_ports:
            dst_ip = packet[IP].dst
            print(f"Detected potential Tor traffic to {dst_ip} on port {dst_port}")
            whois_info = get_whois_info(dst_ip)
            print(whois_info)

def start_sniffing():
    global scanning
    while scanning:
        sniff(filter="tcp", prn=packet_callback, store=0, timeout=1)

def stop_sniffing():
    global scanning
    scanning = False

def main():
    try:
        sniff_thread = threading.Thread(target=start_sniffing)
        sniff_thread.start()

        print("Press Ctrl+C to stop port scanning.")
        try:
            while sniff_thread.is_alive():
                sniff_thread.join(timeout=1)
        except KeyboardInterrupt:
            stop_sniffing()
            sniff_thread.join()
            print('Port scanning stopped.\n')

        ip_address = input("Enter IP address for full WHOIS scan: ")
        whois_info = get_whois_info(ip_address, detailed=True)
        print(whois_info)
    except Exception as e:
        print(f"An error occurred: {e}")
    except KeyboardInterrupt:
        print("Exiting now..")

if __name__ == "__main__":
    main()
