"""
Eshaan Prakash(0303204p)
socksTest.py

This script interacts with the Tor network to perform WHOIS lookups and send HTTP requests anonymously.

Functions:
    connect_to_tor() -> Controller:
        Connects to a running Tor process and returns the controller object.

    request_new_identity(controller: Controller) -> None:
        Requests a new identity from the Tor network using the provided controller.

    send_request_via_tor(url: str) -> None:
        Sends an HTTP request to the specified URL via the Tor network and prints the response.

    get_whois_info(ip: str) -> str:
        Performs a WHOIS lookup for the given IP address and returns the result.

Main Execution:
    - Connects to the Tor network.
    - Requests a new identity.
    - Prompts the user to enter a website or use a default IP test URL.
    - Sends an HTTP request via Tor.
    - If the default IP test URL is used, prompts the user to enter an IP address for a WHOIS lookup and prints the result.
"""

import socks
import socket
import requests
from stem import Signal
from stem.control import Controller
import subprocess
import re

def connect_to_tor():
    try:
        controller = Controller.from_port(port=9051)
        controller.authenticate(password="test123")  # Provide the password if set in torrc
        print("Connected to Tor")
        return controller
    except Exception as e:
        print(f"Failed to connect to Tor: {e}")
        return None

def request_new_identity(controller):
    try:
        controller.signal(Signal.NEWNYM)
        print("New identity requested")
    except Exception as e:
        print(f"Failed to request new identity: {e}")

def send_request_via_tor(url):
    print(f"Sending request to {url} via Tor...")
    session = requests.Session()
    session.proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }

    try:
        response = session.get(url)
        print(f"Response status code: {response.status_code}")
        print(f"Response content [First 2000]: {response.text[:2000]}")  # Print first 200 characters of the response
    except Exception as e:
        print(f"Failed to send request via Tor: {e}")

def get_whois_info(ip):
    try:
        result = subprocess.run(['whois', ip], capture_output=True, text=True)
        if result.returncode == 0:
            whois_output = result.stdout
            return whois_output
        else:
            return f"WHOIS lookup failed for {ip}: {result.stderr}"
    except Exception as e:
        return f"WHOIS lookup failed for {ip}: {e}"

if __name__ == "__main__":
    # Start a new Tor process (ensure Tor is running)
    # Connect to the running Tor process
    controller = connect_to_tor()
    if controller:
        # Request a new identity
        request_new_identity(controller)

        # Send a request via Tor
        ipTest = "https://httpbin.org/ip"
        userIn = input("Enter website (default[d] for IP): ").lower()
        if userIn == "d" or userIn == "default":
            send_request_via_tor(ipTest)
            ipEnter = input("Enter IP address: ")
            whois_info = get_whois_info(ipEnter)
            print(whois_info)
        else:
            send_request_via_tor(userIn)