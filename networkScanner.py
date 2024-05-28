#!/usr/bin/python3

import argparse
import re

welcome_Screen = r"""

 __    __             __             ______
|  \  |  \           |  \           /      \
| $$\ | $$  ______  _| $$_         |  $$$$$$\  _______  ______   _______   _______    ______    ______
| $$$\| $$ /      \|   $$ \        | $$___\$$ /       \|      \ |       \ |       \  /      \  /      \
| $$$$\ $$|  $$$$$$\\$$$$$$         \$$    \ |  $$$$$$$ \$$$$$$\| $$$$$$$\| $$$$$$$\|  $$$$$$\|  $$$$$$\
| $$\$$ $$| $$    $$ | $$ __        _\$$$$$$\| $$      /      $$| $$  | $$| $$  | $$| $$    $$| $$   \$$
| $$ \$$$$| $$$$$$$$ | $$|  \      |  \__| $$| $$_____|  $$$$$$$| $$  | $$| $$  | $$| $$$$$$$$| $$
| $$  \$$$ \$$     \  \$$  $$       \$$    $$ \$$     \\$$    $$| $$  | $$| $$  | $$ \$$     \| $$
 \$$   \$$  \$$$$$$$   \$$$$         \$$$$$$   \$$$$$$$ \$$$$$$$ \$$   \$$ \$$   \$$  \$$$$$$$ \$$


Made By :- Wathsala Dewmina
GitHub  :- https://github.com/WathsalaDewmina/

"""

print(welcome_Screen)

try:
    import scapy.all as scapy
except ImportError:
    print("[-] Scapy is not installed. Please install it by running 'pip install scapy'.")
    exit()

try:
    from tabulate import tabulate

except ImportError:
    print("[-] Tabulate is not installed. Please install it by running 'pip install tabulate'.")
    exit()


def get_target_ip():
    """
    Get the target IP address or range from the command line arguments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--range", dest="target_ip", help="Specify an IP Address or a range of IP Addresses")
    options = parser.parse_args()

    if not options.target_ip:
        parser.error("[-] Please specify an IP Address or a range of IP Addresses. Use --help for more details.")
    elif not is_valid_ip(options.target_ip):
        parser.error("[-] Please provide a valid IP Address or range in CIDR or subnet mask notation. Use --help for more details.")

    return options

def is_valid_ip(ip):
    """
    Validate the provided IP address or range.
    """
    # Regular expression for matching valid IP addresses and ranges
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}(/(\d{1,2}|(\d{1,3}\.){3}\d{1,3}))?$"
    )
    if not ip_pattern.match(ip):
        return False

    # Further validation to check each octet value for IP address
    ip_part = ip.split('/')[0]
    for octet in ip_part.split('.'):
        if not 0 <= int(octet) <= 255:
            return False

    # Validate CIDR notation
    if '/' in ip:
        cidr_part = ip.split('/')[1]
        if cidr_part.isdigit():  # CIDR notation
            if not 0 <= int(cidr_part) <= 32:
                return False
        else:  # Subnet mask notation
            subnet_parts = cidr_part.split('.')
            if len(subnet_parts) != 4:
                return False
            for octet in subnet_parts:
                if not 0 <= int(octet) <= 255:
                    return False

    return True


def scan_network(ip_range):
    """
    Scan the network for devices given an IP address or range.
    """
    try:
        arp_header = scapy.ARP(pdst=ip_range)
        ether_header = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_packet = ether_header / arp_header
        answered_list = scapy.srp(arp_request_packet, timeout=1, verbose=False)[0]

        client_list = []
        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            client_list.append(client_dict)

        return client_list
    except Exception as e:
        print(f"[-] An error occurred while scanning the network: {e}")
        exit()


def print_scan_results(results):
    """
    Print the results of the network scan.
    """
    print("[+] Results....\n")
    headers = ["IP Address", "MAC Address"]
    table = [ [client['ip'], client['mac']] for client in results ]
    print(tabulate(table, headers, tablefmt="grid"))

if __name__ == "__main__":
    try:
        target = get_target_ip()
        scan_results = scan_network(target.target_ip)
        if scan_results:
            print_scan_results(scan_results)
        else:
            print("[-] No devices found in the specified range.")
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user. Exiting...")
        exit()
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")
        exit()

# Author: Wathsala Dewmina
