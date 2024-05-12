#!/usr/bin/python3

import scapy.all as scapy
import argparse

def get_target_ip():
    """
    Get the target IP address or range from the command line arguments.
    """
    parser = argparse.ArgumentParser()    
    parser.add_argument("-r", "--range", dest="target_ip", help="Specify an IP Address or a range of IP Addresses")
    options = parser.parse_args()

    if not options.target_ip:
        parser.error("[-] Please specify an IP Address or a range of IP Addresses. Use --help for more details.")

    return options

def scan_network(ip_range):
    """
    Scan the network for devices given an IP address or range.
    """
    arp_header = scapy.ARP(pdst=ip_range)
    ether_header = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_packet = ether_header/arp_header
    answered_list = scapy.srp(arp_request_packet, timeout=1, verbose=False)[0]
    
    client_list = []
    
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    
    return client_list

def print_scan_results(results):
    """
    Print the results of the network scan.
    """
    print("IP Address\t\t MAC Address")
    print("------------------------------------------")
    for client in results:
        print(client['ip'], "\t\t", client['mac'])

if __name__ == "__main__":
    target = get_target_ip()
    scan_results = scan_network(target.target_ip)
    print_scan_results(scan_results)

# Author: Wathsala Dewmina
