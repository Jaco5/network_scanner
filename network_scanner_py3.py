#!/usr/bin/env python
# run with python2 command
import scapy.all as scapy
import argparse


# Create arp request directed to broadcast MAC, asking for IP
# Send packet and receive response
# Parse the response
# Print result


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target",
                        dest="target",
                        help="target IP / IP range")
    options = parser.parse_args()
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # this can be any mac address, other applications.
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1)[0]
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def print_result(results_list):
    print("_________________________________\n---> IP:\t---> MAC Address:")
    for client in results_list:
        print("- " + client["ip"] + "\t" + client["mac"])


options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
