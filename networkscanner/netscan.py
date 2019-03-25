#!/usr/bin/env python3

import scapy.all as scapy
import argparse



def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", dest="target", required=True, help="ARP scan a IP / IP Range")
    return parser.parse_args()


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)    
    broadcast = scapy.Ether(dst="FF:FF:FF:FF:FF")
    arp_req_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]
    
    client_list = []
    for elements in answered:
        client_dict = {"ip": elements[1].psrc, "mac": elements[1].hwsrc}
        client_list.append(client_dict)
    return client_list


def print_result(res_list):
    print("IP\t\tMAC Address")
    print("-"*40)
    for client in res_list:
        print(client["ip"] + "\t" + client["mac"])


opts = parse_args()
scan_res = scan(opts.target)
print_result(scan_res)



    
