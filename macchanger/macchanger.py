#!/usr/bin/env python3

import subprocess as sub
import optparse
import re
from colorama import Fore

def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change")
    parser.add_option("-m", "--mac-address", dest="mac", help="Mac address to apply on the chosen interface")
    (options, args) = parser.parse_args()
    if not options.interface or not options.mac:
        parser.error("Please enter args, use --help")
    return options


def change_mac(interface, new_mac):
    print(interface)
    #print(new_mac)
    #sub.call(["ifconfig", "{}".format(interface), "down")
    #sub.call(["ifconfig", "{}".format(interface), "hw", "ether","{}".format(new_mac)])


def check_mac(interface):
    ifconfig = sub.check_output(["ifconfig", interface], universal_newlines=True)
    mac_addr = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig)
    if mac_addr:
        return mac_addr.group(0)
    else:
        print(f"{Fore.RED}[-] Couldn't read MAC address")


options = get_args()
#change_mac(options.interface, options.mac)
current_mac = check_mac(options.interface)
if current_mac == options.mac:
    print(f"{Fore.GREEN}[+] MAC address was successfully changed to {options.mac} ")
else:
    print(f"{Fore.RED}[-] Couldn't change MAC address")
