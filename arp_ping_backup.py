#! /usr/bin/env python

# arping2tex:	arping a network and output a LATEX-Table as a result

# SYNTAX:	python ARPing2tex.py <TARGET_IP>

import sys

if len(sys.argv) != 2:
	print("Usage: apring2tex <net>\n eg: arping2tex 192.168.1.0/24")
	sys.exit(1)

from scapy.all import srp, Ether, ARP, conf

conf.verb = 0
print r"STAGE - 1:	Sending BROADCAST {ARP-Request}"
print r""
ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=sys.argv[1]),timeout=2)

print r"COLLECTED: {|MAC| & |IP|}"

for snd, rcv in ans:
	print rcv.sprintf(r" ***MAC***: |%Ether.src%| & ***IP***: |%ARP.psrc%|")

