#! /usr/bin/env python

# arping2tex:	arping a network and output a LATEX-Table as a result

# SYNTAX:	python ARPing2tex.py <TARGET_IP>

##########################################################################################################
##########################################################################################################
##########################################################################################################

###############
### STAGE-1 ###		ARP {MAC:IP}-Target Data Collection/Recon
###############

import sys

if len(sys.argv) != 2:
	print("Usage: python arp_ping.py <target_net>\n eg: python arp_ping.py 192.168.20.0/24")
	sys.exit(1)

from scapy.all import srp, Ether, ARP, conf

conf.verb = 0
print r"STAGE - 1:	Sending BROADCAST {ARP-Request}"
print r""

# Uses 'srp()'-Function (Send & Receive Packet) to emit an ARP-Request to specified dst.ip & receive the matching dst.MAC
ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=sys.argv[1]),timeout=2)
#ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=sys.argv[1]),timeout=2, retry=10)

print r"COLLECTED: {|MAC| & |IP|}"

for snd, rcv in ans:
	print rcv.sprintf(r" ***MAC***: |%Ether.src%| & ***IP***: |%ARP.psrc%|")

##########################################################################################################
##########################################################################################################
##########################################################################################################

###############
### STAGE-2 ###
###############

# Build ARP-Requests for poisoning both {TARGET-GW-IP} && {TARGET-IP}

##########################################################################################################
##########################################################################################################
##########################################################################################################
