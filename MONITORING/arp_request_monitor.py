#! /usr/bin/env python

# arp_request_monitor:	- Constantly monitors all interfaces on a machine
#				- Use of 'store=0' avoids storage in memory (system memory depletion)
#			- Prints all monitored ARP-Requests

# SYNTAX:	python arp_request_monitor.py

from scapy.all import srp, Ether, ARP, conf, sniff

def arp_monitor_callback(pkt):
	if ARP in pkt and pkt[ARP].op in (1,2):# "who has" || "who is at"
		return pkt.sprintf(" ***MAC***: |%ARP.hwsrc%| & ***IP***: |%ARP.psrc%|")

print r"COLLECTED: {|MAC| & |IP|}"
sniff(prn=arp_monitor_callback, filter="arp", store=0)
