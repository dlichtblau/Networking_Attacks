
#! /usr/bin/env python

##############################
### (1) SIMPLE ARP-MONITOR ###
##############################
# Uses 'sniff()'-CALLBACK (parameter, prn), with 'store=0' so function will !store anything and continue infinitely

from scapy.all import *

def arp_monitor_callback(pkt):
	if ARP in pkt and pkt[AR[].op in (1,2): # who-is || is at
		return pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")
sniff(prn=arp_monitor_callback, filter="arp", store=0)
