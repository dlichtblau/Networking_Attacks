#!/usr/bin/python

from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
import sys
import os
from datetime import datetime
from time import *
import threading
import signal

try:
	target = raw_input("[*] Enter Target IP: ")
	min_port = raw_input("[*] Enter Minimum Port#: ")
	max_port = raw_input("[*] Enter Maximum Port#: ")

	try:
		if int(min_port) >= 0 and int(max_port) >= 0 and int (max_port) >= int(min_port):
			pass
		else:
			print "\n[!] Invalid Range of Ports"
			print "[!] Exiting ..."
			sys.exit(1)
	except Exception:
		print "\n[!] Invalid Range of Ports"
		print "[!] Exiting ..."
		sys.exit(1)
except KeyboardInterrupt:
	print "\n[*] User Requested Shutdown ..."
	print "[*] Exiting ..."
	sys.exit(1)

ports = range(int(min_port), int(max_port) + 1)
start_clock = datetime.now()
# Flag set values
SYNACK = 0x12
RSTACK = 0X14

############################################################################################################

def checkhost(ip):
	conf.verb = 0
	try:
		ping = sr1(IP(dst = ip)/ICMP())
		print "\n[*] Target is 'UP' >>> Beginning TCP-SYN_SCAN ..."
	except Exception:
		print "\n[*] Could not resolve Target-IP:	Target-IP is ... (a) Invalid || (b) Blocking Pings"
		print "[*] Exiting ..."
		sys.exit(1)

def scanport(port):
	srcport = RandShort()
	conf.verb = 0

	# Store SENT && RECEIVED packets
	SYNACK_pkt = sr1(IP(dst = target)/TCP(sport = srcport, dport = port,flags = "S"))
	pkt_flags = SYNACK_pkt.getlayer(TCP).flags

	# Extract flags from RECEIVED packets && assign them to a variable (pkt_flags)
	if pkt_flags == SYNACK:
		return True
	else:
		return False

	# Craft the subsequent RST packet SENT to close the TCP-Connection without response
	RST_pkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R")
	send(RST_pkt)

###################
###	   MAIN	    ###
###################
checkhost(target)
print "[*] Scanning STARTED @: "+ strftime("%H:%M:%S") + "!\n"

for port in ports:
	status = scanport(port)
	if status == True:
		print "Port " + str(port) + ": OPEN"
#
#try:#
#	# write out the captured packets to 'arper.pcap'
#	print "[*] Writing packets to 'stealthSYN_scan_saved2.pcap'"
#	wrpcap('stealthSYN_scan_saved2.pcap',packets)
#
#	status == False
#	sys.exit(0)
#except KeyboardInterrupt:
#	print "\n[*] User Requested Shutdown ..."
#	print "[*] Exiting ..."
#	sys.exit(1)

stop_clock = datetime.now()
total_time = stop_clock - start_clock
