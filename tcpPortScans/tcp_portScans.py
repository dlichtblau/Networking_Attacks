#! /usr/bin/env python

import os
import sys
import time

#####################################
###   Not quite finished yet lol  ###
#####################################


def syn_Scan():
	print "[*] This is the TCP(SYN) Port Scan"
	os.system("nmap -P0 -sS 192.168.20.2")
	#os.system("nmap -sS -n 192.168.20.2 --max-rtt-timeout 5)
	sys.exit(0)

def fin_Scan():
        print "[*] This is the TCP(FIN) Port Scan"
	os.system("nmap -P0 -sF 192.168.20.2")
	#os.system("nmap -sF -n 192.168.20.2 --max-rtt-timeout 5)
        sys.exit(0)

def connect_Scan():
        print "[*] This is the TCP(CONNECT) Port Scan"
	os.system("nmap -P0 -sT 192.168.20.2")
	#os.system("nmap -sT -n 192.168.20.2 --max-rtt-timeout 5)
        sys.exit(0)

def xmas_Scan():
        print "[*] This is the TCP(XMAS) Port Scan"
	os.system("nmap -P0 -sX 192.168.20.2")
	#os.system("nmap -sX -n 192.168.20.2 --max-rtt-timeout 5)
        sys.exit(0)

def null_Scan():
        print "[*] This is the TCP(NULL) Port Scan"
	os.system("nmap -P0 -sN 192.168.20.2")
	#os.system("nmap -sN -n 192.168.20.2 --max-rtt-timeout 5)
        sys.exit(0)

def ack_Scan():
        print "[*] This is the TCP(ACK) Port Scan"
	os.system("nmap -P0 -sA 192.168.20.2")
	#os.system("nmap -sA -n 192.168.20.2 --max-rtt-timeout 5)
        sys.exit(0)

def idle_Scan():
	print "[*] This is the TCP(IDLE) Port Scan"
	os.system("nmap -P0 -sI 192.168.20.2")
	#os.system("nmap -sI -n 192.168.20.2 --max-rtt-timeout 5)
	sys.exit(0)

def udp_Scan():
	print "[*] This is the UDP Port Scan"
	os.system("nmap -sU -n 192.168.20.2")
	#os.system("nmap -sU -n 192.168.20.2 --max-rtt-timeout 5")
	sys.exit(0)

def mainMenu(self):
	print("*** WELCOME TO THE TCP & UDP Port Scanner ***")
	print("List of Executable Attacks:")
	print("	1] TCP(SYN)	Port Scan	=	TCP[Flag=SYN]")
	print("	2] TCP(FIN)	Port Scan	=	TCP[Flag=FIN] | TCP[Flag=RST] | TCP[Flag=RST/ACK]")
	print("	3] TCP(CONNECT)	Port Scan	=	TCP[Flag= SYN > SYN/ACK	> ACK]")
	print("	4] TCP(XMAS)	Port Scan	=	TCP[Flag=All Flags Set]")
	print("	5] TCP(NULL)	Port Scan	=	TCP[Flag=No Flags Set]")
	print("	6] TCP(ACK)	Port Scan	=	TCP[Flag=SYN/ACK]")
	print("	7] TCP[IDLE]	Port Scan")
	print(" 8] UDP		Port Scan")
	print("")
	scan_type = raw_input("[*] Enter an Attack to execute: ")
	print ("[*] You have selected Attack-#:	%s" % scan_type)
	time.sleep(1)
	os.system("clear")

	if scan_type == "1":
		syn_Scan()
	elif scan_type == "2":
		fin_Scan()
	elif scan_type == "3":
		connect_Scan()
	elif scan_type == "4":
		xmas_Scan()
	elif scan_type == "5":
		null_Scan()
	elif scan_type == "6":
		ack_Scan()
	elif scan_type == "7":
		idle_Scan()
	elif scan_type == "8"
		udp_Scan()
	else:
		print "[!!!] Failed to enter an attack between 1] --> 8]"
		sys.exit(0)

mainMenu(raw_input)
