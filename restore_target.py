#! /usr/bin/env python

# restore_target.py:	useful to run incase arp_cache_poison.py was unable to restore ARP-Cache

# SYNTAX:	python restore_target.py

##########################################################################################################
##########################################################################################################
##########################################################################################################

from scapy.all import *
import os
import sys
import threading
import signal

interface    = "wlan0"
target_ip    = "192.168.0.106"
target_mac   = "ff:ff:ff:ff:ff:ff"
gateway_ip   = "192.168.0.1"
gateway_mac = "bc:14:01:24:f4:e2"
packet_count = 1000
poisoning    = True

############################################################################################################
############################################################################################################
#	STEP #1:	Perform the below command manually in the CLI of the Attacker-VM to enable IP-Forwarding
###					$ echo 1 > /proc/sys/net/ipv4/ip_forward
############################################################################################################
############################################################################################################

# Sends out appropriate ARP-Packets to network broadcast address to reset ARP-Caches on gateway_ip & target_ip
def restore_target(gateway_ip,gateway_mac,target_ip,target_mac):
    # slightly different method using send
    print "[*] Restoring target..."
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateway_mac),count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff",hwsrc=target_mac),count=5)
	
    # Signals the MAIN-THREAD to terminate & exit
    #os.kill(os.getpid(), signal.SIGINT)

restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
