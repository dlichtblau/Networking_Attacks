#!/usr/bin/python2.7

"""
*
* Practical Test Script 
* @daniel lichtblau
*	
"""

import ipaddress
import sys
import time
import os
import subprocess
import urllib2
from scapy.all import *
ip = IP(src="$SRC.IP")
ip.dst = "$DST.IP"
printnt ip