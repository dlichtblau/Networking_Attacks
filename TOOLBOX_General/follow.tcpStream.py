import re
import zlib
import cv2

from scapy.all import *

### Still not completed, meant to assemble TCP-Stream Packets (via filters for dst.port[80: web]) and then parse through the packet bits in the field headers for images
###	- Will eventually incorporate image-defined pattern-recognition

pictures_directory = "/home/<home_dir>/pic_carver/pictures"
faces_directory = "/home/<home_dir>/pic_carver/faces"
pcap_file = "tcp_image_parser.pcap"

def http_assembler(pcap_file):
	carved_images = 0
	faces_detected = 0
	
	a = rdpcap(pcap_file)
	sessions = a.sessions()
	
	for session in sessions:
		http_payload = ""
		for packet in sessions[session]:
			try:
				if packet[TCP].dport == 80 or packet[TCP].sport:
					# Reassemble the TCP.STREAM
					http_payload += str(packet[TCP].payload)	
			except:
				pass
