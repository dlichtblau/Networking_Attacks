#!/usr/bin/env python

import socket

target_host = "127.0.0.1"
target_port = 80

# Create a Socket-Object:	UDP : SOCK_DGRAM
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Connect CLIENT --> SERVER
client.connect((target_host, target_port))

# Send data
client.sendto("AAABBBCCC",(target_host,target_port))

# Receive data
data, addr = client.recvfrom(4096)

print data
