#!/usr/bin/env python

import socket

### ASSUMPTIONS:
#				I)		Connection will always succeed
#				II)		Server always expects data to come firstly from Client
#				III)	Server will always reply in a timely fashion

target_host = "www.google.com"
target_port = 80

# Create a Socket-Object:	TCP : SOCK_STREAM
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect CLIENT --> SERVER
client.connect((target_host, target_port))

# Send data
client.send("GET / HTTP/1.1\r\nHost: google.com\r\n\r\n")

# Receive data
response = client.recv(4096)

print response
