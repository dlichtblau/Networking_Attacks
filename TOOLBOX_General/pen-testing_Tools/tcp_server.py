#!/usr/bin/env python

### Builds a multi-threaded TCP-SERVER

import socket
import threading

bind_ip = "0.0.0.0"
bind_port = 9999

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind((bind_ip,bind_port))

# Tells server to start listening for connections, with a MAX-BACKLOG of connections = 5
server.listen(5)

print "[*] Listening on %s:%d" % (bind_ip,bind_port)

# CLIENT-HANDLING THREAD
def handle_client(client_socket):
	# (1):	print out what the client sends
	request = client_socket.recv(1024)

	print "[*] Received: %s" % request

	# (2):	send back a packet
	client_socket.send("ACK")

	client_socket.close()

# MAIN SERVER-LOOP
while True:
	# CLIENT = CONNECTED(SERVER)
	# Receive Client-Socket into $client
	# Receive Remote-Connection-Details into $addr
	client,addr = server.accept()

	print "[*] Accepted connection from: %s:%d" % (addr[0],addr[1])

	# Create a new Thread-Object passing Client-Socket as ARG to handle_client():	Allows CLIENT-THREAD to handle incoming data
	client_handler = threading.Thread(target=handle_client,args=(client,))
		
	# Start thread for handling CLIENT-CONNECTION
	client_handler.start()
