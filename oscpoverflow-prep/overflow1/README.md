# Buffer overflow TryHackme OSCP Prep

## Contents

Steps to conduct simple buffer overflow

<a href="https://github.com/catx0rr/bufferoverflow/tree/master/vulnserver#installing-the-vuln-server">
	Installation
</a>
<br />
<a href="https://github.com/catx0rr/bufferoverflow/tree/master/vulnserver#spiking">
	Spiking
</a>
<br />
<a href="https://github.com/catx0rr/bufferoverflow/tree/master/vulnserver#fuzzing">
	Fuzzing
</a>
<br />
<a href="https://github.com/catx0rr/bufferoverflow/tree/master/vulnserver#finding-the-offset">
	Finding the Offset
</a>
<br />
<a href="https://github.com/catx0rr/bufferoverflow/tree/master/vulnserver#overwriting-the-eip">
	Overwriting the EIP
</a>
<br />
<a href="https://github.com/catx0rr/bufferoverflow/tree/master/vulnserver#finding-bad-characters">
	Finding bad Characters
</a>
<br />
<a href="https://github.com/catx0rr/bufferoverflow/tree/master/vulnserver#finding-the-right-module">
	Finding the right module
</a>
<br />
<a href="https://github.com/catx0rr/bufferoverflow/tree/master/vulnserver#gaining-access">
	Gaining Access
</a>
---

## Notes before starting
Easy steps to exploit and gain administrative privileges
> Turn off windows defender and run immunity and vulnserver as administrator
> every time you exploit the vulnserver

**Target:** Windows 7 Professional v6.1 Build 7601



## Create A Fuzzer

> We will create a fuzzer on python3 

