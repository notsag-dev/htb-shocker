# htb-lame
This is my [Hack the box](https://www.hackthebox.eu/)'s Shoker machine write-up.

## Machine
OS: GNU/Linux

IP: 10.10.10.56

Difficulty: Easy

## Enumeration
[Nmap](https://github.com/nmap/nmap) scan on the target:

`nmap -sV -sC -oN shocker.nmap 10.10.10.56`

Flags:
 - `-sV`: Version detection
 - `-sC`: Script scan using the default set of scripts
 - `-oN`: Output in normal nmap format
