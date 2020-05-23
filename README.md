# htb-shocker
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

```
root@kali:~/htb/shoker# nmap -sV -sC -oN shocker.nmap 10.10.10.56
Starting Nmap 7.70 ( https://nmap.org ) at 2020-05-23 14:54 EDT
Nmap scan report for 10.10.10.56
Host is up (0.15s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.06 seconds
```
The page itself just has a picture that doesn't really say much. Inspecting the page doesn't give any extra information either.

List directories of the webpage using [gobuster](https://github.com/OJ/gobuster):
```
root@kali:/usr/share/wordlists# gobuster dir --url 10.10.10.56 --wordlist /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt --timeout 20s
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.56
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        20s
===============================================================
2020/05/23 15:18:57 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/cgi-bin/ (Status: 403)
/index.html (Status: 200)
/server-status (Status: 403)
===============================================================
2020/05/23 15:19:39 Finished
===============================================================
```


