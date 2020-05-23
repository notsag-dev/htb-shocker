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

Other gobuster commands run taking as base /cgi-bin didn't bring much.

Duckduckdicking a bit noticed that the machine's name refers to the Shell Shock vulnerability (CVE-2014-6271), which is related to the `/cgi-bin` directory.

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


```
msf exploit(linux/http/ipfire_bashbug_exec) > use exploit/multi/http/apache_mod_cgi_bash_env_exec
msf exploit(multi/http/apache_mod_cgi_bash_env_exec) > options

Module options (exploit/multi/http/apache_mod_cgi_bash_env_exec):

   Name            Current Setting  Required  Description
   ----            ---------------  --------  -----------
   CMD_MAX_LENGTH  2048             yes       CMD max line length
   CVE             CVE-2014-6271    yes       CVE to check/exploit (Accepted: CVE-2014-6271, CVE-2014-6278)
   HEADER          User-Agent       yes       HTTP header to use
   METHOD          GET              yes       HTTP method to use
   Proxies                          no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOST                            yes       The target address
   RPATH           /bin             yes       Target PATH for binaries used by the CmdStager
   RPORT           80               yes       The target port (TCP)
   SRVHOST         0.0.0.0          yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT         8080             yes       The local port to listen on.
   SSL             false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                          no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI                        yes       Path to CGI script
   TIMEOUT         5                yes       HTTP read response timeout (seconds)
   URIPATH                          no        The URI to use for this exploit (default is random)
   VHOST                            no        HTTP server virtual host
```

