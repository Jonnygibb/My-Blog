+++
date = '2026-09-07T21:16:16+01:00'
draft = true
title = 'Expressway'
+++
## Enumeration

To begin working on the expressway machine, I started by performing a TCP port scan of all ports. After only finding Port 22 (SSH), I ran nmap again with version information and scripts enabled to help uncover some more information.
```
nmap -T4 -sC -sV expressway.htb

Starting Nmap 7.98 ( https://nmap.org ) at 2026-09-07 17:05 -0400                                            
Nmap scan report for expressway.htb (10.129.238.52)                                                          
Host is up (0.014s latency).                                                                                 
Not shown: 999 closed tcp ports (reset)                                                                      
PORT   STATE SERVICE VERSION                                                                                 
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)                                                  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                                                      
                                                                                                             
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .               
Nmap done: 1 IP address (1 host up) scanned in 1.07 seconds
```
Having only found SSH, and ruling out any easy exploits based on the version of OpenSSH presented, I decided to explore the UDP ports available on the machine. The results returned isakmp which I've encountered before in a previous piece of work. I knew it was associated with the protocols available for VPN connections. I took some time to research isakmp since I suspected this would be the crux to beating this machine.
```
sudo nmap -T4 -sU -sV -sC expressway.htb

[sudo] password for kali: 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-09-07 17:27 -0400
Stats: 0:05:13 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 40.55% done; ETC: 17:40 (0:07:39 remaining)
Nmap scan report for expressway.htb (10.129.238.52)
Host is up (0.014s latency).
Not shown: 935 closed udp ports (port-unreach), 64 open|filtered udp ports (no-response)
PORT    STATE SERVICE VERSION
500/udp open  isakmp?
| ike-version: 
|   attributes: 
|     XAUTH
|_    Dead Peer Detection v1.0
| fingerprint-strings: 
|   IKE_MAIN_MODE: 
|_    "3DUfw
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
```
