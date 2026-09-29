+++
date = '2026-09-07T21:16:16+01:00'
draft = true
title = 'Expressway'
+++
## Introduction

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

## ISAKMP, IPSec and IKE

Before continuing down the rabbit hole of the technology in use in this machine, I had to get my head around the terminology being used here.

 - ISAKMP = Internet Security Association and Key Management Protocol
    - This can be thought of as a framework that allows for security associations to be established between two TCP/IP devices/endpoints that would like to talk using some form of authenticity, integrity and/or confidentiality.
 - IPSec = Internet Protocol Security
    - If ISAKMP is the framework for establishing security associations, IPSec refers instead to the actual mecahnisms used to authenticate and maintain confidentiality of infomation being transmitted accross a LAN or VPN.
 - IKE = Internet Key Exchange
    - This term specifically references the key exchange tools used by two endpoints to securely negotiate shared secrets without exposing any sensitive or cryptographically important information over a network.

Whilst all the definitions above form part of the bigger process of VPN security, they all refer to distinct technologies that will be seen throughout the exploitation of this machine.

## Exploring ISAKMP

Before getting too invested into UDP Port 500, I wanted to quickly confirm that the endpoint was actually using ISAKMP. Initially, I did this manually by crafting a basic ISAKMP data packet and sending it to UDP Port 500. The ISAKMP packet structure is documented in the standard RFC 2408. A framework of the packet can be seen below.  
```
                     1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    !                          Initiator                            !
    !                            Cookie                             !
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    !                          Responder                            !
    !                            Cookie                             !
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    !  Next Payload ! MjVer ! MnVer ! Exchange Type !     Flags     !
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    !                          Message ID                           !
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    !                            Length                             !
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Using the above format, a basic ISAKMP packet can be created. This packet below has an initiator cookie of 7 empty bytes followed by 0x01 to identify that the initiator is myself. The responder cookie is left as 8 bytes of all zeros since this will be populated by the ISAKMP server. The next payload byte is 0x01 to tell the message parser that the next payload is a Security Association. Next is version infomation which can be shown by the byte 0x10 to indicate version 1.0 alongside exchange type which is set to 0x02 meaning the exchange is using the Main Mode setting (this will be useful later). The flags value here is also left blank as 0x00. To complete the message header, a message ID is added of 4 0x00 bytes and a length for the whole packet is covered in the next 4 bytes.

Now that the header of the packet is complete, a Security Association is needed. The remainder of the packet encodes the following security association in RFC 2408 format. The contents of this security association is purposefully using outdated Hash, Encryption and Diffie Hellman parameters for maxiumum compatibility with the ISAKMP endpoint.
 - Hash: SHA-256 or SHA-384
 - Encryption: AES-256-CBC or AES-256-GCM
 - DH Group: Group 14 (2048-bit) or higher

```
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    | Next Payload  |   RESERVED    |         Payload Length        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    |              Domain of Interpretation (DOI)                   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    |                          Situation                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    |                                                               |
    ~                       Proposal Payloads                       ~

    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The final packet can be seen below and is sent towards the target using netcat. The interaction can then be monitored using wireshark to see if the ISAKMP server responds.

```bash
ISAKMP_PACKET="\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x58\x00\x00\x00\x3c\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x30\x01\x01\x00\x01\x00\x00\x00\x28\x01\x01\x00\x00\x80\x01\x00\x07\x80\x0e\x00\x80\x80\x02\x00\x02\x80\x04\x00\x05\x80\x03\x00\x01\x80\x0b\x00\x01\x00\x0c\x00\x04\x00\x01\x51\x80"

echo -ne "$ISAKMP_PACKET" | timeout 5 nc -u TARGET_IP 500 | hexdump -C
```

After the test packet is sent and new payload is collected from netcat and therefore confirms that the expressway server is hosting a ISAKMP endpoint.

```bash
echo -ne "$ISAKMP_PACKET" | timeout 5 nc -u expressway.htb 500 | hexdump -C
00000000  00 00 00 00 00 00 00 01  10 ff 52 f4 7a e2 28 69  |..........R.z.(i|
00000010  0b 10 05 00 5c cc 0d 13  00 00 00 38 00 00 00 1c  |....\......8....|
00000020  00 00 00 01 01 10 00 0e  00 00 00 00 00 00 00 01  |................|
00000030  10 ff 52 f4 7a e2 28 69                           |..R.z.(i|
00000038
```

