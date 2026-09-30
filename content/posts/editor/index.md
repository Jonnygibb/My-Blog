+++
date = '2026-09-30T09:23:45-04:00'
draft = true
title = 'Editor'
+++
## Introduction

## Enumeration

As per usual, I will begin this machine by performing some enumeration. Nmap is a good place to start. It reveals that the machine is hosting an SSH interface, an nginx web server on port 80 and another web server running Jetty at TCP 8080. The versioning and service discovery scripts are also able to detect that the machine is an ubuntu machine.

```
$ nmap -T4 -sC -sV -p- editor.htb
Starting Nmap 7.98 ( https://nmap.org ) at 2026-09-30 09:25 -0400
Nmap scan report for editor.htb (10.129.231.23)
Host is up (0.015s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Editor - SimplistCode Pro
|_http-server-header: nginx/1.18.0 (Ubuntu)
8080/tcp open  http    Jetty 10.0.20
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
| http-title: XWiki - Main - Intro
|_Requested resource was http://editor.htb:8080/xwiki/bin/view/Main/
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Jetty(10.0.20)
| http-methods: 
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
| http-robots.txt: 50 disallowed entries (15 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/ 
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/ 
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/ 
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/ 
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/ 
|_/xwiki/bin/undelete/
| http-webdav-scan: 
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|   WebDAV type: Unknown
|_  Server Type: Jetty(10.0.20)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.13 seconds
```

I did some initial searching for SSH CVEs based on the ubuntu and OpenSSH version but nothing immediately leaped out as a realistic exploit for this machine. What did stand out was the webservers that were available to explore.

The first webserver is an information page for a new python based IDE called *SimplistCode Pro*. Interestingly, the website hosts debian and windows install media that can be downloaded. I will leave this for now but they could become useful later. Other than the downloads, the webserver does not have much else interesting from an attackers perspective. 

![Webpage promoting the new code editor](editor_page.png)

Following the documentation link from the initial webpage lands the browser on an xwiki site. The wiki seems to only contain one post from user *Neal Bagwell*. The content of the wiki contains a introduction page alongside an installation page which gives instructions for correctly installing the code editor.

![Wiki page containing introduction and install instructions](editor_wiki.png)

Another interesting thing to note was a login page. I tried some default credentials but no luck this time. The login page is useful in other ways however since the page leaks the version number and distribution of the website. It appears to be XWiki Debian 15.10.8 which further confirms it is a linux based host.

![Login for the XWiki instance](editor_login.png)

## XWiki

