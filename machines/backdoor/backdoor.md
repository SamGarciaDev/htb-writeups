## Enumeration

The IP is 10.10.11.125, I will add it to /etc/hosts

Let's start off by enumerating the open ports:

`nmap -p- --open -sS -v -n -Pn backdoor.htb -oG allPorts`
  
It returns ports 22, 80 and 1337 as being open. 
  
I will run a nmap script to list the services and their versions that are running on each open port
  
`nmap -p22,80,1337 -sCV <ip> -oN targeted`
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b4:de:43:38:46:57:db:4c:21:3b:69:f3:db:3c:62:88 (RSA)
|   256 aa:c9:fc:21:0f:3e:f4:ec:6b:35:70:26:22:53:ef:66 (ECDSA)
|_  256 d2:8b:e4:ec:07:61:aa:ca:f8:ec:1c:f8:8c:c1:f6:e1 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: WordPress 5.8.1
|_http-title: Backdoor &#8211; Real-Life
1337/tcp open  waste?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

If you try to access via browser you will get an innocent website, where you can't do much.

Let's try to list subdirectories using wfuzz

`wfuzz -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt -u "backdoor.htb/FUZZ" --hc=404 -c`
```
=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================
000000238:   301        9 L      28 W       317 Ch      "wp-content"
000000765:   301        9 L      28 W       318 Ch      "wp-includes"
000006941:   301        9 L      28 W       315 Ch      "wp-admin"
```
