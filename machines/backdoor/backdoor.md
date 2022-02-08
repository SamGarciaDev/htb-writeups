## Enumeration

The IP is 10.10.11.125, I will add it to /etc/hosts

nmap -p- --open -sS -v -n -Pn <ip> -oG allPorts
  
It returns ports 22, 80 and 1337 as being open. 
  
I will run a nmap script to list the services and their versions that are running on each open port
  
nmap -p22,80,1337 -sCV <ip> -oN targeted
