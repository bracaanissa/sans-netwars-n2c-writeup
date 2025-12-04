## ⚠️ Disclaimer

This repository contains my personal notes and methodology for completing the **SANS NetWars N2C CTF**.  
It is intended **only for educational and defensive cybersecurity learning**.

- I do **not** claim ownership of the lab environment or challenge material.  
- This write-up **does not reveal proprietary solutions, answer keys, or internal SANS content**.  
- All notes provided here describe **my own actions, commands, and reasoning** during the challenge.

If you are participating in the same event, please respect SANS rules and avoid using this repository as a shortcut.  
Always follow the guidelines of your CTF provider and use this material **responsibly and ethically**.


# 🛡️ SANS NetWars **N2C CTF** — Windows + Elastic Forensics Write-Up  
*A structured walkthrough of my methodology, commands, and analysis steps across the Windows host, Linux host, and Elastic Stack.*

---

## 📚 Table of Contents
- [Overview](#overview)
- [Environment Setup](#environment-setup)
- [Windows Host Challenges](#windows-host-challenges)
  - [1. Host File Inspection](#1-host-file-inspection)
  - [2. User Downloads Secret](#2-user-downloads-secret)
  - [3. Odd Service Investigation](#3-odd-service-investigation)
  - [4. Suspicious Process](#4-suspicious-process)
  - [5. TCP Port Enumeration](#5-tcp-port-enumeration)
  - [6. Registry Key: HideFileExt](#6-registry-key-hidefileext)
  - [7. Persistence Mechanisms](#7-persistence-mechanisms)
- [Elastic Stack (ELK) Challenges](#elastic-stack-elk-challenges)
  - [8. Phishing Email Identification](#8-phishing-email-identification)
  - [9. Host Contacting Attacker](#9-host-contacting-attacker)
  - [10. Malware Executed After Download](#10-malware-executed-after-download)
  - [11. Outbound Connection (Sysmon EventID 3)](#11-outbound-connection-sysmon-eventid-3)
  - [12. IPC Pipe Name (Privilege Escalation)](#12-ipc-pipe-name-privilege-escalation)
- [Linux Host Challenge](#linux-host-challenge)
- [Key Takeaways](#key-takeaways)
- [Notes About SANS Writeups](#notes-about-sans-writeups)

---

## 📝 Overview
This write-up documents my approach to solving the **SANS NetWars N2C CTF**, focusing on:

- Windows forensics  
- Sysmon event analysis  
- Registry persistence mechanisms  
- Elastic Stack (Kibana) log correlation  
- Linux host process enumeration  

All flags are **intentionally excluded** in compliance with ethical transparency.

---

## 🖥️ Environment Setup
The CTF provides:

- A Windows VM (Guacamole access)  
- A Linux VM with shell access  
- An Elastic Stack instance (`Discover`) for log analysis  

All investigations were performed using **PowerShell**, **Linux CLI**, and **Kibana Discover**.

---

# 🪟 Windows Host Challenges

---

## 1. Host File Inspection
The Windows `hosts` file is located at:

```
C:\Windows\System32\drivers\etc\hosts
```

Command:
```powershell
Get-Content "C:\Windows\System32\drivers\etc\hosts"
```

---

## 2. User Downloads Secret
List all user `Downloads` directories:

```powershell
Get-ChildItem -Path C:\Users -Directory |
ForEach-Object {
  $d = Join-Path $_.FullName 'Downloads'
  if (Test-Path $d) {
    Write-Output "---- $($_.Name) ----"
    Get-ChildItem -Path $d -File -Force
  }
}
```

Then read the discovered file:
```powershell
Get-Content "C:\Users\<USERNAME>\Downloads\secret.txt"
```

---

## 3. Odd Service Investigation
Identify a suspicious service:

```powershell
Get-CimInstance -Class Win32_Service |
Where-Object { $_.Name -match 'OddService' }
```

---

## 4. Suspicious Process
Check for processes with unusual names:

```powershell
Get-Process | Where-Object { $_.Name -match 'SSQ' } | Select Name,Id
```

---

## 5. TCP Port Enumeration
Find which port a suspicious process is listening on:

```powershell
Get-NetTCPConnection | Where-Object { $_.OwningProcess -eq <PID> }
```

---

## 6. Registry Key: HideFileExt
Retrieve the value of **HideFileExt**:

```powershell
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name HideFileExt
```

---

## 7. Persistence Mechanisms
Five persistence hooks were present. Tools used:

### ✔ Scheduled Tasks
```powershell
Get-ScheduledTask | Where-Object { $_.TaskName -match 'SSQ' }
```

### ✔ Registry Run Key (HKCU)
```powershell
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
```

### ✔ Startup Folder
```powershell
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -Force
```

### ✔ Services triggering payload
Reviewed with:
```powershell
Get-CimInstance Win32_Service | Select Name,DisplayName,PathName
```

### ✔ WMI Event Consumers
```powershell
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer
```

---

# 🧠 Elastic Stack (ELK) Challenges

---

## 8. Phishing Email Identification  
Switch to `Discover`, filter for **EmailProxy** events:

```text
event_source:"EmailProxy"
```

Look for the one email log whose `event.ReceivedIP1` or `event.ReceivedIP2` differed from the network's normal pattern.

---

## 9. Host Contacting Attacker
Filter HTTP traffic:

```text
event_source:"HTTPProxy" AND event.url:*howtosavethecabal.zip*
```

Look at:

- `event.host`
- `event.ip`

The host that reached out to attacker infrastructure was identified via this log.

---

## 10. Malware Executed After Download (Sysmon ID 1)
Process creation logs:

```text
event.EventID:1 AND event.SourceName:"Microsoft-Windows-Sysmon" AND message:*yppilc*
```

Extract:

- `event.ProcessID`  
- `event.CommandLine`  

---

## 11. Outbound Connection (Sysmon ID 3)
Network connection logs from the payload process:

```text
event.EventID:3 AND event.SourceName:"Microsoft-Windows-Sysmon" AND event.ProcessID:<PID>
```

Add fields:

```
event.DestinationIp
event.DestinationPort
```

Locate the outbound connection to the attacker.

---

## 12. IPC Pipe Name (Privilege Escalation)
Meterpreter’s **getsystem** uses named pipes.

Sysmon Event ID 17 = Pipe Created.

Search:

```text
event.EventID:17 AND message:*pipe*
```

Look for a short named pipe:

```
\\.\pipe\<6 chars>
```

---

# 🐧 Linux Host Challenge

Identify malware executed by the **henchman** user:

```bash
ps -u henchman -o pid,cmd
```

Output revealed a suspicious executable in the user’s home directory.

---

# 🧩 Key Takeaways
- Leveraged **PowerShell** to enumerate services, scheduled tasks, startup folders, registry keys, and WMI consumers.  
- Used **Sysmon** Event IDs (1, 3, 17) to trace process creation, outbound network connections, and pipe creation.  
- Used **Elastic Discover** to correlate logs, identify phishing activity, and track host communications.  
- Applied threat hunting techniques: pattern searching, event correlation, and pivoting based on IOCs.  

---

# 📝 Notes About SANS Writeups
SANS does **not** prohibit writeups *as long as you:*
- Do **not** reveal flags  
- Do **not** copy proprietary challenge text  
- Do **not** leak solutions for proctored exams  

Non-flag, educational walkthroughs **are allowed** and are commonly shared on GitHub.

---

# ✔️ End of Write-Up


