# Splunk SOC Detection Lab

A hands-on detection engineering lab built on a Windows Active Directory environment, simulating real-world SOC workflows using Splunk. This project covers threat detection, alerting, and dashboard building — each detection mapped to the MITRE ATT&CK framework.

---

## Lab Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   VMware Workstation                     │
│                                                         │
│  ┌──────────────────────┐   ┌──────────────────────┐   │
│  │  Windows Server 2019 │   │     Windows 10       │   │
│  │  DC: marvel.local    │   │  Domain Joined       │   │
│  │  IP: 172.25.1.102    │   │  (Victim Machine)    │   │
│  │                      │   │                      │   │
│  │  - Splunk 9.x        │   │  - Splunk UF         │   │
│  │  - Splunk UF         │   │  - Windows TA        │   │
│  │  - Windows TA        │   │                      │   │
│  └──────────────────────┘   └──────────────────────┘   │
│                                                         │
│  ┌──────────────────────┐                               │
│  │   Parrot OS          │                               │
│  │   IP: 172.25.1.10    │                               │
│  │   (Attacker)         │                               │
│  │   - Metasploit       │                               │
│  │   - Hydra / nxc                            │
│  │   - Nmap             │                               │
│  └──────────────────────┘                               │
│                                                         │
│         Custom Network: 172.25.1.0/24                   │
└─────────────────────────────────────────────────────────┘
```

---

## Tools & Technologies

| Category | Tool |
|---|---|
| SIEM | Splunk Enterprise (Developer License) |
| Log Forwarding | Splunk Universal Forwarder |
| Log Parsing | Splunk Add-on for Microsoft Windows (TA) |
| Domain | Windows Server 2019 — Active Directory (marvel.local) |
| Endpoint | Windows 10 (domain joined) |
| Attacker | Parrot OS — Hydra, CrackMapExec, Metasploit |
| Framework | MITRE ATT&CK |

---

## Detections Built

| # | Detection Name | MITRE Technique | Event IDs | Severity |
|---|---|---|---|---|
| 1 | SMB Brute Force | T1110 — Brute Force | 4625 (Logon Type 3) | Medium / High / Critical |
| 2 | Brute Force → Successful Login | T1110.001 | 4625 + 4624 | High |
| 3 | New Local Admin Account Created | T1136.001 | 4720 + 4732 | High |
| 4 | Privilege Escalation — Special Logon | T1078 | 4672 | Medium |
| 5 | Suspicious PowerShell Execution | T1059.001 | Sysmon EID 1 | High |
| 6 | Scheduled Task Created | T1053.005 | 4698 | Medium |
| 7 | Pass-the-Hash (Lateral Movement) | T1550.002 | 4624 Logon Type 3 + NTLM | Critical |

---

## Repository Structure

```
Splunk-detection-engineering-lab/
│
├── README.md                   ← This file
│
├── setup/
│   ├── universal-forwarder.md  ← UF installation & inputs.conf
│   
│
├── detections/
│   ├── smb-brute-force.md
│   ├── brute-force-success.md
│   ├── new-local-admin.md
│   ├── privilege-escalation.md
│   ├── suspicious-powershell.md
│   ├── scheduled-task.md
│   └── pass-the-hash.md
│
├── alerts/
│   └── alert-configs.md        ← Splunk alert settings for each detection
│
├── dashboards/
│   ├── smb-bruteforce-detection.xml        ← Splunk dashboard export (XML)
│   └── dashboard-guide.md      ← How to import the dashboard
│
└── screenshots/
    └── (All screenshots)
```

---

## Setup Guide

### Prerequisites
- VMware Workstation with Windows Server 2019 and Windows 10 VMs
- Splunk Enterprise installed on Windows Server 2019
- Splunk Developer License (60 days) activated
- Splunk Universal Forwarder installed on all Windows hosts
- Splunk Add-on for Microsoft Windows (TA) installed

### 1. Configure Universal Forwarder

Edit `inputs.conf` on each Windows host:

```ini
[WinEventLog://Security]
index = winserver2019
disabled = 0
start_from = oldest
current_only = 0
evt_resolve_ad_obj = 1

[WinEventLog://System]
index = winserver2019
disabled = 0

[WinEventLog://Application]
index = winserver2019
disabled = 0
```

Restart the forwarder:
```powershell
Restart-Service SplunkForwarder
```

### 2. Verify Logs in Splunk

```spl
index=winserver2019 | stats count by EventCode | sort -count
```

---

## Key Learnings

- Built end-to-end detection pipeline from log ingestion to alerting
- Mapped every detection to MITRE ATT&CK techniques
- Simulated real attacks from a Parrot OS attacker to generate authentic telemetry
- Tuned thresholds to minimize false positives (e.g. brute force threshold set to 10 failures in 2 minutes)
- Built a SOC dashboard for centralized visibility

---

## Author

**Niraj Maharzhan**  
Cybersecurity | Network Security | Detection Engineering  
OSCP | CRTP | CEH Practical | CCNA | RHCSA | PCNSA  
[LinkedIn](https://linkedin.com/in/nirajmaharz) | [Blog](https://nirajmaharz.github.io)
