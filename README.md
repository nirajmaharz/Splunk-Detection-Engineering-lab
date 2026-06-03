# Splunk SOC Detection Lab

A hands-on detection engineering lab built on a self-hosted Active Directory environment, using Splunk Enterprise to simulate real-world SOC workflows — log ingestion, threat detection, alerting, and dashboarding.

---

## Lab Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    VMware Workstation                    │
│                                                         │
│  ┌──────────────────────┐    ┌───────────────────────┐  │
│  │  Windows Server 2019 │    │     Windows 10        │  │
│  │  DC: marvel.local    │    │  Domain Joined Client │  │
│  │  172.25.1.102        │    │  172.25.1.x           │  │
│  │                      │    │                       │  │
│  │  ┌────────────────┐  │    │  ┌─────────────────┐  │  │
│  │  │ Splunk         │  │    │  │ Splunk UF       │  │  │
│  │  │ Enterprise     │◄─┼────┼──│ Windows TA      │  │  │
│  │  │ (Developer)    │  │    │  └─────────────────┘  │  │
│  │  └────────────────┘  │    └───────────────────────┘  │
│  │  ┌────────────────┐  │                               │
│  │  │ Splunk UF      │  │    ┌───────────────────────┐  │
│  │  │ Windows TA     │  │    │  Parrot OS (Attacker)  │  │
│  │  └────────────────┘  │    │  172.25.1.10           │  │
│  └──────────────────────┘    │  Metasploit / Hydra /  │  │
│                               │  CrackMapExec          │  │
│                               └───────────────────────┘  │
│                    Custom Network: 172.25.1.0/24          │
└─────────────────────────────────────────────────────────┘
```

## Detections Built

All detections are mapped to [MITRE ATT&CK](https://attack.mitre.org/). Each detection lives in `detections/` with a detailed notes explaining the logic, simulation steps, and tuning.

| Detection | Tactic | Technique | Severity | File |
|-----------|--------|-----------|----------|------|
| SMB Brute Force | Credential Access | T1110 | High | [smb_bruteforce.md](detections/smb_bruteforce.md) |
| AS-REP Roasting | Credential Access | T1558.004 | High | [asrep_roasting.md](detections/asrep_roasting.md) |
| Kerberoasting | Credential Access | T1558.003 | Critical | [kerberoasting.md](detections/kerberoasting.md) |
| New Local Admin Created | Persistence | T1136.001 | High | [new_local_admin.md](detections/new_local_admin.spl) |
| Privilege Escalation | Privilege Escalation | T1078 | High | [privilege_escalation.md](detections/privilege_escalation.spl) |
| Suspicious PowerShell Execution | Execution | T1059.001 | Medium | [suspicious_powershell.md](detections/suspicious_powershell.spl) |
| Scheduled Task Created | Persistence | T1053.005 | Medium | [scheduled_task.md](detections/scheduled_task.spl) |



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
│   ├── smb_bruteforce.md
│   ├── asrep_roasting.md
|   ├── kerberoasting.md
│   ├── new-local-admin.md
│   ├── privilege-escalation.md
│   ├── suspicious-powershell.md
│   ├── scheduled-task.md
│   └── pass-the-hash.md
│
├── alerts/
│   └── alert-configs.md        ← Splunk alert settings for each
│
├── dashboards/
│   ├── smb-bruteforce-detection.xml        ← Splunk dashboard export (XML)
│   └── dashboard-guide.md      ← How to import the dashboard
│
└── screenshots/
    └── (All screenshots)
```

## Lab Setup

| Host | Role | IP | OS |
|------|------|----|----|
| Windows Server 2019 | Domain Controller + Splunk Enterprise | 172.25.1.102 | Windows Server 2019 |
| Windows 10 | Domain-joined client | 172.25.1.x | Windows 10 |
| Parrot OS | Attacker machine | 172.25.1.10 | Parrot OS |

---

## Components

| Component | Purpose |
|-----------|---------|
| Splunk Enterprise (Developer License) | SIEM - log ingestion, search, alerting, dashboards |
| Splunk Universal Forwarder | Ships Windows Event Logs to Splunk |
| Splunk Add-on for Microsoft Windows (TA) | Used for field extractions for Windows logs |
| Active Directory (marvel.local) | Generates realistic authentication and directory event logs |
| Sysmon | Endpoint telemetry - process creation, network connections, file events |

---

## Log Sources

| Source | Event IDs | Description |
|--------|-----------|-------------|
| Windows Security Log | 4624, 4625, 4648, 4672, 4720, 4732, 4768, 4771 | Auth, privilege use, account management |
| Windows System Log | 7045, 7036 | Service installs and state changes |
| Sysmon | 1, 3, 7, 11, 13 | Process creation, network, file, registry |


---

## Setup Guide

See [`setup/splunk_setup.md`](setup/splunk_setup.md) for step-by-step instructions:
1. Splunk Enterprise install and index configuration
2. Universal Forwarder deployment
3. Windows TA configuration
4. Sysmon deployment with SwiftOnSecurity config
5. Alert configuration

---

## Attack Simulation

Each detection includes simulation steps using tools available on the attacker machine (Parrot OS):

| Tool | Used For |
|------|----------|
| Hydra | SMB / RDP brute force simulation |
| nxc | SMB enumeration and credential spray |
| Metasploit | Exploit and post-exploitation simulation |
| Atomic Red Team | MITRE ATT&CK technique simulation |
| Impacket | Kerberoasting, Asreproasting, Pass-the-Hash |

---

## Skills Demonstrated

- Detection engineering with SPL (Splunk Processing Language)
- MITRE ATT&CK mapping and threat modeling
- Active Directory attack simulation and log analysis
- SIEM alerting, tuning, and dashboard creation
- Incident triage and SOC analyst workflow
- Windows event log forensics (Security, Sysmon)


---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
- [Windows Security Event Log Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
