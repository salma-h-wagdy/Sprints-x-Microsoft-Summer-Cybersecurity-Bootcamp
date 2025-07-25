# SprintsxMicrosoft-summer-Cybersecurity-bootcamp

This repository contains my solutions to the hands-on cybersecurity challenges from the Sprints x Microsoft Summer Cybersecurity Bootcamp, including:

- 🕵️‍♀️ **SOC Task** – Malware Forensics and Threat Detection using Volatility, Wireshark, and YARA.
- 🌐 **OSINT Task** – Tracking a Cybercriminal (DarkWebX) using Sherlock, theHarvester, Hudson Rock, and more.
---

# 1-SOC phase task: Malware Forensic Analysis

## Overview
This project documents the behavioral and forensic analysis of a malware sample executed in a secure, isolated Windows 10 virtual machine. The focus was on analyzing memory and network artifacts post-execution.

## Setup Summary
- Isolated Windows 10 VM with internet disabled.
- Defender, UAC, and updates disabled.
- Malware sample executed and monitored for 60 seconds.
- Memory and network traffic captured using FTK Imager and Wireshark.

## Tools Used
- Wireshark
- Volatility 3
- FTK Imager
- Kali Linux
- Yara
- VMware Workstation

## Key Findings

## Network Indicators
- Repeated malformed DNS responses targeting 85.114.128.127

- HTTP GET request to `23.12.131.222` requesting Flash Player payload (404 Not Found)
```sql
/get/flashplayer/update/current/install/install_all_win_cab_64_ax_sgn.z
```

### Memory Artifacts
- Hidden `cmd.exe` process (PID 6296) visible only via `psscan`
- Injected code found ising malfind + YARA in:

    - `SearchApp.exe` (PID 2428) memory regions:

        - 0x2ba63b80000–0x2ba63c8cfff

        - 0x2ba628b0000–0x2ba629bcfff

        - 0x2ba62150000–0x2ba6224ffff

        - 0x2ba64190000–0x2ba6429cfff

    - MsMpEng.exe (PID 3892):

        - 0x9ab0000–0x9ac1fff

- Suspicious spoofing via msedgewebview2.exe launching SearchApp.exe
- Duplicate SSDT entry for `GetPnpProperty@NT_DISK` (possible anomaly)

### IOCs (Indicators of Compromise)
- RWX memory injection into 
    - SearchApp.exe
    - MsMpEng.exe
- Hidden process `cmd.exe` (PID 6296)
- Fake browser process with embedded WebView CLI


## Disclaimer
This analysis was performed in a safe environment. Do not attempt to execute real malware samples outside of an isolated virtual machine.




---
# 2- OSINT phase task: Track a Cyber Criminal

# OSINT Investigation – Track a Cyber Criminal

## Overview
This project was completed as part of the Sprints x Microsoft Summer Cybersecurity Bootcamp. It applies Open Source Intelligence (OSINT) methods to trace the digital footprint of a threat actor known as **DarkWebX** using publicly available tools and frameworks.

## Objectives
- Identify social media accounts
- Discover associated email addresses
- Check for data breaches (bonus)
- Trace IP addresses from leaked logs
- Document findings in a structured investigation report

## Tools Used
- [Sherlock](https://github.com/sherlock-project/sherlock)
- [theHarvester](https://github.com/laramies/theHarvester)
- [HaveIBeenPwned.py](https://github.com/cheetz/HaveIBeenPwned)
- Google Dorking
- WHOIS lookup
- [Hudson Rock OSINT Tools](https://cavalier.hudsonrock.com)

## Key Findings  ( full report included in the directory of the task :D )
### Social Media Accounts

- 29 platforms identified via Sherlock

- Only Reddit (https://reddit.com/user/DarkWebX) had signs of active use

- Most accounts were dormant or invalid

- Hudson Rock provided verified linkage to infostealer breaches

### Email Addresses

- Only one ProtonMail address identified using theHarvester `yourusername@protonmail.com` 

- No confirmed breaches on HaveIBeenPwned

### Breached Data

- Found via Hudson Rock OSINT API

- Linked to 2 compromised machines:

    - Lumma stealer (Feb 2024)

    - RedLine stealer (Jan 2024)

- Exposed usernames, emails, and password fragments

### Tracked IP Addresses

- IPs extracted from leaked data indexed by IntelligenceX

- Cross-verified using Hudson Rock and Google Dorks

- Example IPs:

    - 74.50.94.211 (US)

    - 129.205.113.199 (NG)

    - 152.110.151.79 (ZA)

    - 138.94.*.** (from Hudson Rock)

- Context: Infostealer logs, desktop dumps, browser artifacts


---
## Directories
```
Sprints-x-Microsoft-Summer-Cybersecurity-Bootcamp/
│
├── README.md
│
├── 1- SOC task/
│   ├── memory.raw
│   ├── memory2.mem
│   ├── malware_analysis.pcap
│   ├── injectedCode.yar
│   ├── tools_used.md
│   |
│   ├── reports/
│   │   ├── network_report
│   │   ├── volatility_report
│   │   └── IOCs.txt
│   |
│   ├── screenshots of steps taken/
│   │   ├── volatility analysis on kali linux/
│   │   │   ├── first trial/
│   │   │   └── second trial/
│   │   └── wireshark,ipk on windows/
│   |
│   └── volatility outputs/
│       ├── first trial/
│       └── second trial/
│           └── malfind dmp files/
└──2- OSINT task/
   ├── osint_report
   ├── Key Findings/
   │   ├── social_media_accounts.txt
   │   ├── emails_found.txt
   │   ├── breached_data.txt
   │   └── ip_addresses.txt
   ├── screenshots/
   ├── Google_Dorks_Used.md
   └── tools_used.md

```