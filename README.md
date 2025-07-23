# SprintsxMicrosoft-summer-Cybersecurity-bootcamp


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
- Volatility 2.6
- FTK Imager
- Kali Linux
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
└──

```

## Disclaimer
This analysis was performed in a safe environment. Do not attempt to execute real malware samples outside of an isolated virtual machine.
