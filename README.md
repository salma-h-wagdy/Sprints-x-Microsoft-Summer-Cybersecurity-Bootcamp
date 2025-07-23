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
- VMware

## Key Findings

### Network Indicators


### Memory Artifacts


### Persistence Mechanism


### IOCs (Indicators of Compromise)


## Directories
malware-analysis-report/
│
├── README.md
├── memory.raw                
├── malware_analysis.pcap    
├── reports/
│   ├── network_report
│   ├── volatility_report
│   └── iocs.txt
├── screenshots of steps taken/
|   volatility analysis on kali linux/
|   wireshark,ipk on windows/  
|       
└── tools_used.md


## Disclaimer
This analysis was performed in a safe environment. Do not attempt to execute real malware samples outside of an isolated virtual machine.
