# 🕵️ OSINT Investigation Report: DarkWebX

## 🔹 Introduction

This report details an Open Source Intelligence (OSINT) investigation conducted on a cybercriminal operating under the alias **DarkWebX**. The aim was to collect publicly available intelligence on their digital footprint, including social media activity, email presence, IP traces, and any data breaches.

The project was part of the **Sprints x Microsoft Summer Cybersecurity Bootcamp** and builds real-world cyber threat hunting and intelligence-gathering skills using ethical, legal methods.

---

## 🔹 Steps Followed:

A structured OSINT approach was followed using:

- `Sherlock`: Identified social media profiles by username.
- `theHarvester`: Discovered email addresses tied to domains.
- `HaveIBeenPwned`: Checked for breached credentials.
- `Hudson Rock`: Analyzed stealer logs and leaked data.
- `IntelligenceX`: Searched for mentions in data breaches, IPs, and leak dumps.
- `Google Dorking`: Tried to Locate indexed dark web/forum content.

Each finding was verified where possible for activity, relevance, and credibility.

---

## 🔹 Findings

### 1. Social Media Accounts (SOCMINT)

Sherlock identified **29** platform hits using the alias `DarkWebX`.

#### ✅ Verified Accounts
- [Reddit](https://www.reddit.com/user/DarkWebX) — **Active**
- [Hudson Rock OSINT API](https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-username?username=DarkWebX) — **Leaked credentials confirmed**

#### the rest were Dormant or invalid/Unreachable Accounts 

📎 *Screenshots and Sherlock logs are included in `screenshots/` and `sherlock_output.txt`*

---

### 2. Email Addresses

Using `theHarvester` across multiple domains,  the only identified result was:

- `yourusername@protonmail.com`

then i checked it via **HaveIBeenPwned**, but it wasn't involved in any data breaches

📎 *included in screenshots folder*

---

### 3. Breached Credentials & Leak Logs

Using **Hudson Rock's OSINT API**, it was confirmed that the alias `DarkWebX` is tied to **2 stealer-infected systems**:

| Date Compromised | Stealer Family | OS             | Computer Name | IP Address    | Malware Path                   |
|------------------|----------------|----------------|----------------|---------------|--------------------------------|
| 2024-02-08       | Lumma          | Windows 10 x64 | Kelvin         | 138.94.\*.**  | `BitLockerToGo.exe`            |
| 2024-01-25       | RedLine        | Windows 10 Home| HP             | 201.218.\*.\* | *Not Found*                    |

#### Top leaked credentials (obfuscated for ethics):

- **Emails**: `d*****@gmail.com`, `k******@hotmail.com`
- **Passwords**: `m*********0`, `N*******d`


---

### 4. IP Addresses

Identified using **IntelligenceX** and **Hudson Rock** as part of leaked dump file metadata:

| IP Address      | Region | Source Dump File                                | Context                              |
|-----------------|--------|--------------------------------------------------|--------------------------------------|
| 74.50.94.211    | US     | `SKYYYYYYY.txt` from `keu1].rar`                | Infostealer dump                     |
| 129.205.113.199 | NG     | `others_153640.txt`                              | Extracted from user desktop          |
| 152.110.151.79  | ZA     | `uu_Valid.txt_Valid.txt`                         | Found in file system dump            |
| 111.95.44.115   | ID     | `email_20240828064922.txt`                       | Recent credential leak               |
| 102.90.58.49    | NG     | `Clipboard.txt`, `Malay leads.txt`              | Found in multiple text files         |
| 146.70.104.254  | GB     | `protonmail.txt`                                 | Associated with ProtonMail leaks     |
| 105.112.161.80  | NG     | `webmail.txt`                                    | Legacy credentials dump              |

📎 *Screenshots saved in screenshots/*

---

## 🔹 Conclusion

The investigation of **DarkWebX** confirmed:

- Social media presence across 25+ platforms, though mostly inactive.
- Association with **info-stealer malware infections**, exposing credentials.
- IP addresses linked to known leaks and malware dump archives.

These findings offer a valuable profile of this actor’s online exposure and compromise history.

---

## 🧩 Attribution

This report was prepared for the **OSINT phase** of the **Sprints x Microsoft Summer Cybersecurity Bootcamp** by me, utilizing only publicly available tools and data.

