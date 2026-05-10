# IOCs — Phishing Analysis & Memory Forensics

**Extracted by:** Andy Dela Quarshie Wright  
**Files:** Resume_WesleyTaylor.doc, WKSTN-2961.raw  

---

## Email IOCs

| Type | Value |
|------|-------|
| Sender | westaylor23@outlook.com |
| Recipient | maxine.beck@quicklogisticsorg.onmicrosoft.com |
| Subject | Resume - Application for Junior IT Analyst Role |
| Date | Sun, 20 Aug 2023 18:19:20 +0000 |
| Attachment | Resume_WesleyTaylor.doc |

---

## File IOCs

| Type | Value |
|------|-------|
| Filename | Resume_WesleyTaylor.doc |
| MD5 Hash | 52c4384a0b9e248b95804352ebec6c5b |
| File type | OLE — VBA macro-enabled Word document |
| Macro name | NewMacros.bas — AutoOpen trigger |
| Dropped file | C:\ProgramData\update.js |

---

## Network IOCs

| Type | Value | Detail |
|------|-------|--------|
| C2 domain | boogeymanisback.lol | Malware download and C2 |
| Malicious URL | https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png | Payload download URL |
| C2 IP | 128.199.95.189 | updater.exe C2 server |
| C2 port | 8080 | C2 communication port |

---

## Process IOCs

| Process | PID | Parent | Detail |
|---------|-----|--------|--------|
| WINWORD.EXE | 1124 | — | Opened malicious document |
| wscript.exe | 4260 | 1124 | Executed update.js |
| updater.exe | 6216 | 4260 | Malware payload — C2 beacon |

---

## Persistence IOCs

| Type | Value |
|------|-------|
| Scheduled task name | Updater |
| Trigger | Daily at 09:00 |
| Command | PowerShell -NonI -W hidden IEX from registry |
| Registry key | HKCU:\Software\Microsoft\Windows\CurrentVersion\debug |

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Spearphishing Attachment | T1566.001 | Resume_WesleyTaylor.doc via email |
| User Execution | T1204.002 | Victim opens malicious Word document |
| VBA Macro | T1059.005 | AutoOpen macro executes on document open |
| Ingress Tool Transfer | T1105 | update.png downloaded from boogeymanisback.lol |
| Scheduled Task | T1053.005 | Updater task — daily persistence |
| Fileless Execution | T1059.001 | PowerShell IEX from registry — in-memory execution |
| Command and Control | T1071.001 | updater.exe beaconing to 128.199.95.189:8080 |
