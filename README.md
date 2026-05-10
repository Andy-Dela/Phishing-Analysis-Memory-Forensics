# Phishing Analysis & Memory Forensics

**Analyst:** Andy Dela Quarshie Wright  
**Role:** SOC Level 1 Analyst  
**Tools:** Thunderbird, olevba, oletools, Volatility, strings  
**Files Analysed:** Resume - Application for Junior IT Analyst Role.eml, Resume_WesleyTaylor.doc, WKSTN-2961.raw  

---

## Overview

End-to-end phishing investigation combining email analysis, malicious document inspection, and memory forensics. A phishing email disguised as a job application delivered a macro-enabled Word document to victim maxine.beck@quicklogisticsorg. The macro downloaded and executed malware, established C2 communication, and set up persistence via scheduled tasks. Full attack chain reconstructed using static and dynamic analysis tools.

---

## Incident Summary

| Field | Detail |
|-------|--------|
| Victim | maxine.beck@quicklogisticsorg.onmicrosoft.com |
| Sender | westaylor23@outlook.com |
| Subject | Resume - Application for Junior IT Analyst Role |
| Date | Sun, 20 Aug 2023 18:19:20 +0000 |
| Attachment | Resume_WesleyTaylor.doc |
| MD5 Hash | 52c4384a0b9e248b95804352ebec6c5b |
| Malware family | VBA Macro Dropper |
| C2 domain | boogeymanisback.lol |
| C2 IP | 128.199.95.189 port 8080 |
| Persistence | Scheduled task — Updater — daily at 09:00 |
| Malicious process | updater.exe (PID 6216) |

---

## Investigation Structure

- [Phase 1 — Email Analysis](investigation/phishing-analysis.md)
- [Phase 2 — Memory Forensics](memory-forensics/memory-analysis.md)
- [IOCs](iocs/iocs.md)
- [Screenshots](screenshots/)

---

## Attack Chain

```
Phishing email received by maxine.beck
        ↓
Resume_WesleyTaylor.doc opened in Microsoft Word
        ↓
AutoOpen VBA macro executes on document open
        ↓
Macro downloads update.png from boogeymanisback.lol
        ↓
Payload saved as C:\ProgramData\update.js
        ↓
wscript.exe executes update.js
        ↓
updater.exe spawned — connects to 128.199.95.189:8080 (C2)
        ↓
Scheduled task created — Updater runs daily at 09:00 (persistence)
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|-----|-------------|
| Spearphishing Attachment | T1566.001 | Resume_WesleyTaylor.doc via email |
| User Execution | T1204.002 | Victim opens malicious Word document |
| VBA Macro | T1059.005 | AutoOpen macro executes on document open |
| Ingress Tool Transfer | T1105 | update.png downloaded from boogeymanisback.lol |
| Scheduled Task | T1053.005 | Updater task for persistence |
| Command and Control | T1071.001 | updater.exe beaconing to 128.199.95.189:8080 |

---

## Certifications

- CompTIA Security+
- TryHackMe SOC Level 1
- Google Cybersecurity Professional Certificate
