# Phishing Analysis And Memory Forensics

<h2>Project Overview</h2>
<p>This project documents the end-to-end investigation of a targeted phishing attack against a Human Resources Specialist. The attacker utilized a malicious resume attachment to gain a foothold, establish a Command and Control (C2) callback, and implement advanced persistence mechanisms via scheduled tasks.The investigation covers Email Header Analysis, Artifact Extraction, and Volatile Memory Forensics using the Volatility Framework.</p> </br>

<h2>Technical Skills Demonstrated</h2>
<p><b>Email Security</b>:  Analyzing SPF/DKIM/DMARC (via headers) and identifying malicious senders.

<b>Malware Triage</b>:  Calculating MD5 hashes and identifying malicious URLs and domains.

<b>Memory Forensics (Volatility)</b>: Using windows.filescan, windows.pslist, and windows.memmap to extract attacker commands from a RAM dump.

<b>Persistence Analysis</b>: Identifying malicious scheduled tasks (schtasks) and Base64 encoded PowerShell commands.
 </p> </br>

<h2>Investigation Walktrough</h2>
<p>
  <h3>Phishing Triage</h3>
The attack began with a spoofed job application email.

Attacker Email: westaylor23@outlook.com
Victim: maxine.beck@quicklogisticsorg.onmicrosoft.com

 <img src="https://i.imgur.com/fcIkhU7.png" height="80%" width="80%" alt="Investigation Walkthrough"/>

 Malicious Attachment: Resume_WesleyTaylor.doc (MD5: 52c4384a0b9e248b95804352ebec6c5b)
 
 <img src="https://i.imgur.com/5q2RRo9.png" height="80%" width="80%" alt="Investigation Walkthrough"/>

 <h3>Malware Delivery & C2</h3>
Opening the document triggered a download from a remote server.

 URL is used to download the stage 2 payload: https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png
  <img src="https://i.imgur.com/kHWZnYw.png" height="80%" width="80%" alt="Investigation Walkthrough"/>

  The process that executed the newly downloaded stage 2 payload: wscript.exe
  
 <img src="https://i.imgur.com/Twwawjp.png" height="80%" width="80%" alt="Investigation Walkthrough"/>

  The PID of the process that executed the stage 2 payload: 4260
 
 <img src="https://i.imgur.com/kxgJQip.png" height="80%" width="80%" alt="Investigation Walkthrough"/>

  The URL used to download the malicious binary executed by the stage 2 payload: https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe
 
 <img src="https://i.imgur.com/yyxOCgt.png" height="80%" width="80%" alt="Investigation Walkthrough"/>

  The PID of the malicious process used to establish the C2 connection: 6216
  
 <img src="https://i.imgur.com/x53GBxQ.png" height="80%" width="80%" alt="Investigation Walkthrough"/>

 <h3>Memory Analysis & Persistence</h3>

 The full file path of the malicious email attachment based on the memory dump: C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc
 
 <img src="https://i.imgur.com/GKyoTnM.png" height="80%" width="80%" alt="Investigation Walkthrough"/>

 The full command used by the attacker to maintain persistent access: schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR ‘C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \”IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))\”’
 
 <img src="https://i.imgur.com/0b7G7AB.png" height="80%" width="80%" alt="Investigation Walkthrough"/>
  
 </p>
