# Room: BoogeyMAN 2  
[TryHackMe Link](https://tryhackme.com/room/boogeyman2)  
**Difficulty:** Medium  
**Date:** 14/08/2025  
**Status:** Completed  

---

## Introduction  
This is my walkthrough of the Boogeyman 2 challenge from TryHackMe, the second in a series of capstone challenges for the SOC Level 1 path.  
The challenge is a multi-part DFIR (Digital Forensics & Incident Response) investigation focusing on a fictional threat actor called the Boogeyman.  

---

## Challenge Scenario  
Quick Logistics LLC suffered an attack from the Boogeyman and improved its defenses. Unfortunately, the threat actor returned with updated tactics, techniques, and procedures (TTPs).  

- Maxine, an HR Specialist, received a malicious resume via email.  
- This attachment compromised her workstation.  
- The SOC team flagged suspicious commands, prompting a full DFIR investigation.  

**Task:** Analyze the artefacts, emails, and memory dump to unmask the Boogeyman’s methods.  

---

## Walkthrough & Questions  

**Q1: What email was used to send the phishing email?**  
Opened `Resume – Application for Junior IT Analyst Role.eml` → found in **From:** field of email header.  

**Q2: What is the email of the victim employee?**  
Found in the **To:** field in the same header.  

**Q3: What is the name of the attached malicious document?**  
Searched for `attachment` in the `.eml` file → located filename in `Content-Disposition` field.  

**Q4: What is the MD5 hash of the malicious attachment?**  
Downloaded attachment → ran:  

```bash
md5sum Resume_WesleyTaylor.doc
````

**Q5: What URL is used to download the stage 2 payload?**
Analyzed the document with `olevba`:

```bash
olevba Resume_WesleyTaylor.doc
```

Extracted URL from VBA macros.

**Q6: What is the name of the process that executed the stage 2 payload?**
Discovered through macro execution analysis.

**Q7: What is the full file path of the malicious stage 2 payload?**
Extracted during analysis of downloaded payload from Q5.

**Q8: What is the PID of the process that executed the stage 2 payload?**
Analyzed memory dump with Volatility 3:

```bash
vol -f WKSTN-2961.raw windows.pstree
```

**Q9: What is the parent PID of the process that executed the stage 2 payload?**
Visible in Volatility `pstree` output.

**Q10: What URL is used to download the malicious binary executed by stage 2 payload?**
Dumped child process memory:

```bash
vol -f WKSTN-2961.raw windows.memmap --pid <CHILD-PID> --dump
strings pid.dmp | grep files.boogeymanisback.lol
```

Also confirmed via `strings` on full dump:

```bash
strings WKSTN-2961.raw | grep files.boogeymanisback.lol
```

**Q11: What is the PID of the malicious process used to establish the C2 connection?**
Identified via Volatility `pstree` and `netscan`.

**Q12: What is the full file path of the malicious process used to establish the C2 connection?**
Verified with Volatility `cmdline` plugin.

**Q13: What is the IP and port of the C2 connection?**
Checked with Volatility `netscan`:

```bash
vol -f WKSTN-2961.raw windows.netscan | grep 6216
```

**Q14: What is the full file path of the malicious email attachment based on memory dump?**
Located in Outlook temp folder:

```bash
vol -f WKSTN-2961.raw windows.filescan | grep Resume
```

**Q15: What is the full command used to maintain persistence?**
Found malicious scheduled task:

```bash
strings WKSTN-2961.raw | grep -i schtasks
```

---

## Conclusion

✅ Mission accomplished!
We confirmed that the Boogeyman gained access via a malicious email attachment, downloaded a second-stage payload, established C2 communication, and maintained persistence with a scheduled task (`schtasks`).

This challenge was an excellent simulation of a real-world DFIR case study, combining:

* Email analysis
* Memory forensics
* Malware investigation
* Persistence detection

---

## Tools & References

* [Olevba](https://github.com/decalage2/oletools/wiki/olevba)
* [Volatility 3](https://github.com/volatilityfoundation/volatility3)
* Volatility Command Reference
* [Microsoft Learn – schtasks](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks)
* [MITRE ATT\&CK – Scheduled Task (T1053.005)](https://attack.mitre.org/techniques/T1053/005/)

