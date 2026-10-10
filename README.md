# 🔐 Azure Honeypot — Incident Response & DFIR

## Overview

This project documents the investigation of an intentionally exposed Windows 11
honeypot hosted in Microsoft Azure.

During an approximately 72-hour observation period, the system experienced repeated
internet-based authentication attempts, successful Windows network authentication
and compromise of an exposed MySQL service.

The investigation was conducted using Microsoft Defender for Endpoint, Microsoft
Sentinel, KQL and MDE forensic investigation packages.

### Technologies

`Microsoft Azure` · `Microsoft Defender for Endpoint` · `Microsoft Sentinel` ·
`KQL` · `Windows 11` · `MySQL` · `DFIR`

---

## 🌎 Inbound Authentication Activity

<img width="800" alt="image" src="https://github.com/user-attachments/assets/bdf6aee7-c900-41fd-82f6-0146bfe48a15" />

Public source IP addresses were observed attempting network authentication against
the honeypot from infrastructure geolocated across multiple countries.

Several sources progressed from failed attempts to successful network authentication.

> **Note:** IP geolocation represents observed source infrastructure and does not
> establish the physical location or identity of an attacker.

---

## 🔎 Authentication Investigation

<img width="1000" alt="image" src="https://github.com/user-attachments/assets/b655c03a-df13-4daf-8696-884583f557ef" />


Analysis of Windows authentication telemetry identified repeated failed
administrator logons followed by successful network authentication.

One source generated seven failed administrator authentication attempts followed
by three successful network logons. Related network telemetry showed activity
associated with SMB (445) and RPC (135).

Successful network authentication was confirmed. Interactive RDP access or
post-authentication code execution was not established by these events alone.

---

## 🗄️ MySQL Compromise

The exposed MySQL service also experienced successful privileged authentication.

Investigation of the MySQL audit telemetry identified database discovery,
enumeration, destructive database operations, creation of a ransom database,
ransom-related artifacts and eventual shutdown of the MySQL service.

The attacker's ransom message claimed that data had been backed up. Independent
evidence confirming data exfiltration was not identified during the investigation.

---

## 🔬 Host DFIR Analysis

<img width="800" alt="image" src="https://github.com/user-attachments/assets/85a24378-62a2-4157-a722-2552cb6ec187" />


Two Microsoft Defender investigation packages were analyzed to compare the endpoint
before and after containment.

The first package was collected after compromise but before endpoint isolation,
while the second was collected after isolation. The comparison identified reduced
network state and Microsoft Defender containment artifacts without clear evidence
of newly established persistence between the two snapshots.

Because no clean pre-exposure forensic package was available, the first package
was treated as the earliest available comparative baseline rather than a pristine
pre-compromise baseline.

---

## 🛡️ Containment

<img width="800" alt="image" src="https://github.com/user-attachments/assets/bba3386a-699e-47bb-92b7-2ece87680777" />


The affected endpoint was isolated using Microsoft Defender for Endpoint.

Post-isolation forensic evidence supported successful network containment.
Eradication and restoration were outside the scope of the collected evidence.

---

## 📄 Full Investigation Report

The complete report contains the incident timeline, authentication analysis,
MySQL investigation, indicators of compromise, KQL analysis, containment actions
and host-based DFIR assessment.

### [📄 View Full Incident Response & DFIR Report](YOUR-GOOGLE-DOC-LINK)

---

## ⚠️ Lab Disclaimer

This project was conducted in an authorized cybersecurity lab environment.
The system was intentionally configured and exposed for defensive security
research, incident response and digital forensics practice.
