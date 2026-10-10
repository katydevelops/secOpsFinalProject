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

## 📌 Key Findings

| Investigation area | Evidence-based finding |
|---|---|
| Windows authentication | One source generated 7 failed administrator logons followed by 3 successful network logons |
| Network activity | Related telemetry included SMB (445) and RPC (135); interactive RDP access was not established |
| MySQL | Privileged authentication, enumeration, destructive database operations and ransom-related artifacts were observed |
| Exfiltration | The ransom message claimed data was backed up, but exfiltration was not independently confirmed |
| Host forensics | Compared two post-compromise MDE investigation packages, one before and one after isolation |
| Response | MDE isolation supported network containment; eradication and restoration were not verified |

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


## 🔎 KQL Investigation Queries

The following KQL queries were used during the investigation in Microsoft Defender Advanced Hunting and Azure Log Analytics to examine authentication activity, identify suspicious source IPs and investigate destructive MySQL operations.

<details>
<summary><strong>1. IOC Hunt — External Authentication Sources</strong></summary>

Identified external IP addresses connecting to the honeypot, including authentication attempts, associated accounts and first/last observed activity.

```kql
let MyDevice = "hq-fe29312";
DeviceLogonEvents
| where DeviceName == MyDevice
| where isnotempty(RemoteIP)
| summarize Attempts=count(),
            FirstSeen=min(TimeGenerated),
            LastSeen=max(TimeGenerated),
            Actions=make_set(ActionType),
            Accounts=make_set(AccountName)
    by RemoteIP
| order by Attempts desc
```

</details>

<details>
<summary><strong>2. Windows Authentication Investigation</strong></summary>

Reviewed successful and failed authentication events involving the local administrator and guest accounts during the incident window.

```kql
let START_TIME = datetime(2026-10-06T01:49:58.6192813Z);
let END_TIME = datetime(2026-10-09T02:00:50Z);
let MyDevice = "hq-fe29312";
DeviceLogonEvents
| where TimeGenerated between (START_TIME .. END_TIME)
| where DeviceName == MyDevice
| where AccountName in~ ("administrator", "guest")
| project TimeGenerated, RemoteIP, AccountName, ActionType, LogonType, FailureReason
| order by TimeGenerated asc
```

</details>

<details>
<summary><strong>3. MySQL Authentication Investigation</strong></summary>

Examined MySQL connection events to identify remote authentication activity against the exposed database service.

```kql
let MyDevice = "hq-fe29312";
let START_TIME = datetime(2026-10-06T01:49:58.6192813Z);
let END_TIME = datetime(2026-10-09T02:00:50Z);
MySQLAudit_CL
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where TimeGenerated between (START_TIME .. END_TIME)
| where DeviceName == MyDevice
| where RawData has "Connect"
| project TimeGenerated, DeviceName, RawData
| order by TimeGenerated asc
```

</details>

<details>
<summary><strong>4. Destructive MySQL Activity</strong></summary>

Investigated SQL activity associated with database deletion, ransom-note creation, binary-log manipulation and service shutdown.

```kql
let MyDevice = "hq-fe29312";
let START_TIME = datetime(2026-10-06T01:49:58.6192813Z);
let END_TIME = datetime(2026-10-09T02:00:50Z);
MySQLAudit_CL
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where TimeGenerated between (START_TIME .. END_TIME)
| where DeviceName == MyDevice
| where RawData has "Query"
| where RawData has_any ("DROP DATABASE", "RECOVER_YOUR_DATA", "RESET MASTER", "PURGE BINARY LOGS", "SHUTDOWN")
| project TimeGenerated, RawData
| order by TimeGenerated asc
```

</details>

<details>
<summary><strong>5. Suspected Windows Credential Attack</strong></summary>

Isolated authentication events from `182.180.164.70`, revealing seven failed administrator logons followed by three successful network authentications.

```kql
let SuspectIP = "182.180.164.70";
DeviceLogonEvents
| where DeviceName == "hq-fe29312"
| where RemoteIP == SuspectIP
| project TimeGenerated, RemoteIP, AccountName, ActionType, LogonType, FailureReason
| order by TimeGenerated asc
```

</details>

**Key takeaway:** Correlating Windows authentication events with MySQL audit telemetry helped distinguish credential-guessing activity from confirmed unauthorized access and destructive database operations. Successful network authentication did not independently establish interactive RDP access, and the attacker's claim of data exfiltration remained unverified.

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

The complete report includes the incident timeline, authentication analysis, MySQL investigation, indicators of compromise, KQL analysis, containment actions and host-based DFIR assessment.

**📘 [View Full Incident Response & DFIR Assessment](https://docs.google.com/document/d/1Lxonfqcq7GOItQXcCARFLMjYPtRbDZY3bCDtFnkL43A/edit?usp=sharing)**

---

## ⚠️ Lab Disclaimer

This project was conducted in an authorized cybersecurity lab environment.
The system was intentionally configured and exposed for defensive security
research, incident response and digital forensics practice.
