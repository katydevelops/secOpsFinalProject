# 🔐 Azure Honeypot — Incident Response & DFIR Capstone

<img width="1000" alt="Azure Honeypot header image" src="https://github.com/user-attachments/assets/41e136c5-1264-4c9a-b22e-8844ad5b6534" />

## 🔎 Overview

This project documents an approximately 72-hour security investigation of an intentionally exposed Windows 11 honeypot hosted in Microsoft Azure.

During the observation period, the endpoint experienced repeated internet-based authentication attempts, successful Windows network logons and compromise of an exposed MySQL service involving destructive database operations and ransom-related artifacts.

The investigation used Microsoft Defender for Endpoint, Microsoft Sentinel, KQL, MySQL audit telemetry and MDE forensic investigation packages to reconstruct suspicious activity, evaluate potential attacker access and assess the effectiveness of endpoint containment.

The analysis distinguishes confirmed malicious activity from events that could not be independently verified, including interactive RDP access, data exfiltration and persistent host compromise.

### 🛠️ Technologies

`Microsoft Azure` · `Microsoft Defender for Endpoint` · `Microsoft Sentinel` · `KQL` · `Windows 11` · `MySQL` · `DFIR`

**Observation Window:** October 6–9, 2026 (UTC)

---

## 📄 Full Investigation Report

The complete report includes the incident timeline, Windows authentication analysis, MySQL investigation, indicators of compromise, KQL analysis, containment actions and host-based DFIR assessment.

**📘 [View Full Incident Response & DFIR Assessment]([https://docs.google.com/document/d/1Lxonfqcq7GOItQXcCARFLMjYPtRbDZY3bCDtFnkL43A/edit?usp=sharing](https://drive.google.com/file/d/1WF-FYnWHMgB5EV2r2rcUQLQ0v-THIUrq/view?usp=drive_link))**

---

## 📌 Key Findings

| Investigation Area | Evidence-Based Finding |
|---|---|
| Windows Authentication | One source generated 7 failed administrator logons followed by 3 successful network logons |
| Network Activity | Related telemetry included SMB (445) and RPC (135); interactive RDP access was not established |
| MySQL Compromise | Privileged authentication, enumeration, destructive database operations and ransom-related artifacts were observed |
| Data Exfiltration | The ransom message claimed data was backed up, but exfiltration was not independently confirmed |
| Host Forensics | Compared two post-compromise MDE investigation packages, one before and one after isolation |
| Incident Response | MDE isolation supported network containment; eradication and restoration were not verified |

---

## ⏱️ Incident Timeline

The investigation reconstructed the following sequence of activity using Windows authentication telemetry, MySQL audit records and endpoint forensic evidence.

| Investigation Phase | Observed Activity |
|---|---|
| Honeypot Exposure | Windows 11 Azure endpoint intentionally exposed for security research |
| Initial Authentication Activity | External sources generated repeated authentication attempts |
| Windows Authentication | Failed administrator logons and successful network authentication events identified |
| MySQL Compromise | Privileged database access, enumeration and destructive SQL operations observed |
| Ransom-Related Activity | Ransom database and related artifacts identified in MySQL audit telemetry |
| Incident Investigation | Windows, MySQL and endpoint telemetry analyzed using KQL and MDE forensic packages |
| Containment | Endpoint isolated using Microsoft Defender for Endpoint |
| Post-Containment Assessment | Second forensic package collected to assess endpoint state after isolation |

**Note:** The timeline summarizes observed activity and investigative phases. It does not establish that the Windows authentication events and MySQL compromise originated from the same attacker or formed a single attack chain.

---

## 🌎 Inbound Authentication Activity

<img width="1000" alt="Geographic visualization of external authentication source IP addresses" src="https://github.com/user-attachments/assets/bdf6aee7-c900-41fd-82f6-0146bfe48a15" />

Public source IP addresses were observed attempting network authentication against the honeypot from infrastructure geolocated across multiple countries.

Multiple external sources generated authentication activity, including failed attempts and successful network logons. One source produced a documented sequence of seven failed administrator logons followed by three successful network logons.

> **Note:** IP geolocation represents observed source infrastructure and does not establish the physical location or identity of an attacker.

---

## 🔎 Windows Authentication Investigation

<img width="1000" alt="Microsoft Defender authentication telemetry showing failed and successful network logons" src="https://github.com/user-attachments/assets/b655c03a-df13-4daf-8696-884583f557ef" />

Analysis of Windows authentication telemetry identified repeated failed administrator logons followed by successful network authentication.

One external source, `182.180.164.70`, generated seven failed administrator authentication attempts followed by three successful network logons.

Related network telemetry included activity associated with SMB (445) and RPC (135).

The authentication events established that successful network logons occurred. However, these events alone did not establish interactive RDP access, post-authentication code execution or a causal relationship with the MySQL compromise.

This distinction was important when evaluating the extent of unauthorized access and avoiding conclusions unsupported by the available telemetry.

---

## 🔬 KQL Investigation Queries

The following queries demonstrate the investigative approach used to examine Windows authentication activity, identify suspicious external sources and investigate destructive MySQL operations.

Queries are organized by their intended execution environment:

- **Microsoft Defender Advanced Hunting:** Windows authentication and source IP investigation
- **Azure Log Analytics:** MySQL audit telemetry and destructive database activity

The Defender queries use the standard `Timestamp` field from `DeviceLogonEvents`. The MySQL queries use `TimeGenerated` from the custom Log Analytics table.

> **Query validation note:** The MySQL queries below use the incident observation window without an unverified `_ResourceId` hostname extraction. If the workspace contains multiple MySQL log sources, an additional host-specific filter should be validated against the actual audit schema before running the queries.

### 1. IOC Investigation — External Authentication Sources

**Environment:** Microsoft Defender Advanced Hunting

Identifies external IP addresses associated with authentication events, including attempted accounts, authentication outcomes and first/last observed activity.

<details>
<summary><strong>View KQL Query</strong></summary>

```kql
let MyDevice = "hq-fe29312";
DeviceLogonEvents
| where DeviceName =~ MyDevice
| where isnotempty(RemoteIP)
| summarize
    Attempts=count(),
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp),
    Actions=make_set(ActionType),
    Accounts=make_set(AccountName)
    by RemoteIP
| order by Attempts desc
```
</details>

<img width="800" alt="image" src="https://github.com/user-attachments/assets/482b3956-7d90-415b-90f8-f285882a30ca" />


### 2. Windows Authentication Investigation

**Environment:** Microsoft Defender Advanced Hunting

Reviews successful and failed authentication events involving the local administrator and guest accounts during the incident observation window.

<details>
<summary><strong>View KQL Query</strong></summary>

```kql
let START_TIME = datetime(2026-10-06T01:49:58.6192813Z);
let END_TIME = datetime(2026-10-09T02:00:50Z);
let MyDevice = "hq-fe29312";
DeviceLogonEvents
| where Timestamp between (START_TIME .. END_TIME)
| where DeviceName =~ MyDevice
| where AccountName in~ ("administrator", "guest")
| project
    Timestamp,
    RemoteIP,
    AccountName,
    ActionType,
    LogonType,
    FailureReason
| order by Timestamp asc
```
</details>

<img width="800" alt="image" src="https://github.com/user-attachments/assets/c15dd9e3-32f1-4ee2-be3c-82d674f2f3c1" />


### 3. MySQL Authentication Investigation

**Environment:** Azure Log Analytics

Examines MySQL connection audit events during the observation window to identify database authentication activity.

<details>
<summary><strong>View KQL Query</strong></summary>

```kql
let START_TIME = datetime(2026-10-06T01:49:58.6192813Z);
let END_TIME = datetime(2026-10-09T02:00:50Z);
MySQLAudit_CL
| where TimeGenerated between (START_TIME .. END_TIME)
| where RawData contains "Connect"
| project
    TimeGenerated,
    _ResourceId,
    RawData
| order by TimeGenerated asc
```
</details>
<img width="800" alt="image" src="https://github.com/user-attachments/assets/1560eac4-8e36-45e7-8af6-e3539fdfddef" />


### 4. Destructive MySQL Activity

**Environment:** Azure Log Analytics

Investigates SQL activity associated with database deletion, ransom-related artifacts, binary-log manipulation and service shutdown.

<details>
<summary><strong>View KQL Query</strong></summary>

```kql
let START_TIME = datetime(2026-10-06T01:49:58.6192813Z);
let END_TIME = datetime(2026-10-09T02:00:50Z);
MySQLAudit_CL
| where TimeGenerated between (START_TIME .. END_TIME)
| where RawData contains "Query"
| where RawData contains "DROP DATABASE"
    or RawData contains "RECOVER_YOUR_DATA"
    or RawData contains "RESET MASTER"
    or RawData contains "PURGE BINARY LOGS"
    or RawData contains "SHUTDOWN"
| project
    TimeGenerated,
    _ResourceId,
    RawData
| order by TimeGenerated asc
```
</details>

<img width="800" alt="image" src="https://github.com/user-attachments/assets/ab459d25-d5d9-419a-a788-1d958da283b4" />


### 5. Suspected Windows Credential Attack

**Environment:** Microsoft Defender Advanced Hunting

Isolates authentication events associated with `182.180.164.70`, the source that generated seven failed administrator logons followed by three successful network logons.

<details>
<summary><strong>View KQL Query</strong></summary>

```kql
let START_TIME = datetime(2026-10-06T01:49:58.6192813Z);
let END_TIME = datetime(2026-10-09T02:00:50Z);
let SuspectIP = "182.180.164.70";
DeviceLogonEvents
| where Timestamp between (START_TIME .. END_TIME)
| where DeviceName =~ "hq-fe29312"
| where RemoteIP == SuspectIP
| project
    Timestamp,
    RemoteIP,
    AccountName,
    ActionType,
    LogonType,
    FailureReason
| order by Timestamp asc
```
</details>
<img width="800" alt="image" src="https://github.com/user-attachments/assets/01b0cfcd-4993-46bb-b7d2-a6f100003ff4" />


**Key Takeaway:** Correlating Windows authentication events with MySQL audit telemetry helped distinguish suspicious credential activity from observed database compromise. Successful network authentication did not independently establish interactive RDP access, and the attacker's claim of data exfiltration remained unverified.

---

## 🗄️ MySQL Compromise

The exposed MySQL service experienced successful privileged authentication during the observation period.

Analysis of MySQL audit telemetry identified:

- Database discovery and enumeration
- Privileged database authentication
- Destructive database operations
- Creation of a ransom-related database and associated artifacts
- Binary-log manipulation activity
- MySQL service shutdown activity

These findings supported a confirmed compromise of the exposed database service.

The attacker's ransom message claimed that data had been backed up. However, independent evidence confirming successful data exfiltration was not identified during the investigation.

The available evidence also did not establish a direct causal relationship between the observed Windows network authentication activity and the MySQL compromise.

---

## 🔬 Host DFIR Analysis

<img width="800" alt="Microsoft Defender endpoint forensic investigation package analysis" src="https://github.com/user-attachments/assets/85a24378-62a2-4157-a722-2552cb6ec187" />

Two Microsoft Defender investigation packages were analyzed to compare the endpoint before and after containment.

The first package was collected after compromise but before endpoint isolation. The second package was collected after isolation.

The comparison identified reduced network state and Microsoft Defender containment artifacts without clear evidence of newly established persistence between the two snapshots.

Because no clean pre-exposure forensic package was available, the first package was treated as the earliest available comparative baseline rather than a pristine pre-compromise baseline.

This limitation prevented definitive conclusions about whether persistence mechanisms existed before the first forensic collection.

The forensic comparison therefore focused on observable changes between the available endpoint snapshots rather than claiming complete reconstruction of the host's pre-compromise state.

---

## 🛡️ Incident Containment

<img width="800" alt="Microsoft Defender for Endpoint isolation and containment evidence" src="https://github.com/user-attachments/assets/bba3386a-699e-47bb-92b7-2ece87680777" />

The affected endpoint was isolated using Microsoft Defender for Endpoint.

Post-isolation forensic evidence supported successful network containment, including reduced network state and containment-related artifacts.

However, endpoint isolation alone did not establish that malicious artifacts were eradicated or that the system was restored to a trusted state.

**Response Assessment:**

| Response Phase | Assessment |
|---|---|
| Detection | Suspicious authentication and destructive MySQL activity identified |
| Investigation | Windows, MySQL and endpoint forensic evidence analyzed |
| Containment | MDE endpoint isolation performed with supporting post-isolation evidence |
| Eradication | Not independently verified |
| Recovery | Not independently verified |

The response assessment was limited to actions performed and evidence collected during the authorized lab exercise.

---

## 📚 Lessons Learned

This investigation reinforced several important incident response and digital forensics principles.

**Authentication does not automatically establish attacker control.** Successful Windows network logons require additional evidence before concluding that interactive access or code execution occurred.

**Database audit telemetry can provide critical evidence of compromise.** MySQL records helped identify privileged access, destructive operations and ransom-related activity that could not be established through Windows authentication logs alone.

**Attacker claims require independent verification.** A ransom message claiming data exfiltration is not equivalent to confirmed outbound data transfer.

**Forensic collection timing matters.** Without a clean pre-compromise baseline, conclusions about persistence and historical endpoint state must remain limited to available evidence.

**Containment is not eradication.** Network isolation can restrict further communication without proving that an endpoint is free of malicious artifacts or ready for restoration.

---

## ⚠️ Lab Disclaimer

This project was conducted in an authorized cybersecurity lab environment.

The Windows 11 endpoint was intentionally configured and exposed for defensive security research, incident response and digital forensics practice.

All investigative activity was performed within the scope of the authorized lab environment.
