# Incident Response Runbook — Windows Endpoint Security Monitoring

## 1. Purpose

This runbook documents a repeatable process for triaging and investigating Windows endpoint security events using Splunk Enterprise, Windows Security logs, and Sysmon telemetry.

It is designed to support consistent evidence collection, event correlation, initial severity assessment, and escalation decisions in a controlled lab environment.

## 2. Scope

This runbook covers the following investigation scenarios:

- Failed Windows logon attempts (Security Event ID 4625).
- Process creation and command-line investigation (Sysmon Event ID 1).
- PowerShell execution-policy bypass, encoded-command, and hidden-window indicators.
- Correlation of process-creation and network-connection events.
- Documentation of findings, severity rationale, and escalation recommendations.

## 3. Lab Environment

| Component | Configuration |
|---|---|
| SIEM | Splunk Enterprise |
| Endpoint | Windows 11 virtual machine |
| Endpoint hostname | `DESKTOP-RRPR83H` |
| Active Directory domain | `skyshield.local` |
| Domain controller | `SKY-SRV-01` |
| Log forwarding | Splunk Universal Forwarder |
| Search index | `main` |
| Virtualization | Oracle VirtualBox |

## 4. Analyst Responsibilities

During an investigation, the analyst should:

1. Identify the alert or event requiring investigation.
2. Establish the relevant time range, endpoint, account, and event identifiers.
3. Review the underlying event details rather than relying only on a summary or alert title.
4. Correlate related events when the available telemetry supports it.
5. Distinguish confirmed evidence from assumptions and document limitations.
6. Assign a provisional severity based on observed evidence and potential impact.
7. Escalate activity that remains suspicious or requires additional authorization or expertise.
8. Record the investigation outcome and supporting evidence.

## 5. General Investigation Workflow

### Step 1 — Identify the event

Record the detection name, event identifier, endpoint, relevant account, and approximate event time.

### Step 2 — Review the raw event

Open the matching event in Splunk and inspect its original fields or XML payload. Verify the timestamp, event identifier, account, process details, and available status information.

### Step 3 — Establish context

Compare the event with known lab activity and related telemetry. Look for repeated events, related process activity, or other evidence that helps explain what occurred.

### Step 4 — Assess the evidence

Document what is confirmed, what remains uncertain, and whether the activity appears consistent with the controlled test or warrants further investigation.

### Step 5 — Record and escalate

Document the search, relevant event details, findings, provisional severity, and recommended next action. Escalate when evidence indicates potential compromise or the investigation cannot establish a sufficiently supported explanation.

## 6. Evidence Handling

For each investigation, preserve the following details where available:

- Date and time of the event, including the applicable time zone.
- Endpoint hostname and relevant account.
- Event ID and log source.
- Splunk search query and relevant results.
- Supporting screenshots or exported evidence.
- Investigation findings and known limitations.
- Severity rationale and recommended next action.

Do not treat a suspicious command-line argument or a failed logon as proof of compromise by itself. Conclusions should be based on the available evidence and its context.

## 7. Procedure — Failed Windows Logons (Event ID 4625)

### Objective

Identify and investigate failed Windows authentication attempts using Security Event ID 4625 and Splunk Enterprise.

### Data Source

- Windows Security Event Log
- Splunk index: `main`
- Endpoint: `DESKTOP-RRPR83H`
- Event ID: `4625`

### Step 1 — Search for failed logons

In Splunk Search & Reporting, select an appropriate time range and run:

```spl
index=main host="DESKTOP-RRPR83H" source="WinEventLog:Security" "4625"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| where EventCode="4625"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]+)</Data>"
| rex field=_raw "<Data Name='SubStatus'>(?<SubStatus>[^<]+)</Data>"
| table _time TargetUserName EventCode SubStatus sourcetype
| sort - _time
```

If the selected time range returns no results, widen the time range before concluding that no matching events exist.

### Step 2 — Review the results

For each relevant event, examine:

- **Timestamp:** When the failed authentication occurred.
- **Target username:** The account associated with the event.
- **Event ID:** Confirm that the event is 4625.
- **Substatus:** Review the additional authentication failure information.
- **Raw event:** Inspect the underlying XML for additional details, including logon type and other available fields.

### Step 3 — Interpret the substatus

Common values observed in this lab include:

| Substatus | Interpretation |
|---|---|
| `0xc000006a` | Incorrect password |
| `0xc0000064` | User account does not exist or was not recognized |

Interpret these values in the context of the complete event. Do not assume that every failed logon indicates malicious activity.

### Step 4 — Identify patterns

Check whether failures involve:

- Repeated attempts against the same account.
- Multiple accounts on the same endpoint.
- Unexpected timestamps or authentication patterns.
- Other related security events available in the lab.

A high number of failures may justify further investigation, but a threshold alone does not establish an attack.

### Step 5 — Validate against known activity

Compare the event with authorized test activity when possible. In this lab, a controlled `runas` attempt using an incorrect password generated a Windows Security Event ID 4625 for `SOC-TestUser`.

Splunk successfully indexed and returned the corresponding event, including substatus `0xc000006a`.

### Step 6 — Document the outcome

Record the time range searched, affected account, event details, relevant substatus, supporting evidence, and investigation conclusion.

If the evidence is consistent with a known test, document that finding. If the activity is unexpected or cannot be explained, recommend further investigation and escalation as appropriate.

### Validation Evidence

- Splunk report: `Windows Failed Logon Detection - Event ID 4625`
- Screenshot: `screenshots/windows-failed-logon-detection.png`

## 8. Procedure — Process Creation and PowerShell Investigation

### Objective

Investigate Windows process-creation events using Sysmon Event ID 1 and Splunk Enterprise to identify command-line indicators that may warrant further review.

### Data Source

- SIEM: Splunk Enterprise
- Log source: Sysmon Operational
- Event ID: `1` — Process creation
- Endpoint: `DESKTOP-RRPR83H`
- Search index: `main`

### Step 1 — Search for process-creation events

Run the following search in Splunk Search & Reporting:

```spl
index=main host="DESKTOP-RRPR83H" source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| where EventCode="1"
| table _time EventCode _raw
| sort - _time
```

Select a suitable time range. If the search returns no results, verify the time range and inspect the available Sysmon source and sourcetype values before troubleshooting further.

### Step 2 — Review process details

Inspect the raw event XML for available information, including:

- Image — executable path.
- CommandLine — command-line arguments.
- User — account associated with the process.
- ParentImage — parent process path.
- ParentCommandLine — parent process command line.
- ProcessId and ProcessGuid — process identifiers.
- Computer and UtcTime — endpoint and event timing.

Field availability and exact formatting depend on the event and ingestion configuration.

### Step 3 — Review PowerShell indicators

When investigating PowerShell execution, review command-line arguments for indicators such as:

- `-ExecutionPolicy Bypass`
- `-EncodedCommand`
- `-WindowStyle Hidden`

These arguments can occur in legitimate administrative or automation activity. Their presence alone does not establish malicious behavior.

### Step 4 — Correlate relevant activity

When appropriate, compare process-creation events with other available telemetry, including:

- Related parent and child processes.
- Nearby Windows Security events.
- Sysmon Event ID 3 network connections.
- Known controlled test activity and relevant timestamps.

Confirm that the events refer to the same endpoint and, where available, the same process identifiers. Avoid attributing a network connection to a process solely because the timestamps are close.

### Step 5 — Assess and document findings

Record the relevant executable, command line, user, parent process, timestamps, related events, and investigation limitations.

Distinguish observed indicators from confirmed malicious activity. Assign a provisional severity based on the available evidence, potential impact, and applicable escalation criteria.

### Validation and Evidence

The project includes documented PowerShell detection and process-investigation work, as well as incident-correlation analysis.

Refer to the associated project documentation and screenshots to review the specific searches and validation evidence:

- `documentation/powershell-executionpolicy-detection.md`
- `documentation/powershell-process-investigation.md`
- `documentation/powershell-multi-indicator-detection.md`
- `documentation/incident-correlation-and-severity-assessment.md`

## 9. Triage, Severity, and Escalation

### 9.1 Initial Triage

For each alert or suspicious event:

1. Confirm the endpoint, event timestamp, event identifier, and relevant account or process.
2. Review the raw event and the search results that triggered the investigation.
3. Determine whether the activity matches known, authorized lab testing.
4. Search for related events within a reasonable time window.
5. Record confirmed facts, unresolved questions, and evidence limitations.

### 9.2 Provisional Severity Guidelines

Severity should reflect the available evidence, potential impact, and relevant organizational procedures. These guidelines are illustrative for this lab and are not a substitute for an organization's incident-classification policy.

| Provisional severity | Example indicators | Recommended action |
|---|---|---|
| Informational | Expected activity from a controlled test, with supporting evidence | Document the result and close the lab investigation |
| Low | An isolated anomaly with a plausible explanation and no corroborating evidence of compromise | Document findings and continue monitoring as appropriate |
| Medium | Repeated unexpected authentication failures or suspicious process activity that requires additional context | Investigate related events and recommend escalation if concerns remain |
| High | Multiple corroborating indicators suggesting possible compromise, unauthorized access, or significant impact | Promptly escalate through the applicable incident-response process |

Do not assign severity from a single command-line indicator or event count alone. Document the reasoning and any uncertainty behind the assessment.

### 9.3 Escalation Criteria

Recommend escalation when:

- Authentication failures show an unexplained pattern or affect sensitive accounts.
- Process activity contains suspicious indicators that cannot be explained by authorized activity.
- Multiple event sources provide corroborating evidence of potentially malicious behavior.
- The observed activity may indicate unauthorized access, persistence, or data exposure.
- Additional investigation requires permissions, telemetry, or expertise outside the analyst's scope.

When escalating, include the detection name, endpoint, timeline, affected account or process, relevant search results, evidence files, severity rationale, and outstanding questions.

### 9.4 Incident Closure

Before closing an investigation:

1. Confirm that the relevant events and time range were reviewed.
2. Record the investigation conclusion and supporting evidence.
3. Document whether the activity was consistent with a known test, likely benign, suspicious, or inconclusive.
4. Explain any limitations that prevent a stronger conclusion.
5. Record any recommended follow-up actions.
6. Ensure the supporting screenshots and documentation are saved in the project repository.

For real organizational incidents, follow the organization's authorization, containment, notification, and incident-handling procedures. Do not take disruptive response actions without appropriate authorization.

## 10. Investigation Record Template

Use this template to document each investigation.

- **Investigation title:**
- **Date and time reviewed:**
- **Analyst:**
- **Endpoint:**
- **Detection or event ID:**
- **Affected account or process:**
- **Splunk search and time range:**
- **Observed evidence:**
- **Related events reviewed:**
- **Confirmed findings:**
- **Uncertainties and limitations:**
- **Provisional severity and rationale:**
- **Recommended action:**
- **Final disposition:**
- **Evidence and documentation links:**

## 11. Runbook Maintenance

Review this runbook when detection searches, event sources, endpoint configuration, or investigation procedures change. Validate procedural updates against controlled lab activity before describing them as tested.

This runbook documents procedures developed in an educational virtual lab. Its example severity levels and escalation guidance are illustrative and should be adapted before use in a production environment.
