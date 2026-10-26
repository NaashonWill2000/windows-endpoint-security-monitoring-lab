# SOC Process Investigation and Escalation Analysis

## 1. Investigation Objective

Investigate PowerShell process activity recorded by Sysmon, correlate process creation and termination events, assess the available evidence, and determine whether escalation is warranted.

## 2. Environment

- **SIEM:** Splunk Enterprise
- **Endpoint telemetry:** Sysmon for Windows
- **Endpoint:** `DESKTOP-RRPR83H`
- **Domain:** `skyshield.local`
- **Account:** `SKYSHIELD\Administrator`
- **Data source:** `WinEventLog:Microsoft-Windows-Sysmon/Operational`

## 3. Evidence Collected

| Field | Observation |
|---|---|
| Process image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Process GUID | `{23bf689a-96cd-6adf-2001-000000002000}` |
| Process creation | October 26, 2026, 14:07:09.745 |
| Process termination | October 26, 2026, 14:07:10.279 |
| Sysmon Event IDs | 1 (Process Creation), 5 (Process Termination) |
| Command line | `powershell.exe -Command "Write-Output 'SOCIngestionCheck20261026'"` |
| Observed duration | Approximately 0.535 seconds |

## 4. Investigation and Correlation

A Splunk search identified a PowerShell process-creation event followed by a process-termination event. Both records shared the same Process GUID, establishing that they referred to the same process.

The creation event contained the command-line marker `SOCIngestionCheck20261026`, which matched a known, controlled test performed to validate Sysmon event collection and Splunk ingestion.

The termination event recorded the same process GUID and executable. Its lack of a command-line field was consistent with the event's purpose: recording process termination rather than process creation.

## 5. Assessment

**Disposition: Benign — authorized lab validation activity.**

The process command line matched the known ingestion test, and the matching Process GUID confirmed the relationship between the creation and termination events.

The evidence supports closing this specific investigation as authorized activity. This conclusion does not establish that other PowerShell activity on the endpoint is benign.

## 6. Escalation Decision

Escalation was not warranted for this specific event after correlation with the known test activity.

If the command line or test context had been unknown, additional investigation would have been appropriate before closing the alert. Relevant next steps would include reviewing the parent process, examining related process-creation events, checking surrounding endpoint telemetry, and validating the activity with the system owner.

## 7. Analyst Skills Demonstrated

- Splunk SPL searches and event filtering
- Windows Sysmon Event ID analysis
- Process GUID correlation across lifecycle events
- PowerShell command-line investigation
- Evidence-based alert triage
- Benign activity validation and escalation decisions
- Security investigation documentation

## 8. Limitations

This investigation focused on one correlated process lifecycle. It did not independently establish the complete user session, inspect all PowerShell activity, or determine whether unrelated activity on the endpoint was malicious.

The finding should therefore be applied only to the investigated process and its known test context.