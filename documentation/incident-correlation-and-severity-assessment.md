# Incident Correlation and Severity Assessment

## Objective
Investigate outbound network connections using Splunk Enterprise and Sysmon telemetry. Correlate network activity with process creation events, validate the executable's digital signature, and assign a provisional severity based on the available evidence.

## Investigation Overview
Sysmon Event ID 3 recorded two outbound network connections to `150.171.22.17` over port `443`. The associated process IDs were `8152` and `7788`.

Correlating these events with Sysmon Event ID 1 (Process Create) identified the executable:

`C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe`

The process command line included `/ping`. Authenticode signature validation returned `Valid`, with Microsoft Corporation identified as the signer.

## Correlation Results

| Process ID | Process Creation Time | Network Connection Time | Destination IP | Port | Elapsed Seconds |
|---|---|---|---|---|---:|
| 8152 | 2026-10-27 08:37:35.361 | 2026-10-27 08:37:38.196 | 150.171.22.17 | 443 | 2.835 |
| 7788 | 2026-10-27 08:42:11.997 | 2026-10-27 08:42:13.176 | 150.171.22.17 | 443 | 1.179 |

## Evidence Collected

1. `screenshots/splunk-incident-network-connections.png` — Sysmon network connection events.
2. `screenshots/splunk-edge-update-process-correlation.png` — process creation and termination events.
3. `screenshots/edge-update-digital-signature-validation.png` — Authenticode signature validation.
4. `screenshots/splunk-incident-correlation-timing.png` — correlated process and network timestamps with elapsed-time calculations.

## Severity Assessment

**Provisional severity: Informational / Low**

The activity appears likely benign based on the available evidence:

- The executable ran from the Microsoft Edge Update installation directory.
- The executable's Authenticode signature was valid and identified Microsoft Corporation as the signer.
- The command line included `/ping`, consistent with an updater communication pattern.
- The network connections occurred shortly after the corresponding process-creation events.

No confirmed malicious behavior was identified in the evidence reviewed.

## Limitations and Follow-Up

A valid digital signature supports the identity of the software publisher but does not independently establish the destination IP address's ownership or reputation. Port `443` is commonly used for HTTPS, but the port alone does not establish that a connection is safe.

If additional suspicious behavior or threat-intelligence findings emerge, investigate the destination IP, review surrounding endpoint telemetry, and reassess the severity.

## Skills Demonstrated

- Splunk Search Processing Language (SPL)
- Sysmon Event ID 1 and Event ID 3 correlation
- Endpoint process and network investigation
- Digital-signature validation with PowerShell
- Event timeline reconstruction and elapsed-time analysis
- Evidence-based severity prioritization
- Technical documentation for security investigations
