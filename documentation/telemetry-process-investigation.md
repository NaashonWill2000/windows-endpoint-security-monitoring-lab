# Windows Telemetry Process Investigation and Network Enrichment

## 1. Investigation Overview

**Investigation type:** Windows process investigation and network enrichment  
**Host:** `DESKTOP-RRPR83H`  
**Process under investigation:** `CompatTelRunner.exe`  
**Initial assessment:** Likely legitimate Windows compatibility telemetry  
**Disposition:** No confirmed malicious indicators identified in the evidence reviewed

### Objective

Investigate Windows compatibility telemetry activity by correlating Sysmon process-creation, process-termination, and network-connection events. Validate the executable's digital signature and enrich the observed network destination using external registration information.

## 2. Process Investigation

Splunk Sysmon telemetry recorded `CompatTelRunner.exe` executing under the `NT AUTHORITY\SYSTEM` account.

The observed parent process was:

`C:\Windows\System32\svchost.exe`

The parent command line referenced the Windows Inventory Service:

`svchost.exe -k InvSvcGroup -p -s InventorySvc`

Observed command lines referenced Windows compatibility and inventory-related modules, including `aeinv.dll`, `devinv.dll`, `GeneralTel.dll`, and `appraiser.dll`.

These observations are consistent with Windows compatibility and inventory activities. Process ancestry and command-line context support this interpretation but do not independently establish that every activity was benign.

## 3. Executable Signature Validation

The executable's Authenticode signature was checked using PowerShell.

**File path:**

`C:\Windows\System32\CompatTelRunner.exe`

**Signature status:** `Valid`  
**Signer:** Microsoft Windows / Microsoft Corporation

The valid signature supports the conclusion that the executable is an authenticated Microsoft-signed Windows component. Signature validation alone does not establish the safety of every action performed by a process.

## 4. Network Connection Enrichment

Sysmon Event ID 3 recorded an outbound network connection associated with `CompatTelRunner.exe`.

| Field | Observed value |
|---|---|
| Timestamp | October 26, 2026, 14:28:02 |
| Host | `DESKTOP-RRPR83H` |
| Destination IP | `40.84.85.40` |
| Destination port | `443` |
| Connection initiated | `true` |
| Destination hostname | Not recorded |

Port 443 is commonly used for HTTPS connections.

### External enrichment

An ARIN RDAP lookup for `40.84.85.40` listed Microsoft Corporation as the registered organization.

A reverse-DNS lookup using `nslookup 40.84.85.40` returned a non-existent-domain response from the configured DNS server.

The lack of a reverse-DNS hostname is inconclusive and does not, by itself, indicate malicious activity. IP registration provides useful ownership context but does not identify the exact remote service or prove the connection was safe.

## 5. Investigation Findings

The following evidence was correlated:

- A valid Microsoft Windows Authenticode signature.
- A process ancestry chain referencing the Windows Inventory Service.
- Compatibility and inventory-related command-line arguments.
- An outbound connection to `40.84.85.40` over port 443.
- ARIN registration information listing Microsoft Corporation.
- A reverse-DNS lookup that returned no hostname.

Together, these findings are consistent with routine Windows compatibility telemetry. No confirmed malicious indicators were identified in the evidence reviewed.

## 6. Disposition and Confidence

**Disposition:** Likely legitimate Windows telemetry.

**Confidence:** Moderate.

This classification is based on the available process, signature, and network-registration evidence. It is not a guarantee that the activity was harmless.

No packet capture, TLS inspection, or independent verification of the specific remote service was performed as part of this investigation.

## 7. Skills Demonstrated

- Sysmon process and network event analysis.
- Splunk SPL searches and field extraction.
- Process ancestry and command-line investigation.
- Authenticode signature validation using PowerShell.
- External IP registration enrichment.
- Reverse-DNS investigation.
- Evidence-based incident disposition and confidence assessment.

## 8. Evidence and Screenshots

The following screenshots support the investigation findings:

1. `screenshots/splunk-telemetry-process-investigation.png` — Splunk process investigation showing PowerShell child processes and their `CompatTelRunner.exe` parent.
2. `screenshots/compat-tel-runner-signature-validation.png` — PowerShell output showing the executable's valid Microsoft Authenticode signature.
3. `screenshots/compat-tel-runner-network-connection.png` — Splunk Sysmon Event ID 3 showing the outbound connection to `40.84.85.40` over port `443`.
4. `screenshots/compat-tel-runner-ip-registration.png` — ARIN RDAP registration information listing Microsoft Corporation for the destination IP.

## 9. Conclusion

This investigation demonstrates how endpoint telemetry can be enriched with executable-signature validation and external network-registration information to support a defensible disposition.

The evidence supports classifying the observed activity as likely legitimate Windows compatibility telemetry, with moderate confidence and clearly documented limitations.
