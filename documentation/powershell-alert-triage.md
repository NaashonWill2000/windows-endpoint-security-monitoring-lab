# PowerShell Alert Triage Investigation

## 1. Case Summary

- **Detection:** PowerShell Multi-Indicator Detection
- **Indicator:** Execution policy bypass
- **Affected host:** `DESKTOP-RRPR83H`
- **Account:** `SKYSHIELD\Administrator`
- **Event ID:** Sysmon 1 — Process Creation
- **Event timestamp:** `2026-10-24 22:35:45.187` (as displayed by Splunk)
- **Disposition:** Benign / Authorized Activity
- **Investigation type:** Controlled lab validation

## 2. Alert Evidence

Splunk identified a PowerShell process launched with the `-ExecutionPolicy Bypass` argument.

**Process image**
`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

**Parent process**
`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

**Observed command line**
```text
"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -Command "Write-Output 'SOCInvestigationTest20261024'"
```

## 3. Investigation and Analysis

The command line contained the unique marker `SOCInvestigationTest20261024`, which matched the harmless test command intentionally executed during lab validation.

The event's process image and parent-process information were consistent with the controlled nested PowerShell launch. The detection correctly identified the execution-policy bypass indicator, and the event was successfully ingested from Sysmon into Splunk Enterprise.

The execution-policy bypass argument alone does not establish malicious intent. The known test marker provided the key evidence for determining that this specific event was authorized.

## 4. Triage Decision

**Final disposition: Benign / Authorized Activity**

**Rationale:** The unique marker matched the controlled test performed by the analyst. The observed command and process context were consistent with that test.

This event is not classified as a false positive because the detection successfully identified the configured indicator. The investigation established that the activity was benign.

## 5. Analyst Actions

- Reviewed the detection indicator and command line.
- Examined the affected host, user, process image, and parent process.
- Correlated the unique marker with the authorized test activity.
- Assigned a benign / authorized disposition.
- Determined that containment or remediation was not warranted for this controlled test event.

## 6. Conclusion

This investigation demonstrated a basic SOC alert-triage workflow using live Sysmon telemetry and Splunk Enterprise. The analyst reviewed process-creation evidence, validated the activity against a known test, and documented a disposition supported by the available evidence.

**Scope limitation:** This was a controlled lab test, not an investigation of a confirmed real-world attack. The disposition applies to this specific event and should not be generalized to other PowerShell execution-policy bypass alerts.
