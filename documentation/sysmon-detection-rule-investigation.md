
# Sysmon PowerShell Detection Rule Investigation

## Objective
Create and manually validate a Sigma-style detection rule using a harmless PowerShell command-line marker and Sysmon process-creation telemetry.

## Lab Environment
- Endpoint: Windows 11 (`WS01`)
- Telemetry source: Sysmon Operational log
- Event ID: 1 — Process creation
- Detection format: Sigma-style YAML rule
- Test marker: `SysmonDetectionTest`

## Test Procedure
Executed the following harmless command in the lab:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'SysmonDetectionTest'"
```

Reviewed the resulting Sysmon Event ID 1 record in Event Viewer and inspected its XML details.

## Detection Logic
The rule in `rules/sysmon-powershell-test.yml` checks for:
- Event ID 1
- A `CommandLine` field containing `SysmonDetectionTest`

## Observed Evidence
The Sysmon Event ID 1 record contained the `SysmonDetectionTest` marker in its `CommandLine` field.

Screenshot evidence: [Sysmon PowerShell Detection Test](../screenshots/sysmon-powershell-detection-test.png)

## Validation Result
**Manual condition check: matched.** The observed event contained the string specified by the rule.

This confirms that the event provides the expected input for the detection condition. The Sigma-style rule has not yet been executed by a Sigma-compatible detection engine, so automated rule execution and alert generation have not been verified.

## Limitations
- This was a controlled, benign test in a single Windows 11 virtual machine.
- The marker is a test string, not an indicator of malicious activity.
- No SIEM integration, automated alerting, or production environment was tested.

## Next Steps
- Validate the rule with a Sigma-compatible tool or convert it to a query supported by a log-analysis platform.
- Expand testing with additional controlled process-creation scenarios.
