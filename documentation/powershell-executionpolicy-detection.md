# PowerShell Execution Policy Bypass Detection

## Overview
This investigation demonstrates how Splunk Enterprise can identify PowerShell process-creation events containing the `-ExecutionPolicy Bypass` argument using live Sysmon telemetry.

## Lab Environment
- Endpoint: Windows 11 VM (WS01)
- Telemetry: Sysmon Operational event log
- Log forwarding: Splunk Universal Forwarder
- SIEM: Splunk Enterprise
- Data source: `WinEventLog:Microsoft-Windows-Sysmon/Operational`

## Detection Objective
Identify PowerShell process-creation events whose command lines contain execution-policy bypass arguments for further investigation.

## Detection Logic
The SPL search extracts the Sysmon event ID, executable image, and command line from the raw XML event. It then filters for process-creation events containing selected execution-policy bypass or encoded-command arguments.

## Validation
A controlled, harmless test command was executed on WS01:

```powershell
powershell.exe -ExecutionPolicy Bypass -Command "Write-Output 'BlueTeamDetectionTest'"
```

The matching event was located in Splunk, confirming that the search detected the test command-line argument in live Sysmon telemetry.

## Evidence
- `screenshots/splunk-powershell-executionpolicy-detection.png` — Screenshot of the matching PowerShell detection event in Splunk.

## Investigation Notes
The `-ExecutionPolicy Bypass` argument is not inherently malicious. Administrators and automation tools may use it legitimately. Detection results should be investigated in context, including the parent process, user, command line, and surrounding activity.

## Scope and Limitations
This test validates detection of a specific command-line pattern. It does not demonstrate detection of every malicious PowerShell technique, and the saved search is not an automatically triggered alert.

## Key Takeaways
This exercise demonstrates live endpoint telemetry collection, SPL-based filtering, PowerShell command-line investigation, and validation of a detection using a controlled test event.
