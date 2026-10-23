# PowerShell Process Investigation

## Overview
This investigation analyzes a controlled PowerShell test event captured by Sysmon on a Windows 11 endpoint and searched in Splunk Enterprise. The objective was to examine process-creation telemetry and identify the executable, command line, user context, and parent-process information associated with the event.

## Lab Environment
- **Endpoint:** Windows 11 VM (WS01)
- **Telemetry source:** Microsoft-Windows-Sysmon/Operational
- **Log forwarding:** Splunk Universal Forwarder
- **SIEM:** Splunk Enterprise
- **Event type:** Sysmon Event ID 1 — Process Creation

## Investigation Objective
Investigate a PowerShell process containing the `-ExecutionPolicy Bypass` argument and the controlled test marker `BlueTeamDetectionTest`.

## Investigation Procedure
1. Searched live Sysmon telemetry in Splunk using SPL.
2. Extracted the Sysmon event ID, executable image, command line, user, parent image, and parent command line from the raw XML event.
3. Filtered the results for the controlled test marker.
4. Examined the parent and child process information to understand how the test process was launched.

## Observed Findings

### Detection
Splunk returned a matching Sysmon Event ID 1 containing the `BlueTeamDetectionTest` marker and the `-ExecutionPolicy Bypass` argument.

### Process Context
- **Child executable:** `powershell.exe`
- **Parent executable:** `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe`
- **Parent command line:** `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe`
- **User context:** Available in the extracted Sysmon `User` field in Splunk.

The parent and child executable paths indicate that a PowerShell process launched another PowerShell process, consistent with the controlled test procedure.

## SPL Investigation Query

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=-24h
| rex field=_raw "<EventID>(?<SysmonEventID>[^<]*)</EventID>"
| rex field=_raw "Name='Image'>(?<Image>[^<]*)</Data>"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| rex field=_raw "Name='User'>(?<User>[^<]*)</Data>"
| rex field=_raw "Name='ParentImage'>(?<ParentImage>[^<]*)</Data>"
| rex field=_raw "Name='ParentCommandLine'>(?<ParentCommandLine>[^<]*)</Data>"
| search SysmonEventID="1" CommandLine="*BlueTeamDetectionTest*"
| table _time host User Image ParentImage CommandLine ParentCommandLine
| sort - _time
```

## Assessment
The observed event was consistent with the authorized lab test performed on WS01. The `-ExecutionPolicy Bypass` argument can occur in legitimate administrative activity and does not, by itself, establish malicious intent.

In a real investigation, an analyst should correlate the user, parent process, full command line, event timing, and surrounding endpoint activity before determining whether the behavior is suspicious.

## Scope and Limitations
This investigation validates analysis of a controlled process-creation event in live Sysmon telemetry. It does not demonstrate detection of every malicious PowerShell technique or establish that the activity would be malicious in another context.

## Key Takeaways
- Investigated live Windows endpoint telemetry using Splunk SPL.
- Extracted process and parent-process context from Sysmon XML events.
- Traced a PowerShell parent-child process relationship.
- Evaluated a command-line indicator in the context of an authorized test.
- Documented the findings and limitations of the investigation.
