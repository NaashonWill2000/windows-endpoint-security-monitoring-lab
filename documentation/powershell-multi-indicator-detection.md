# PowerShell Multi-Indicator Detection

## Overview
This project demonstrates a Splunk Enterprise detection search that identifies selected PowerShell command-line indicators in live Sysmon process-creation telemetry.

## Lab Environment
- **Endpoint:** Windows 11 VM (WS01)
- **Telemetry source:** Microsoft-Windows-Sysmon/Operational
- **Log forwarding:** Splunk Universal Forwarder
- **SIEM:** Splunk Enterprise
- **Index:** `main`

## Detection Objective
Identify PowerShell process-creation events containing selected command-line indicators that may warrant further investigation.

## Indicators
The SPL search looks for:
- **Encoded command arguments:** `-enc` or `-EncodedCommand`
- **Execution-policy bypass arguments:** `-ExecutionPolicy Bypass` or `-ep bypass`
- **Hidden-window arguments:** `-WindowStyle Hidden` or `-w hidden`

These indicators can occur in legitimate administrative activity and should not be treated as proof of malicious behavior.

## Detection Logic

```spl id="rg7j2v"
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=-24h
| rex field=_raw "<EventID>(?<SysmonEventID>[^<]*)</EventID>"
| rex field=_raw "Name='Image'>(?<Image>[^<]*)</Data>"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| rex field=_raw "Name='User'>(?<User>[^<]*)</Data>"
| rex field=_raw "Name='ParentImage'>(?<ParentImage>[^<]*)</Data>"
| rex field=_raw "Name='ParentCommandLine'>(?<ParentCommandLine>[^<]*)</Data>"
| search SysmonEventID="1"
| where match(CommandLine, "(?i)(-enc(odedcommand)?\s|-executionpolicy\s+bypass|-ep\s+bypass|-windowstyle\s+hidden|-w\s+hidden)")
| eval Indicator=case(
    match(CommandLine, "(?i)(-enc(odedcommand)?\s)"), "Encoded command",
    match(CommandLine, "(?i)(-executionpolicy\s+bypass|-ep\s+bypass)"), "Execution policy bypass",
    match(CommandLine, "(?i)(-windowstyle\s+hidden|-w\s+hidden)"), "Hidden window",
    true(), "Other"
)
| table _time host User Indicator Image ParentImage CommandLine ParentCommandLine
| sort - _time
```

## Validation Results
- Executed a controlled PowerShell test using the `-ExecutionPolicy Bypass` argument.
- Confirmed that live Sysmon telemetry arrived in Splunk.
- Verified that the detection search returned the test event.
- Confirmed that the `Indicator` field classified the event as `Execution policy bypass`.
- Saved the search as a reusable Splunk report titled **PowerShell Multi-Indicator Detection**.

## Evidence
- `screenshots/splunk-powershell-multi-indicator-detection.png` — Screenshot of the matching event and indicator classification in Splunk.

## Scope and Limitations
This search identifies selected command-line patterns. It does not detect every malicious PowerShell technique, and a matching argument is not sufficient to establish malicious intent. The saved report is not an automatically triggered alert.

## Key Takeaways
This project demonstrates SPL development, live endpoint telemetry analysis, command-line indicator classification, and validation of a reusable detection search against controlled lab activity.
