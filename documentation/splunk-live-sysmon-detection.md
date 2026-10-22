# Live Sysmon Telemetry and Splunk Detection

## Overview

This lab demonstrates live Windows endpoint telemetry collection and detection using Sysmon, Splunk Universal Forwarder, and Splunk Enterprise.

## Lab Architecture

- **Endpoint:** Windows 11 VM (WS01)
- **Telemetry source:** Microsoft-Windows-Sysmon/Operational
- **Log forwarding:** Splunk Universal Forwarder
- **SIEM:** Splunk Enterprise running on the host computer
- **Receiving port:** TCP 9997
- **Index:** `main`

## Implementation

1. Configured Sysmon on WS01 to generate endpoint telemetry.
2. Configured Splunk Universal Forwarder to collect the Sysmon Operational event log.
3. Configured the forwarder to send events to the Splunk Enterprise receiver.
4. Verified that live Sysmon events arrived in Splunk.
5. Extracted XML fields using SPL, including the Sysmon event ID, executable path, and command line.
6. Created and saved a reusable detection search for the `SysmonDetectionTest` marker.

## Detection Logic

The detection identifies Sysmon Event ID 1 process-creation events whose command line contains the test marker.

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" earliest=-24h
| rex field=_raw "<EventID>(?<SysmonEventID>[^<]*)</EventID>"
| rex field=_raw "Name='Image'>(?<Image>[^<]*)</Data>"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]*)</Data>"
| search SysmonEventID="1" CommandLine="*SysmonDetectionTest*"
| table _time host SysmonEventID Image CommandLine
| sort - _time
```

## Validation Results

- Confirmed that the forwarder service was running.
- Confirmed connectivity to the Splunk Enterprise receiver.
- Verified ingestion of live Sysmon XML events.
- Extracted executable paths and command-line values from the XML.
- Found a matching Event ID 1 event containing `SysmonDetectionTest`.
- Saved the working search as **Sysmon PowerShell Test Marker Detection**.

## Evidence

- `screenshots/splunk-live-sysmon-detection.png` — live Sysmon detection search and matching event.

## Scope and Limitations

This detection was validated using a controlled test marker. It demonstrates live telemetry ingestion and a working SPL detection search; it does not establish detection effectiveness against every malicious PowerShell technique.

The saved search is reusable but is not, by itself, an automatically triggered alert. Alert scheduling and notification have not been validated as part of this lab.

## Key Takeaways

This project demonstrates Windows endpoint monitoring, event forwarding, SIEM ingestion, XML field extraction, SPL search development, and validation of a detection against live endpoint telemetry.
