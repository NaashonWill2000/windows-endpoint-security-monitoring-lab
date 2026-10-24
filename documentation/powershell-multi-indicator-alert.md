# PowerShell Multi-Indicator Detection Alert

## Overview

Configured a scheduled Splunk Enterprise alert to identify potentially suspicious PowerShell command-line arguments in Sysmon process-creation events.

## Detection Indicators

The existing SPL detection identifies these command-line patterns:

- **Encoded command:** PowerShell encoded-command arguments.
- **Execution policy bypass:** `-ExecutionPolicy Bypass` and `-ep Bypass`.
- **Hidden window:** `-WindowStyle Hidden` and `-w Hidden`.

## Alert Configuration

- **Alert name:** PowerShell Multi-Indicator Detection Alert
- **Alert type:** Scheduled
- **Schedule:** Every 5 minutes
- **Search window:** Last 600 seconds
- **Trigger condition:** Number of results greater than 0
- **Severity:** Medium
- **Trigger behavior:** Once
- **Action:** Add to Triggered Alerts
- **Permissions:** Private

## Validation

Validated the alert search using controlled PowerShell test activity. The matching result displayed:

- Indicator: Execution policy bypass
- Command line: Contains `-ExecutionPolicy Bypass`
- Image: `powershell.exe`

The alert was enabled, and its trigger history contained an entry. The matching result was accessible through the alert's View Results link.

- Generated a fresh, controlled PowerShell test using the unique marker `BlueTeamAlertValidation20261023`.
- Confirmed that Sysmon recorded the process-creation event and Splunk indexed the event.
- Verified that the new marker appeared in the results associated with a scheduled alert trigger.
- [Scheduled Alert Validation Evidence](../screenshots/splunk-scheduled-alert-validation.png)

## Limitations

The test validates detection of a command-line pattern, not a confirmed attack. These PowerShell arguments can occur in legitimate administrative activity and require investigation in context.

The alert is subject to the Splunk Enterprise trial-license expiration noted by the application. The configured action adds matches to Triggered Alerts; an email or external notification action was not configured.

## Potential Improvements

- Test encoded-command and hidden-window detections using controlled, benign examples.
- Tune the search window and throttling to reduce duplicate triggers.
- Configure an appropriate notification action if needed.
- Capture screenshots of the alert configuration and matching results.
