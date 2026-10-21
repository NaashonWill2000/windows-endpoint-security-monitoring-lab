# Splunk Sigma Detection Validation

## Objective
Validate the Splunk search logic converted from a Sigma rule designed to identify a PowerShell process command containing the marker `SysmonDetectionTest`.

## Environment
- SIEM: Splunk Enterprise
- Data source: Uploaded JSON test record
- Host: WS01
- Index: `main`
- Source type: `_json`

## Detection Query
```spl
index=main EventCode=1 CommandLine="*SysmonDetectionTest*"
```

## Results
Splunk successfully ingested the JSON test record, extracted the relevant fields, and returned one matching event when the detection query was executed.

The matching record contained the expected process-creation event code and test marker in the command-line field.

Evidence: `../screenshots/splunk-sigma-detection-match.png`

## Conclusion
The test confirms that the Splunk search logic matches the normalized test record and that the relevant fields are searchable.

**Scope limitation:** The event was uploaded as a JSON test record. This validation does not demonstrate continuous ingestion from Sysmon, direct ingestion of a raw Windows event, or real-time alerting. Those capabilities require separate testing.
