# Windows Security Event Investigations

## 1. Failed Logon Investigation — Event ID 4625

**Objective:** Examine Windows records of failed authentication attempts.

**Environment:** Windows 11 workstation (`WS01`) and Windows Server domain controller (`SKY-SRV-01`).

**Test and observations:**
- Filtered the Windows Security log for Event ID `4625`.
- Performed one controlled incorrect-password attempt on `WS01`, followed by a successful sign-in.
- Located a matching failed-logon event with Logon Type 2.
- Reviewed a separate failed-logon event on `SKY-SRV-01` with source network address `127.0.0.1`.

**Analysis:** Logon Type 2 indicates an interactive logon attempt. The loopback address indicates that the recorded source was the local host; by itself, it does not establish the underlying cause or prove malicious activity.

**Security relevance:** Analysts can review timestamps, account names, logon types, failure details, and source information to investigate authentication problems or potentially suspicious patterns. A single failure is not sufficient to conclude that an attack occurred.

## 2. Successful Logon Review — Event ID 4624

**Objective:** Review successful authentication events and interpret their logon types.

**Evidence observed:**
- Located a successful-logon event on `WS01`.
- Logon Type: 5.
- Account Domain: `SKYSHIELD`.
- Logon Process: `Advapi`.

**Analysis:** Logon Type 5 represents a service logon. The `Advapi` logon process alone does not identify the exact service responsible for the event.

**Security relevance:** Understanding logon types helps analysts distinguish service activity from interactive sign-ins and investigate whether authentication activity is consistent with the system's expected behavior.

## 3. Process Creation Monitoring — Event ID 4688

**Objective:** Verify that Windows records successful process-creation events.

**Environment:** Windows 11 domain-joined workstation (`WS01`).

**Configuration:** Enabled successful Process Creation auditing using Windows Advanced Audit Policy.

**Test:** Launched Microsoft Notepad and inspected the resulting Security event in Event Viewer.

**Evidence observed:**
- Event ID: `4688`.
- New Process Name: Microsoft Notepad executable under `C:\Program Files\WindowsApps`.
- Parent Process Name: A complete executable path ending in `.exe`.

**Result:** Successfully generated and inspected a process-creation event, validating that process auditing was operational on the workstation.

**Security relevance:** Process-creation logs provide evidence analysts can use to investigate program execution and establish process relationships. An executable path should be evaluated in context rather than treated as suspicious solely because of its location.

## 4. User Account Management Event Review — Events 4720, 4726, and 4738

**Objective:** Review Windows Security records associated with user-account lifecycle and account changes.

**Evidence reviewed:**
- Event IDs `4720` and `4726` were included in the account-management event review.
- Inspected a historical Event ID `4738` on `WS01`.
- The `4738` event identified `WS01` as the subject account and `defaultuser0` as the target account.
- The event was logged on October 9, 2026, before the current investigation work.

**Analysis:** Event ID `4738` records a user account being changed. The available event details did not establish which specific account property changed or why. Because the event was historical, it was not treated as a result of the current controlled test.

**Security relevance:** Account creation, deletion, and modification events can help analysts investigate unauthorized account changes. Conclusions should be based on the complete event details and corroborating evidence.

## 5. Local Security-Group Change Review — Event ID 4732

**Objective:** Investigate a record of a member being added to a local security-enabled group.

**Environment:** Windows 11 workstation (`WS01`).

**Evidence observed:**
- Event ID: `4732`.
- Subject Account Name: `Administrator`.
- Group Name: `Users`.
- Member SID: Began with `S-1-5-21`.
- Timestamp: Overlapped with the period of a controlled `BlueTeamTest` account exercise.

**Analysis:** Event ID `4732` records the addition of a member to a local security-enabled group. Although the timestamp overlapped with the account test, the relationship to `BlueTeamTest` remained unconfirmed because the member SID was not conclusively matched to that account.

**Security relevance:** Local group membership can affect access and privileges. Analysts should verify the affected member, group, initiating account, and timestamp before drawing conclusions.

## 6. Active Directory Group Addition — Event ID 4728

**Objective:** Verify that the domain controller records membership additions to a global security group.

**Environment:** Windows Server domain controller (`SKY-SRV-01`), domain `skyshield.local`.

**Test correlation:** Compared the event timestamp with the original Active Directory group configuration.

**Evidence observed:**
- Event ID: `4728`.
- Subject Account Name: `Administrator`.
- Group Name: `IT-Support`.
- Member Name: Jordan Lee (`jlee`).
- Event timestamp: October 8, 2026, at 7:02:06 PM.

**Result:** The event timestamp matched the original addition of Jordan Lee to the `IT-Support` global security group during lab configuration.

**Security relevance:** Event ID `4728` provides evidence of global security-group membership additions. Analysts can correlate the initiating account, affected group, member identity, and timestamp with authorized changes to investigate potentially unauthorized access or privilege escalation.

## 7. Active Directory Group Removal — Event ID 4729

**Objective:** Verify that the domain controller records the removal of a member from a global security group.

**Environment:** Windows Server domain controller (`SKY-SRV-01`), domain `skyshield.local`.

**Test:** Temporarily removed Jordan Lee (`jlee`) from the `IT-Support` group using Active Directory Users and Computers.

**Evidence observed:**
- Event ID: `4729`.
- Subject Account Name: `Administrator`.
- Group Name: `IT-Support`.
- Member Name: Jordan Lee (`jlee`).

**Result:** Successfully located the Security event corresponding to the controlled group-membership removal. Jordan Lee was subsequently restored to `IT-Support`, returning the lab to its original group-membership state.

**Security relevance:** Event ID `4729` helps analysts investigate access changes, correlate group-membership removals with approved administrative actions, and determine whether a user's access changed unexpectedly.

## Investigation Methodology

For each event, the investigation focused on:

1. Filtering the appropriate Windows Security log by event ID.
2. Reviewing the event timestamp and relevant account or process fields.
3. Comparing the evidence with known lab activity when possible.
4. Distinguishing confirmed observations from assumptions.
5. Recording the security relevance and limitations of the available evidence.

## Limitations

This project uses a small virtual lab and built-in Windows auditing. It does not represent a production Security Operations Center, centralized log-management platform, or full SIEM deployment. Some historical events could not be conclusively attributed to a specific action. Findings are limited to the event details and tests documented here.
