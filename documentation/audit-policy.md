# Windows Security Audit Policy Configuration

## Objective

Document the Windows audit-policy settings reviewed and configured during the Windows Endpoint Security Monitoring & Investigation Lab.

## Lab Environment

- **Workstation:** `WS01` — Windows 11
- **Domain Controller:** `SKY-SRV-01` — Windows Server
- **Active Directory Domain:** `skyshield.local`
- **Tools:** Windows Advanced Audit Policy, Local Security Policy, Command Prompt, and Event Viewer

## Audit Policy Verification

Audit settings were inspected using the `auditpol` command-line utility and, where applicable, the Local Security Policy interface.

### 1. Logon Auditing

**Subcategory:** Logon

**Verified configuration:**
- Success: Enabled
- Failure: Enabled

**Purpose:** Records successful and failed logon activity, supporting authentication troubleshooting and security investigations.

**Verification command:**

```cmd
auditpol /get /subcategory:"Logon"
```

### 2. User Account Management

**Subcategory:** User Account Management

**Verified on WS01:**
- Success: Enabled

**Purpose:** Helps record account-management activity, such as user account creation, deletion, and modification, depending on the event and applicable audit configuration.

**Verification command:**

```cmd
auditpol /get /subcategory:"User Account Management"
```

### 3. Security Group Management

**Subcategory:** Security Group Management

**Verified configuration:**
- Success: Enabled on WS01
- Success: Enabled on the domain controller (`SKY-SRV-01`)

**Purpose:** Supports investigations of security-group membership changes and related administrative activity.

**Verification command:**

```cmd
auditpol /get /subcategory:"Security Group Management"
```

### 4. Process Creation

**Subcategory:** Process Creation

**Initial configuration on WS01:**
- Success: No Auditing

**Change performed:**

Enabled successful Process Creation auditing on `WS01` using an elevated command prompt:

```cmd
auditpol /set /subcategory:"Process Creation" /success:enable
```

**Verification command:**

```cmd
auditpol /get /subcategory:"Process Creation"
```

**Result:** Successful Process Creation auditing was enabled and verified. Launching Notepad generated a Security event with ID `4688`.

**Purpose:** Provides records of process execution that analysts can use to investigate program launches and examine process relationships.

## Configuration and Testing Workflow

1. Inspected existing audit-policy settings.
2. Identified that successful Process Creation auditing was disabled on `WS01`.
3. Enabled successful Process Creation auditing from an elevated command prompt.
4. Verified the updated setting with `auditpol`.
5. Launched Notepad and located the corresponding Event ID `4688` in Event Viewer.

## Important Considerations

- Audit settings can differ between a workstation and a domain controller.
- The settings documented here reflect the lab checks performed; they do not imply that every Windows audit subcategory is enabled.
- This project enabled successful Process Creation auditing. It did not enable failed Process Creation auditing.
- Event collection depends on the applicable audit policy, event type, system activity, and log configuration.
- Security logs can contain sensitive information. Review screenshots and exported evidence before sharing them publicly.

## Outcome

This phase demonstrated how to inspect Windows audit settings, enable a specific audit subcategory, verify the configuration, and validate the result through a controlled process-creation test.
