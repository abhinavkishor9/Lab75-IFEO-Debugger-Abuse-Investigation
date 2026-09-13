# Lab 75 - IFEO Debugger Abuse Investigation

## Lab Scenario

Image File Execution Options (IFEO) is a legitimate Windows feature that allows developers and administrators to configure debugging behavior for specific executables. However, the same mechanism can be abused to redirect the execution of a targeted application through the `Debugger` Registry value.

In this lab, a controlled IFEO configuration was created for `notepad.exe`, with the legitimate Windows `cmd.exe` executable configured as the debugger. The lab focuses on identifying the Registry configuration, validating the target and debugger, examining process creation telemetry with Sysmon, reviewing available Wazuh telemetry, correlating process evidence, documenting telemetry limitations, and safely removing the configuration after the investigation.

The investigation follows the principle:

> **Follow the evidence, not the assumption.**

No malicious payload was used in this lab.

---

## Lab Objectives

- Understand how Windows Image File Execution Options work.
- Identify the Registry location used by IFEO.
- Establish a baseline before modifying the Registry.
- Determine whether a `Debugger` value already exists.
- Create a controlled IFEO `Debugger` configuration.
- Validate the configured target executable.
- Validate the configured debugger executable.
- Capture Registry evidence before and after the change.
- Investigate process creation using Sysmon Event ID 1.
- Examine process IDs and parent process IDs.
- Review executable paths and command lines.
- Investigate available Wazuh telemetry.
- Correlate Registry and process evidence.
- Identify situations where process attribution is inconclusive.
- Preserve investigation artifacts.
- Remove the test configuration.
- Verify that the `Debugger` value was successfully removed.

---

## Lab Environment

- **Operating System:** Windows 11 Pro
- **Hostname:** `DESKTOP-9MMM37V`
- **User:** `desktop-9mmm37v\dell`
- **PowerShell:** 7.6.6
- **Sysmon:** Installed
- **Wazuh Agent:** Installed
- **Primary Sysmon Event:** Event ID 1
- **IFEO Target:** `notepad.exe`
- **Debugger:** `C:\Windows\System32\cmd.exe`
- **Lab Directory:** `C:\IFEODebuggerLab`
- **Date:** 13 September 2026

---

## Key Concept

The IFEO Registry location is:

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\
```

Each executable can have its own IFEO subkey.

For this lab:

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe
```

The controlled `Debugger` value was configured as:

```text
Debugger = C:\Windows\System32\cmd.exe
```

When investigating IFEO abuse, the presence of the Registry key alone should not be treated as proof of malicious activity. The configured debugger, executable location, process creation events, parent-child relationship, command line, user context, and surrounding telemetry should also be examined.

---

## Investigation Workflow

1. Establish IFEO baseline
2. Validate target executable
3. Validate debugger executable
4. Create controlled IFEO configuration
5. Verify Registry modification
6. Generate controlled process activity
7. Review Sysmon Event ID 1
8. Correlate process information
9. Review Wazuh telemetry
10. Preserve evidence
11. Remove IFEO configuration
12. Validate cleanup

---

## Step 1 - Establish IFEO Baseline

Define the Registry path:

```powershell
$IFEO = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe"
```

Check the existing Registry configuration:

```powershell
Get-ItemProperty $IFEO -ErrorAction SilentlyContinue
```

Check whether the Registry key exists:

```powershell
Get-Item $IFEO -ErrorAction SilentlyContinue
```

The baseline showed:

```text
UseFilter : 1
```

No existing `Debugger` value was identified during the baseline check.

The baseline evidence was saved to:

```text
C:\IFEODebuggerLab\Evidence\ifeo-baseline.txt
```

---

## Step 2 - Validate the Target Executable

Set the target executable:

```powershell
$Target = "$env:windir\System32\notepad.exe"
```

The resolved target was:

```text
C:\WINDOWS\System32\notepad.exe
```

Observed properties:

```text
Size: 360448 bytes
Authenticode: Valid
```

The target executable was not modified as part of the lab.

---

## Step 3 - Validate the Debugger Executable

Set the debugger:

```powershell
$Debugger = "$env:windir\System32\cmd.exe"
```

The resolved debugger was:

```text
C:\WINDOWS\System32\cmd.exe
```

Observed properties:

```text
Size: 344064 bytes
Authenticode: Valid
```

SHA-256:

```text
97AC98B1A92C286054CCE55239CFCCDFC23A5517BD07FE693072C9CA96C7DABB
```

The configured debugger was a legitimate Windows executable.

---

## Step 4 - Create the IFEO Configuration

Create or open the target IFEO key:

```powershell
New-Item -Path $IFEO -Force | Out-Null
```

Create the controlled `Debugger` value:

```powershell
New-ItemProperty `
    -Path $IFEO `
    -Name "Debugger" `
    -PropertyType String `
    -Value "$env:windir\System32\cmd.exe" `
    -Force
```

Verify the configuration:

```powershell
Get-ItemProperty $IFEO
```

Expected configuration:

```text
Debugger : C:\WINDOWS\System32\cmd.exe
```

Save the modified Registry state:

```text
C:\IFEODebuggerLab\Evidence\ifeo-after-change.txt
C:\IFEODebuggerLab\Evidence\ifeo-properties.txt
```

---

## Step 5 - Verify the Registry Configuration

The configuration can also be checked with `reg.exe`.

PowerShell uses:

```text
HKLM:\
```

However, `reg.exe` uses:

```text
HKLM\
```

Therefore, the correct command is:

```powershell
reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /s
```

The relevant configuration was:

```text
Debugger    REG_SZ    C:\WINDOWS\System32\cmd.exe
```

This confirms that the controlled `Debugger` value existed during the lab.

---

## Step 6 - Generate Controlled Process Activity

Launch the target executable:

```powershell
Start-Process "$env:windir\System32\notepad.exe"
```

Review `cmd.exe` processes:

```powershell
Get-Process cmd
```

Review Notepad processes:

```powershell
Get-Process notepad
```

Additional process information can be collected with:

```powershell
Get-CimInstance Win32_Process
```

The investigation should focus on:

- Process ID
- Parent Process ID
- Executable path
- Command line
- Parent executable
- Parent command line
- User
- Timestamp

---

## Step 7 - Investigate Sysmon Event ID 1

Sysmon Event ID 1 records process creation activity.

Search for IFEO-related process activity:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
} -MaxEvents 200 |
Where-Object {
    $_.Message -match "Image File Execution Options"
}
```

Search for relevant process names:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
} -MaxEvents 200 |
Where-Object {
    $_.Message -match "notepad.exe|cmd.exe"
}
```

Observed Sysmon Event ID 1 timestamps included:

```text
08:32:11
08:37:08
08:39:47
08:41:17
08:41:44
08:43:16
```

The process evidence was saved to:

```text
C:\IFEODebuggerLab\Evidence\process-events.txt
```

---

## Step 8 - Correlate Process Activity

Multiple `cmd.exe` processes were observed during the investigation.

Some `cmd.exe` processes were associated with legitimate applications, including McAfee browser components.

Examples included parent processes associated with:

```text
C:\Program Files\McAfee\wps\1.40.161.1\extnhost\mc-extn-browserhost.exe
```

and:

```text
C:\Program Files\McAfee\WebAdvisor\BrowserHost.exe
```

Therefore, the presence of `cmd.exe` in Sysmon telemetry was not treated as proof of IFEO-triggered execution.

Process names alone are insufficient for attribution.

The investigation instead considered:

- Parent process
- Parent command line
- Executable path
- Process ID
- Parent Process ID
- Timestamp
- User context

---

## Step 9 - Validate the Observed Notepad Path

An important observation was that the observed Notepad process used the following WindowsApps path:

```text
C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2607.14.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
```

The IFEO configuration targeted:

```text
C:\Windows\System32\notepad.exe
```

These are different executable paths.

Therefore, the observed Notepad process could not automatically be attributed to the IFEO configuration.

The investigation did not claim a confirmed process chain such as:

```text
notepad.exe
    |
    +--- cmd.exe
```

because the available evidence did not conclusively establish that relationship.

---

## Step 10 - Review Wazuh Telemetry

The Wazuh Dashboard was reviewed for available telemetry.

The expected archive index:

```text
wazuh-archives-*
```

was not available in the environment.

Available index patterns included:

```text
wazuh-alerts-*
wazuh-monitoring-*
wazuh-states-inventory-*
wazuh-states-vulnerabilities-*
wazuh-statistics-*
```

The investigation therefore used the available:

```text
wazuh-alerts-*
```

index where applicable.

Potential search terms included:

```text
Image File Execution Options
notepad.exe
cmd.exe
```

The absence of `wazuh-archives-*` was documented as a telemetry limitation rather than assuming that archive events existed.

---

## Step 11 - Preserve Evidence

The following evidence files were created during the lab:

```text
C:\IFEODebuggerLab\Evidence\
    ifeo-baseline.txt
    ifeo-after-change.txt
    ifeo-properties.txt
    ifeo-final-before-cleanup.txt
    process-events.txt
```

These files preserve the Registry state and process investigation data collected during the exercise.

---

## Step 12 - Remove the IFEO Configuration

The initial PowerShell cleanup was attempted with:

```powershell
Remove-ItemProperty `
    -Path $IFEO `
    -Name "Debugger" `
    -ErrorAction SilentlyContinue

Remove-Item `
    -Path $IFEO `
    -Force `
    -ErrorAction SilentlyContinue
```

A subsequent Registry query showed that the `Debugger` value was still present:

```text
Debugger    REG_SZ    C:\WINDOWS\System32\cmd.exe
```

Therefore, cleanup was not considered successful at this stage.

---

## Step 13 - Complete Cleanup Using reg.exe

The remaining `Debugger` value was removed directly:

```powershell
reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /f
```

The command returned:

```text
The operation completed successfully.
```

---

## Step 14 - Validate Cleanup

The final Registry check was:

```powershell
reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger
```

The result was:

```text
ERROR: The system was unable to find the specified registry key or value.
```

This confirmed that the lab-created `Debugger` value had been removed.

The remaining `UseFilter` configuration was not treated as part of the test configuration because it existed during the original baseline.

---

## Findings

### Confirmed

- The IFEO key for `notepad.exe` existed.
- `UseFilter = 1` was present during the baseline.
- No existing `Debugger` value was identified during the baseline.
- A controlled `Debugger` value was created.
- The debugger was configured as `C:\Windows\System32\cmd.exe`.
- The debugger executable had valid Authenticode validation.
- Sysmon Event ID 1 telemetry was available.
- Multiple `cmd.exe` process events were observed.
- Wazuh alert telemetry was available.
- The `wazuh-archives-*` index was unavailable.
- The test `Debugger` value was successfully removed.

### Inconclusive

The available evidence did not conclusively establish that an observed `cmd.exe` process was launched because of the IFEO configuration.

The observed Notepad process also used a WindowsApps/MSIX path rather than the targeted:

```text
C:\Windows\System32\notepad.exe
```

Therefore, the process relationship was not treated as confirmed.

---

## Evidence Gaps

The investigation had several telemetry limitations:

- No `wazuh-archives-*` index was available.
- Multiple legitimate `cmd.exe` processes were present.
- The observed Notepad process path did not match the System32 IFEO target.
- A definitive Registry modification event was not established through Sysmon telemetry.
- The available process telemetry was insufficient to prove an IFEO-triggered process chain.

These limitations were documented instead of filling the gaps with assumptions.

---

## MITRE ATT&CK Mapping

### T1546.012 - Image File Execution Options Injection

**Technique:** `T1546.012`

**Tactic:** Persistence / Privilege Escalation

IFEO can be abused to influence the execution of targeted applications by configuring a debugger through the Windows Registry.

This lab demonstrates the Registry configuration and investigation process in a controlled environment.

---

## SOC Analyst Takeaways

When investigating possible IFEO abuse, a SOC analyst should not stop after finding the Registry key.

The investigation should correlate:

- IFEO Registry key
- `Debugger` value
- Debugger executable path
- File signature
- File hash
- User context
- Process creation events
- Parent-child relationships
- Command lines
- Process timestamps
- SIEM telemetry
- Endpoint telemetry
- Evidence gaps

A debugger pointing to a suspicious executable in a user-writable directory would require additional investigation.

A legitimate executable such as:

```text
C:\Windows\System32\cmd.exe
```

should still be investigated in context rather than automatically classified as malicious.

---

## Final Lab Verdict

```text
IFEO Configuration: Confirmed

Debugger Value: Confirmed

Debugger:
C:\Windows\System32\cmd.exe

Malicious Activity: Not Established

IFEO-triggered Process Chain: Inconclusive

Wazuh Archive Telemetry: Unavailable

Cleanup: Confirmed Successful
```

## Key DFIR Principle

> **Artifact != Proof**

The Registry configuration proves that the IFEO `Debugger` value existed during the lab.

Sysmon provides process creation telemetry.

Wazuh provides additional SIEM visibility when the required telemetry is available.

The final determination must be based on correlation of the available evidence rather than the presence of a single suspicious-looking artifact.
