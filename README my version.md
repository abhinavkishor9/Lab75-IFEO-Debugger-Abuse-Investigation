# Lab75-IFEO-Debugger-Abuse-Investigation
## Lab Scenario
Image File Execution Options (IFEO) is a legitimate Windows mechanism used by developers and administrators to configure debugging behavior for specific executables. IFEO configuration is stored in the Windows Registry under:

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\

A subkey can be created for a particular executable, for example:

...\Image File Execution Options\notepad.exe

One of the values that can be configured is:

Debugger

When Windows launches the targeted executable, the configured debugger can be invoked. This makes IFEO useful for legitimate debugging—but also potentially interesting from a persistence and execution-abuse perspective.

For SOC/DFIR purposes, the important question is therefore not:

“Does an IFEO key exist?”

but:

“Was an IFEO Debugger value created or modified, what executable does it target, what debugger is configured, who made the change, and what happened when the target executable was launched?”

Image File Execution Options (IFEO) is a legitimate Windows feature that allows developers and administrators to configure debugging behavior for specific executables. However, the same mechanism can be abused to redirect the execution of a targeted application through the `Debugger` Registry value.

In this lab, a controlled IFEO configuration was created for `notepad.exe`, with the legitimate Windows `cmd.exe` executable configured as the debugger. The lab focuses on identifying the Registry configuration, validating the target and debugger, examining process creation telemetry with Sysmon, reviewing available Wazuh telemetry, correlating process evidence, documenting telemetry limitations, and safely removing the configuration after the investigation.

The investigation follows the principle:

> **Follow the evidence, not the assumption.**

No malicious payload was used in this lab.

---

## Lab Objectives

- Understand the purpose of Image File Execution Options (IFEO) and how the Debugger value can influence application execution.
- Simulate a controlled IFEO configuration targeting notepad.exe and pointing it to the legitimate cmd.exe executable.
- Examine the Windows Registry to identify the targeted application, configured debugger, and other existing IFEO properties.
- Validate the target and debugger executables using their file paths, metadata, and Authenticode signatures.
- Use Sysmon Event ID 1 to investigate process creation and identify relevant notepad.exe and cmd.exe activity.
- Correlate process IDs, parent processes, command lines, timestamps, and user context to determine whether observed activity is related to the IFEO configuration.
- Review available Wazuh telemetry and identify whether additional evidence supports the investigation.
- Distinguish the controlled IFEO activity from unrelated legitimate cmd.exe executions and avoid unsupported process attribution.
- Preserve important Registry and process artifacts for investigation and documentation.
- Remove the test Debugger configuration and verify that the endpoint has returned to its expected state.

---
## Lab Scenario

A Windows endpoint is being investigated for possible IFEO Debugger abuse. IFEO is a legitimate Windows debugging feature, but attackers can abuse the Debugger Registry value to redirect the execution of a targeted application. In this controlled lab, notepad.exe is configured with cmd.exe as its debugger, and the analyst investigates the resulting Registry and process activity using PowerShell, Sysmon, and Wazuh.

The investigation focuses on:

- Identifying the IFEO Debugger configuration.
- Validating the target and debugger executables.
- Reviewing Sysmon Event ID 1 process activity.
- Correlating parent-child processes and command lines.
- Checking available Wazuh telemetry.
- Determining whether the observed activity can be attributed to IFEO.
- Removing and verifying the test configuration.

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

