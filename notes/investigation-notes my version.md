# Investigation Notes 

## 1. IFEO Registry Path

The target Registry path was:

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe
```

The PowerShell Registry provider path was:

```powershell
$IFEO = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe"
```

The Registry location is important because IFEO configurations are stored on a per-executable basis.

---

## 2. Baseline Check

The existing IFEO configuration was checked before making any changes:

```powershell
Get-ItemProperty $IFEO -ErrorAction SilentlyContinue
```

The key itself was also checked:

```powershell
Get-Item $IFEO -ErrorAction SilentlyContinue
```

The baseline contained:

```text
UseFilter : 1
```

No existing `Debugger` value was identified.

The baseline was saved to:

```text
C:\IFEODebuggerLab\Evidence\ifeo-baseline.txt
```

The existing `UseFilter` value was treated as baseline information and was not considered part of the controlled modification.

---

## 3. Target Validation

The target executable was defined as:

```powershell
$Target = "$env:windir\System32\notepad.exe"
```

Resolved path:

```text
C:\WINDOWS\System32\notepad.exe
```

Observed properties:

```text
Size: 360448 bytes
Authenticode: Valid
```

The target executable itself was not modified.

---

## 4. Debugger Validation

The debugger executable was defined as:

```powershell
$Debugger = "$env:windir\System32\cmd.exe"
```

Resolved path:

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

## 5. IFEO Modification

The target key was created or opened:

```powershell
New-Item -Path $IFEO -Force | Out-Null
```

The controlled debugger value was added:

```powershell
New-ItemProperty `
    -Path $IFEO `
    -Name "Debugger" `
    -PropertyType String `
    -Value "$env:windir\System32\cmd.exe" `
    -Force
```

The configuration was verified with:

```powershell
Get-ItemProperty $IFEO
```

Observed value:

```text
Debugger : C:\WINDOWS\System32\cmd.exe
```

Evidence was exported to:

```text
C:\IFEODebuggerLab\Evidence\ifeo-after-change.txt
C:\IFEODebuggerLab\Evidence\ifeo-properties.txt
```

---

## 6. Registry Verification with reg.exe

The Registry configuration was also verified with `reg.exe`.

An important syntax difference was identified during the investigation.

PowerShell uses:

```text
HKLM:\
```

`reg.exe` uses:

```text
HKLM\
```

Therefore, this command was used:

```powershell
reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /s
```

The resulting configuration included:

```text
Debugger    REG_SZ    C:\WINDOWS\System32\cmd.exe
```

This confirmed that the controlled value was present.

---

## 7. Controlled Execution

The target executable was launched:

```powershell
Start-Process "$env:windir\System32\notepad.exe"
```

Process information was collected using:

```powershell
Get-Process cmd
```

```powershell
Get-Process notepad
```

Additional process information was collected using:

```powershell
Get-CimInstance Win32_Process
```

The investigation focused on:

- Process ID
- Parent Process ID
- Executable path
- Command line
- Parent executable
- Parent command line
- User
- Timestamp

---

## 8. Sysmon Investigation

Sysmon Event ID 1 was used to review process creation telemetry.

An IFEO-related search was performed:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
} -MaxEvents 200 |
Where-Object {
    $_.Message -match "Image File Execution Options"
}
```

A process-name search was also performed:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
} -MaxEvents 200 |
Where-Object {
    $_.Message -match "notepad.exe|cmd.exe"
}
```

Observed Event ID 1 timestamps included:

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

## 9. Process Correlation

Multiple `cmd.exe` processes were observed.

The investigation identified legitimate software relationships among some of the processes.

Examples included parent processes associated with:

```text
C:\Program Files\McAfee\wps\1.40.161.1\extnhost\mc-extn-browserhost.exe
```

and:

```text
C:\Program Files\McAfee\WebAdvisor\BrowserHost.exe
```

A Sysmon Event ID 1 record also showed a `cmd.exe` process with a Chrome parent:

```text
Parent Image:
C:\Program Files\Google\Chrome\Application\chrome.exe

Original File Name:
Cmd.Exe

User:
DESKTOP-9MMM37V\Dell

Event ID:
1
```

This was treated as legitimate browser-related process activity rather than automatically associating it with IFEO.

---

## 10. Notepad Path Validation

The observed Notepad process used:

```text
C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2607.14.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
```

The IFEO configuration targeted:

```text
C:\Windows\System32\notepad.exe
```

The paths are different.

This created an important attribution limitation.

The presence of a `notepad.exe` process did not prove that the System32 executable configured in IFEO was responsible for that process.

---

## 11. Process Attribution

The available telemetry did not provide sufficient evidence to confirm a specific:

```text
notepad.exe
    |
    +--- cmd.exe
```

relationship caused by the IFEO configuration.

The investigation therefore classified the process attribution as:

```text
Inconclusive
```

This was based on the available evidence rather than an assumption.

---

## 12. Wazuh Investigation

The Wazuh Dashboard was reviewed for supporting telemetry.

The expected archive index:

```text
wazuh-archives-*
```

was not available.

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

Search terms included:

```text
Image File Execution Options
notepad.exe
cmd.exe
```

The unavailable archive index was recorded as an evidence gap.

---

## 13. Evidence Preservation

The following artifacts were preserved:

```text
C:\IFEODebuggerLab\Evidence\
    ifeo-baseline.txt
    ifeo-after-change.txt
    ifeo-properties.txt
    ifeo-final-before-cleanup.txt
    process-events.txt
```

These files preserve the Registry state and process investigation information collected during the lab.

---

## 14. Cleanup Investigation

The initial PowerShell cleanup was attempted:

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

A subsequent Registry query showed:

```text
Debugger    REG_SZ    C:\WINDOWS\System32\cmd.exe
```

The value was therefore still present.

The cleanup was not considered successful at this stage.

---

## 15. Final Cleanup

The remaining `Debugger` value was removed using:

```powershell
reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /f
```

Result:

```text
The operation completed successfully.
```

Final verification:

```powershell
reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger
```

Result:

```text
ERROR: The system was unable to find the specified registry key or value.
```

The test `Debugger` value was therefore successfully removed.

---

## 16. Evidence Assessment

| Evidence | Result |
|---|---|
| IFEO key exists | Confirmed |
| Baseline `UseFilter` | Confirmed |
| Existing `Debugger` before lab | Not identified |
| Controlled `Debugger` value | Confirmed |
| Debugger path | `C:\Windows\System32\cmd.exe` |
| Debugger signature | Valid |
| Sysmon Event ID 1 | Available |
| `cmd.exe` activity | Observed |
| IFEO-specific process chain | Inconclusive |
| Wazuh alerts index | Available |
| Wazuh archives index | Unavailable |
| Cleanup | Confirmed successful |

---

## 17. MITRE ATT&CK

Relevant technique:

```text
T1546.012 - Event Triggered Execution: Image File Execution Options Injection
```

The technique is relevant because IFEO can be abused to influence the execution of a targeted application through Registry configuration.

---

