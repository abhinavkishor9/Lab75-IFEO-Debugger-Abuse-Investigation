# Troubleshooting Notes 

## 1. reg.exe Returned "Invalid key name"

### Problem

The following command was initially attempted:

```powershell
reg.exe query $IFEO /s
```

The command returned:

```text
ERROR: Invalid key name.
```

### Cause

`$IFEO` contained a PowerShell Registry Provider path:

```text
HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe
```

The `reg.exe` utility does not use the PowerShell `HKLM:\` format.

### Fix

Use the native Windows Registry path:

```powershell
reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /s
```

### Lesson

PowerShell Registry paths and `reg.exe` Registry paths use different syntax.

```text
PowerShell:
HKLM:\...

reg.exe:
HKLM\...
```

---

## 2. PowerShell Cleanup Did Not Remove the Debugger Value

### Problem

The following cleanup commands were executed:

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

No visible error was returned.

However, a subsequent Registry query still showed:

```text
Debugger    REG_SZ    C:\WINDOWS\System32\cmd.exe
```

### Impact

The IFEO configuration was still present.

Cleanup could not be considered successful based only on the absence of an error message.

### Fix

The Registry value was removed directly using `reg.exe`:

```powershell
reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /f
```

Result:

```text
The operation completed successfully.
```

### Verification

The value was checked again:

```powershell
reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger
```

Result:

```text
ERROR: The system was unable to find the specified registry key or value.
```

### Lesson

Always verify Registry cleanup after making a security configuration change.

A command completing without an error does not by itself prove that the expected Registry value was removed.

---

## 3. Multiple cmd.exe Processes Were Observed

### Problem

Several `cmd.exe` processes were present during the process investigation.

### Initial Concern

Because `cmd.exe` was the configured IFEO debugger, it could be tempting to assume that every observed `cmd.exe` process was related to the lab.

### Investigation

Process IDs, parent process IDs, executable paths, and command lines were examined.

Some processes were associated with legitimate software such as:

```text
C:\Program Files\McAfee\wps\1.40.161.1\extnhost\mc-extn-browserhost.exe
```

and:

```text
C:\Program Files\McAfee\WebAdvisor\BrowserHost.exe
```

Another observed `cmd.exe` process had Chrome as the parent:

```text
C:\Program Files\Google\Chrome\Application\chrome.exe
```

### Resolution

These processes were not automatically attributed to IFEO.

### Lesson

Process-name matching is not sufficient for process attribution.

Always examine:

- Parent Process ID
- Parent executable
- Parent command line
- Child command line
- Executable path
- User
- Timestamp

---

## 4. Observed Notepad Path Did Not Match IFEO Target

### Problem

The IFEO configuration targeted:

```text
C:\Windows\System32\notepad.exe
```

The observed Notepad process used:

```text
C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2607.14.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe
```

### Impact

The process could not be automatically associated with the IFEO configuration.

### Resolution

The difference in executable paths was documented as an attribution limitation.

The investigation did not claim that the WindowsApps Notepad process was the process targeted by the IFEO configuration.

### Lesson

Executable names are not enough.

When investigating execution-based persistence, validate the complete executable path.

---

## 5. Wazuh Archive Index Was Unavailable

### Problem

The expected Wazuh index:

```text
wazuh-archives-*
```

was not available.

### Available Indexes

The environment provided:

```text
wazuh-alerts-*
wazuh-monitoring-*
wazuh-states-inventory-*
wazuh-states-vulnerabilities-*
wazuh-statistics-*
```

### Resolution

The investigation used:

```text
wazuh-alerts-*
```

where applicable.

The missing archive index was documented as a telemetry limitation.

### Lesson

Do not create or assume SIEM evidence when the required index or data source is unavailable.

Document the evidence gap instead.

---

## 6. Sysmon Event ID 1 Did Not Automatically Prove IFEO Execution

### Problem

Sysmon Event ID 1 showed multiple process creation events involving `cmd.exe` and `notepad.exe`.

### Initial Risk

It would be easy to interpret the presence of both process names as proof that the IFEO configuration triggered `cmd.exe`.

### Investigation

The available events were correlated using:

- Process ID
- Parent Process ID
- Parent Image
- Command Line
- Executable Path
- User
- Timestamp

### Resolution

A confirmed IFEO-triggered process chain could not be established from the available telemetry.

### Lesson

Sysmon Event ID 1 is useful for process investigation, but the event must be correlated with the correct executable path and parent-child relationship.

---

## 7. Registry Modification Telemetry Was Not Independently Confirmed

### Observation

The Registry state clearly showed that the controlled `Debugger` value existed after the lab configuration.

However, a definitive Sysmon Registry modification event was not established from the available telemetry.

### Assessment

The Registry state itself was treated as confirmed evidence.

The absence of a specific Registry modification event was documented as a telemetry limitation.

### Lesson

A current Registry state and a Registry modification event answer different questions.

```text
Registry state:
What configuration exists?

Registry modification event:
When and by which process was the configuration changed?
```

Both can be useful during DFIR investigations, but one should not be substituted for the other.

---

