# Timeline - Lab 75 IFEO Debugger Abuse Investigation

## Investigation Date

**13 September 2026**

## Timeline

| Time | Activity | Evidence / Observation |
|---|---|---|
| Before modification | IFEO baseline collected | `notepad.exe` IFEO key existed |
| Before modification | Existing Registry values reviewed | `UseFilter : 1` observed |
| Before modification | Existing `Debugger` checked | No existing `Debugger` value identified |
| Before modification | Baseline preserved | `ifeo-baseline.txt` |
| Before modification | Target executable validated | `C:\Windows\System32\notepad.exe` |
| Before modification | Target signature checked | Authenticode `Valid` |
| Before modification | Debugger validated | `C:\Windows\System32\cmd.exe` |
| Before modification | Debugger signature checked | Authenticode `Valid` |
| Configuration phase | IFEO key opened/created | `notepad.exe` target key |
| Configuration phase | `Debugger` value created | `C:\Windows\System32\cmd.exe` |
| Configuration phase | Registry configuration verified | `Debugger` value confirmed |
| Configuration phase | Registry evidence exported | `ifeo-after-change.txt` and `ifeo-properties.txt` |
| 08:32:11 | Sysmon Event ID 1 observed | Process creation telemetry |
| 08:37:08 | Sysmon Event ID 1 observed | Process creation telemetry |
| 08:39:47 | Sysmon Event ID 1 observed | Process creation telemetry |
| 08:41:17 | Sysmon Event ID 1 observed | Process creation telemetry |
| 08:41:44 | Sysmon Event ID 1 observed | Process creation telemetry |
| 08:43:16 | Sysmon Event ID 1 observed | Process creation telemetry |
| Investigation phase | Multiple `cmd.exe` processes reviewed | Some associated with legitimate software |
| Investigation phase | Notepad process reviewed | WindowsApps/MSIX path observed |
| Investigation phase | Process attribution assessed | IFEO-triggered chain remained inconclusive |
| Investigation phase | Wazuh indexes reviewed | `wazuh-alerts-*` available |
| Investigation phase | Wazuh archive index checked | `wazuh-archives-*` unavailable |
| Evidence phase | Process evidence preserved | `process-events.txt` |
| Cleanup phase | PowerShell cleanup attempted | `Debugger` remained present |
| Cleanup phase | Registry value deleted with `reg.exe` | Operation completed successfully |
| Final verification | `Debugger` value queried | Specified value no longer found |
| Final state | Lab configuration removed | Cleanup confirmed |

---

## Key Evidence Timeline

### 1. Baseline

The IFEO key for `notepad.exe` was inspected before modification.

Observed:

```text
UseFilter : 1
```

No existing `Debugger` value was identified.

Evidence:

```text
C:\IFEODebuggerLab\Evidence\ifeo-baseline.txt
```

---

### 2. Controlled Configuration

The following value was added:

```text
Debugger    REG_SZ    C:\WINDOWS\System32\cmd.exe
```

Evidence:

```text
C:\IFEODebuggerLab\Evidence\ifeo-after-change.txt
C:\IFEODebuggerLab\Evidence\ifeo-properties.txt
```

---

### 3. Process Investigation

Sysmon Event ID 1 process creation telemetry was reviewed.

Observed timestamps included:

```text
08:32:11
08:37:08
08:39:47
08:41:17
08:41:44
08:43:16
```

The process investigation did not establish a confirmed IFEO-triggered:

```text
notepad.exe -> cmd.exe
```

relationship.

Evidence:

```text
C:\IFEODebuggerLab\Evidence\process-events.txt
```

---

### 4. Wazuh Review

Available Wazuh indexes included:

```text
wazuh-alerts-*
wazuh-monitoring-*
wazuh-states-inventory-*
wazuh-states-vulnerabilities-*
wazuh-statistics-*
```

The expected:

```text
wazuh-archives-*
```

index was unavailable.

This was recorded as an evidence gap.

---

### 5. Cleanup

Initial PowerShell cleanup was attempted, but verification showed that:

```text
Debugger    REG_SZ    C:\WINDOWS\System32\cmd.exe
```

was still present.

The value was subsequently removed using:

```powershell
reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /f
```

Result:

```text
The operation completed successfully.
```

---

### 6. Final Verification

The final check was:

```powershell
reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger
```

Result:

```text
ERROR: The system was unable to find the specified registry key or value.
```

Final status:

```text
IFEO Debugger Value:
Removed

Cleanup:
Successful
```

---

## Evidence State Over Time

```text
Baseline
   |
   | No Debugger value identified
   v
Controlled IFEO Configuration
   |
   | Debugger = C:\Windows\System32\cmd.exe
   v
Process Investigation
   |
   | Multiple process events observed
   | IFEO attribution inconclusive
   v
Wazuh Review
   |
   | Alerts available
   | Archives unavailable
   v
Cleanup Attempt
   |
   | Debugger still present
   v
reg.exe Deletion
   |
   | Operation successful
   v
Final Verification
   |
   | Debugger value not found
   v
Clean Lab State
```

---

## Final Timeline Assessment

The timeline confirms that the controlled IFEO configuration was created, investigated, and subsequently removed.

The process telemetry did not provide sufficient evidence to establish a confirmed IFEO-triggered process chain.

The final Registry verification confirmed that the test `Debugger` value was removed successfully.

> **Follow the evidence, not the assumption.**
