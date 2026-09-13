# Timeline

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

