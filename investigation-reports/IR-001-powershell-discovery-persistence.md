# IR-001: Encoded PowerShell → Discovery → Scheduled Task Persistence

| | |
|---|---|
| **Host** | `win11-endpoint` (Wazuh agent 001, Windows 11) |
| **User** | `HarshaPai\Harsha_Pai`, integrity level High |
| **Severity** | High (rules 92057 and 100010 both level 12) |
| **Verdict** | True positive: controlled attack simulation in my own lab |
| **Timestamps** | IST (UTC+5:30) unless marked UTC |

> **Note on method.** The three stages were run as separate test sessions on 2026-10-07, not as one continuous incident. This report orders them as an attacker would (execution → discovery → persistence) and gives the real timestamp for each. Both the execution and persistence events carry the same logon session (`LogonId 0x25fbb`), which ties them to one user session.

## 1. Alert

Wazuh raised three alert families on the same host and user:

| Stage | Rule | Level | MITRE | Description |
|---|---|---|---|---|
| Execution | 92057 | 12 | T1059.001 | `powershell.exe` spawned a powershell process which executed a base64 encoded command |
| Discovery | 92031 / 92033 | 3 | TA0007 | Discovery activity executed / spawned via powershell |
| Persistence | 100010 (custom) | 12 | T1053.005 | Suspicious scheduled task creation detected - possible persistence |

## 2. Triage

- **92057** was the highest-signal alert: hidden window, no profile, encoded payload, High integrity. I decoded the payload instead of trusting the level (see section 6).
- **92031/92033** are level 3 on their own, but they matter in context: recon commands launched from PowerShell on a host that had just run an encoded command.
- **100010** is my custom rule. The command line shows a task named `UpdaterTask2` that runs daily at 03:30. That name mimics a legitimate update task, which is a typical persistence disguise.
- **A false positive I ruled out:** rule 92058 (Application Compatibility Database launched, level 12) recurred four times in the same period. The first instance had command line `sdbinst.exe -m -bg` with parent `svchost.exe`, a benign Windows maintenance pattern. Later instances showed no parent in the dashboard grid, so I treated them as the same recurring pattern and closed them as false positives, flagged to revisit if the pattern changes. Evidence: [rule detail](../screenshots/03-triage-and-telemetry/tri-01-rule-92058-detail.png), [recurrence](../screenshots/03-triage-and-telemetry/tri-02-rule-92058-recurrence.png), [parent process](../screenshots/03-triage-and-telemetry/tri-03-sysmon-event-parent-svchost.png).

## 3. Timeline

| Time (IST) | Stage | Event |
|---|---|---|
| 02:01 (Oct 7) | Persistence | First scheduled task `UpdaterTask` created; rule 100010 fired |
| 15:48:48 | Persistence | `schtasks /create /tn UpdaterTask2 ... /sc daily /st 03:30 /f`; alert at 15:48:49 |
| 20:37:23 | Execution | `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand ...`; alert at 20:37:49 |
| 23:30:48-49 | Discovery | Discovery commands from PowerShell; rules 92031 and 92033 fired (two pairs) |

Logical attack order: **20:37 execution → 23:30 discovery → 15:48 persistence**, with the stages run on different occasions.

Detection latency (event to alert): about 0.5 s for 100010 and about 26 s for 92057.

## 4. Root cause

All activity runs from an interactive, elevated `powershell.exe` session started by `Harsha_Pai` (parent `powershell.exe`, no unusual grandparent). That session is the operator's own simulated foothold. In a real incident the next question would be how that session was obtained (phishing, stolen credentials, exposed remote access); this lab has no such upstream event because I started the session myself.

## 5. Scope

- **Hosts:** one (`win11-endpoint`). The lab has a single monitored endpoint, so lateral movement could not be assessed.
- **Accounts:** one (`Harsha_Pai`). A separate local-admin creation test (rule 60154, test account `labadmin`) was a different simulation; `net user` on the endpoint now shows no `labadmin` account.
- **Pivot query used in the dashboard:** `agent.name: "win11-endpoint" AND data.win.eventdata.logonId: "0x25fbb"` returns every event in the same logon session.
- **Persistence artifacts created during the test:** scheduled tasks `UpdaterTask` and `UpdaterTask2` (confirmed absent on 2026-10-10, see section 7), plus test files in `C:\Users\Public`.

## 6. Evidence and IOCs

**Execution (92057), 2026-10-07 15:07:23 UTC**

- Command line: `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand dwBoAG8AYQBtAGkAOwAgAEcAZQB0AC0AUAByAG8AYwBlAHMAcwAgAHwAIABTAGUAbABlAGMAdAAgAC0ARgBpAHIAcwB0ACAAMwA=`
- Decoded (base64, UTF-16LE): `whoami; Get-Process | Select -First 3`. The payload is harmless recon; the *technique* (hidden window plus encoding) is what the rule targets.
- Process: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, PID 7020, parent PID 592 (`powershell.exe`)
- SHA256: `8BB6FA8C283B4D92120B1EF249A9B311B0F804D4CABBE9981159976C8BE76A5E`
- MD5: `61F649A6FDC374A6BF36C860519E017C`

**Persistence (100010), 2026-10-07 10:18:48 UTC**

- Command line: `schtasks.exe /create /tn UpdaterTask2 /tr "C:\Windows\System32\cmd.exe /c echo lab-persistence2" /sc daily /st 03:30 /f`
- Parent: `powershell.exe` (PID 1092), same user and `LogonId 0x25fbb`
- SHA256 (`schtasks.exe`): `B96AF3066F0B9DE8A460F77BAAE006C5372A266BE18C561DAA7C7AE8635D399D`
- Artifacts: scheduled tasks `UpdaterTask`, `UpdaterTask2`

Hashes belong to genuine signed Windows binaries (living off the land), so hash reputation would not flag them. Behaviour does.

Screenshots: [92057 hits](../screenshots/02-detections/det-04-rule-92057-encoded-powershell.png) · [discovery](../screenshots/02-detections/det-05-rules-92031-92033-discovery.png) · [100010 alert](../screenshots/02-detections/det-03-rule-100010-alert-commandline.png)

## 7. Response

**Recommended in a real incident:** isolate the host, disable or reset the account, hunt the same logon session, remove persistence, then review how the session began.

**Verified and cleaned up on the lab endpoint (2026-10-10):**

- **Scheduled tasks:** `schtasks /query /fo LIST | findstr /i "UpdaterTask"` returned nothing, and `schtasks /delete` for both `UpdaterTask` and `UpdaterTask2` reported the task does not exist. Neither persistence task was present when checked.
- **Registry Run keys (HKCU and HKLM):** only legitimate entries remain (OneDrive, Edge auto-launch, SecurityHealth, VBoxTray). No lab persistence entry is present.
- **Local accounts:** `net user` lists no `labadmin` account.
- **Residual test files:** `attack-transcript.txt`, `bits_download.txt`, `bits_download2.txt` and `iwr_download.txt` in `C:\Users\Public` were deleted.

## 8. Detection gaps and improvements

- Decode `-EncodedCommand` payloads automatically and alert on download or credential-access keywords in the decoded text.
- Add allow-listing to rule 100010 (known installers) and flag tasks pointing at user-writable paths.
- Correlate by `logonId` so execution, discovery and persistence from one session raise a single higher-severity alert.
- Level-3 discovery alerts are easy to ignore; a frequency rule (several discovery commands within one minute) would raise their priority.
