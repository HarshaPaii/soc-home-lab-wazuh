# Custom Detection Rules

Two custom Wazuh rules live in `/var/ossec/etc/rules/local_rules.xml` on the Wazuh-SIEM manager. Both match Sysmon Event ID 1 (process creation) forwarded by the Wazuh agent on `win11-endpoint`.

| Rule | Level | MITRE | Detects |
|---|---|---|---|
| 100010 | 12 | T1053.005 Scheduled Task | `schtasks.exe /create` |
| 100012 | 12 | T1105 Ingress Tool Transfer | `bitsadmin.exe` or `certutil.exe` execution |

Validate any rule change before restarting the manager:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t && echo "CONFIG OK"
sudo systemctl restart wazuh-manager
```

---

## Rule 100010: Scheduled task persistence

```xml
<group name="local,sysmon,persistence,">
  <rule id="100010" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)schtasks\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)/create</field>
    <description>Suspicious scheduled task creation detected - possible persistence</description>
    <mitre><id>T1053.005</id></mitre>
  </rule>
</group>
```

**Why I wrote it:** creating a scheduled task is a common way to survive reboots. I wanted an explicit level-12 alert on `schtasks /create` so persistence stands out from routine process-creation noise.

**Test and result:** `schtasks /create /tn UpdaterTask2 /tr "cmd.exe /c echo lab-persistence2" /sc daily /st 03:30 /f` run from an elevated PowerShell session. The rule fired on the first task (about 02:01 IST) and again on the second (15:48:49 IST on 2026-10-07), so it fired reliably, not once.

Evidence: [rule detail](../screenshots/02-detections/det-02-rule-100010-detail.png) · [alert with command line](../screenshots/02-detections/det-03-rule-100010-alert-commandline.png)

### The debugging story (about 3 hours)

The rule never fired at first. I checked, in order: Sysmon logging locally (it was), the agent's `ossec.conf` Sysmon block, rule syntax, VM RAM, and clock sync. All were healthy.

The real cause was in the pipeline, not the rule. The indexer connector was repeatedly failing to sync the state of agent 001 because the agent's database was corrupted. The fix:

1. Stop `wazuh-dashboard`, `wazuh-manager`, `wazuh-indexer`.
2. Delete `/var/ossec/queue/db/001.db` and `/var/ossec/var/db/agents/001*`.
3. Start `wazuh-indexer`, then `wazuh-manager`, then `wazuh-dashboard`, with pauses between.
4. Restart `WazuhSvc` on the Windows agent so it re-registers its state.

After that the rule fired immediately.

**What I would do differently:** check whether the alert exists on the manager first (`/var/ossec/logs/alerts/alerts.json`, or test the raw event with `wazuh-logtest`). That one check separates "rule logic is wrong" from "events are not reaching the indexer" in minutes.

### Known limits and tuning ideas

- Matches any `/create`, including legitimate software installers. In production I would add exceptions for known parent processes and flag tasks that run from user-writable paths (`C:\Users\Public`, `%TEMP%`).
- Rule 100011, an earlier draft for encoded PowerShell, was superseded: Wazuh's built-in rule 92057 already catches that behaviour and is the rule that alerted in testing, so I relied on it rather than duplicate it.

---

## Rule 100012: LOLBin file download (bitsadmin / certutil)

```xml
<group name="local,sysmon,execution,">
  <rule id="100012" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)bitsadmin\.exe|certutil\.exe</field>
    <description>Suspicious LOLBin usage - possible file download (bitsadmin/certutil)</description>
    <mitre>
      <id>T1105</id>
    </mitre>
  </rule>
</group>
```

**Why I wrote it:** attackers use built-in Windows tools ("living off the land") to download payloads without dropping their own binaries. During testing:

- `certutil` was blocked and killed by Windows Defender's cloud protection before Sysmon logged it. I documented this as a defense-in-depth result.
- `bitsadmin /transfer` ran successfully but produced **no alert**. I confirmed this with an empty `grep bitsadmin` on the manager's `alerts.json`, and the agent was healthy and forwarding (clean `agent_control` and `ossec.log`). No default rule matched it, so this was a real detection gap.

**Test and result:** `bitsadmin /transfer myDownloadJob2 /download /priority normal https://raw.githubusercontent.com/HarshaPaii/soc-home-lab-wazuh/main/README.md C:\Users\Public\bits_download2.txt`. The rule fired at level 12 at 18:44:41 IST on 2026-10-09, with the full command line and parent `powershell.exe` captured. The test downloaded a file from my own public repo, so no malicious payload was involved.

Evidence: [alert in dashboard](../screenshots/02-detections/det-10-rule-100012-lolbin-bitsadmin.png)

### Known limits and tuning ideas

- **Noisy by design:** it matches the binary alone, so even `bitsadmin /list` would fire. The next version should also match the command line (`/transfer`, `-urlcache`, `-split`, `http`) to cut false positives.
- **Untested path:** the `certutil` branch was never validated end to end because Defender blocked it first. I treat it as unverified.
- BITS is also used by Windows Update, so a production version needs allow-listing by parent process.
