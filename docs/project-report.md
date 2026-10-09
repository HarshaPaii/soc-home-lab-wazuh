# SOC Home Lab: Project Report

**Author:** Harsha Pai · **Repo:** github.com/HarshaPaii/soc-home-lab-wazuh

## Problem
Entry-level SOC roles expect hands-on experience with a SIEM, endpoint telemetry and detection work, but enterprise tools cost money. I wanted to show I can build a monitoring pipeline, detect real attacker techniques, write my own detections and investigate alerts, on a laptop at zero cost.

## Environment
- **Host:** Intel i3-1115G4, 8 GB RAM, VirtualBox 7.2.18
- **Wazuh-SIEM:** Ubuntu Server 24.04 LTS running Wazuh manager, indexer and dashboard
- **win11-endpoint:** Windows 11 with Sysmon (SwiftOnSecurity config) and Wazuh agent 4.9.2
- **Kali 2026.2:** recon (nmap) and an attempted Hydra RDP brute force
- All VMs on one bridged /24 network; dashboard timestamps set to IST

## Steps Taken
1. Built the SIEM VM, installed Wazuh, and connected the Windows agent.
2. Installed Sysmon and wired its event channel into the agent (`ossec.conf`).
3. Simulated seven techniques: encoded PowerShell, discovery commands, registry Run key and scheduled-task persistence, local admin creation, failed-logon burst, and LOLBin download.
4. Confirmed each detection in the Threat Hunting dashboard and mapped it to MITRE ATT&CK.
5. Wrote two custom rules (100010, 100012) for gaps in default coverage.
6. Investigated a PowerShell → Discovery → Persistence chain and triaged a recurring false positive (rule 92058).

## Findings
- **7 of 7** simulated techniques detected, at levels 3 to 12 (see the coverage table in the README).
- **Detection gap found:** `bitsadmin` downloads raised no alert until I wrote rule 100012.
- **Defense in depth:** Windows Defender blocked `certutil` before Sysmon logged it.
- **False positive:** rule 92058 (level 12) recurred four times from benign Windows maintenance.
- Hashes of the abused binaries are genuine Microsoft files, so behaviour-based rules were needed, not hash reputation.

## Lessons Learned
- **Debug the pipeline before the rule.** Custom rule 100010 looked broken for about 3 hours. The cause was a corrupted agent database in the indexer pipeline. Checking the manager's `alerts.json` first would have shown this in minutes.
- **Default rule sets have gaps.** LOLBin downloads via `bitsadmin` slipped through, and my fix matches the binary only; matching on command-line arguments is the next improvement.
- **Resource limits shape the workflow.** With 8 GB RAM I could not run both VMs together, so I ran the endpoint and the SIEM separately; the agent queues events locally and sends them on reconnect, so no data was lost.
- **Plan disk space.** The lab grew to about 95 GB and filled the drive mid-project (`VERR_DISK_FULL`). I merged snapshots, trimmed and compacted the virtual disks, and disabled the unused vulnerability-detection feed.
- **Be honest about limits.** The Hydra RDP attempt failed, the failed-logon test was generated locally, and the `certutil` rule branch is unverified.

## Evidence
Screenshots are in `/screenshots`; the custom rules in `/detection-rules`; the investigation in `/investigation-reports`.
