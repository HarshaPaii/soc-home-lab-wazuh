# Resume Bullets (X-Y-Z)

- Detected 7 of 7 simulated MITRE ATT&CK techniques (T1059.001, T1053.005, T1547.001, T1098, T1110, T1105, discovery) as measured by level 3-12 Wazuh alerts per technique, by building a Wazuh SIEM with Sysmon endpoint telemetry on a Windows 11 VM lab.
- Closed a confirmed detection gap where `bitsadmin` file downloads raised no alert, as measured by custom rules 100010 and 100012 firing at level 12 on re-test, by authoring PCRE2-based Wazuh rules mapped to T1053.005 and T1105 and validating them with `wazuh-analysisd -t`.
- Completed a 3-stage investigation (encoded PowerShell, discovery, scheduled-task persistence) as measured by a full alert-to-response report with timeline, IOCs and a correlated logon session, by triaging Wazuh alerts, decoding the base64 payload, and ruling out a recurring level-12 false positive (rule 92058).
