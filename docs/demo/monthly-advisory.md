# Monthly use-case advisory: October 2026

For October 2026, 118 priority gaps are ranked; the 10 highest are recommended below. The top recommendation is T1204.001.

> Ranked by code (threat-group usage, recent intel, data availability). Placeholder data: the ranking method is real, the inputs are not.

## Recommended next use cases (top 10 of 118 ranked gaps)

| # | Technique | Name | Score | Why | Likely log source |
| --- | --- | --- | --- | --- | --- |
| 1 | T1204.001 | User Execution: Malicious Link | 80 | used by OilRig, MuddyWater, APT33, APT39 | endpoint_process |
| 2 | T1555 | Credentials from Password Stores | 80 | used by OilRig, MuddyWater, APT33, APT39 | endpoint_process |
| 3 | T1566.001 | Phishing: Spearphishing Attachment | 80 | used by OilRig, MuddyWater, APT33, APT39 | authentication |
| 4 | T1566.002 | Phishing: Spearphishing Link | 80 | used by OilRig, MuddyWater, APT33, APT39 | authentication |
| 5 | T1588.002 | Obtain Capabilities: Tool | 80 | used by OilRig, MuddyWater, APT33, APT39 | endpoint_process |
| 6 | T1003.004 | OS Credential Dumping: LSA Secrets | 80 | used by OilRig, MuddyWater, APT33 | endpoint_process |
| 7 | T1003.005 | OS Credential Dumping: Cached Domain Credentials | 80 | used by OilRig, MuddyWater, APT33 | endpoint_process |
| 8 | T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | 80 | used by OilRig, APT33, APT39 | endpoint_process |
| 9 | T1036.005 | Masquerading: Match Legitimate Resource Name or Location | 80 | used by OilRig, MuddyWater, APT39 | endpoint_process |
| 10 | T1113 | Screen Capture | 80 | used by OilRig, MuddyWater, APT39 | endpoint_process |

## Test an existing use case instead of writing a new one

- T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder: UC-010 exists but has not passed validation

## Not recommended (rejected by an engineer before)

- T1105 Ingress Tool Transfer: Already alerted by the EDR; a SIEM use case would duplicate it (week-1)

## Onboard a log source first

- T1505.003 Server Software Component: Web Shell (used by OilRig, APT39)

To start one, ask the chat: "build a use case for <technique>".
