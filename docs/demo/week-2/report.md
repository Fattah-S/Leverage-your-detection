# Weekly posture report: week-2

Organisation profile: Example Gulf Bank (fictional) · threat groups: OilRig (G0049), MuddyWater (G0069), APT33 (G0064), APT39 (G0087) · ATT&CK v20.0 · LLM: mock

> Prototype run on placeholder use cases and placeholder intel. It proves the agents work together; it does not measure real detection quality.

## Summary

Coverage of priority techniques moved from 8.2% to 9.7%. 4 proposals merged, 0 rejected, 120 priority gaps still open.

## Coverage of priority techniques

| | Start of week | End of week |
| --- | --- | --- |
| Covered | 11 of 134 (8.2%) | 13 of 134 (9.7%) |
| No log source | 1 | 1 |

## Agent activity

| Event | Count |
| --- | --- |
| `new_ttp` | 4 |
| `intel_ignored` | 0 |
| `exposure` | 1 |
| `gap` | 3 |
| `covered` | 1 |
| `needs_log_source` | 0 |
| `broken_rule` | 0 |
| `noisy_rule` | 1 |
| `proposal_opened` | 4 |
| `validation_passed` | 4 |
| `validation_failed` | 0 |
| `review_requested` | 0 |
| `rule_merged` | 4 |
| `proposal_rejected` | 0 |
| `skipped_previously_rejected` | 1 |

## Proposals (pull requests)

| ID | Kind | Use case | Status | Reason |
| --- | --- | --- | --- | --- |
| PR-011 | watchlist | WL-user02 | merged | Account seen in leak-site tracker (sample) on 2026-10-19; watch its sign-ins until reset. |
| PR-012 | tuning | UC-004 | merged | 78 alerts in 7 days, 84% closed as false positive; 80% come from one pattern (host=SRV-MON01, process=monitor-agent.exe). Expected after exclusion: about 16 alerts. |
| PR-013 | new_use_case | UC-T1204.002 | merged | T1204.002 (User Execution: Malicious File) has no validated use case. Trigger: intel intel-004: Placeholder advisory: new activity against GCC financial sector. Used by: OilRig, MuddyWater, APT33, APT39. Priority high. |
| PR-014 | new_use_case | UC-T1059.005 | merged | T1059.005 (Command and Scripting Interpreter: Visual Basic) has no validated use case. Trigger: intel intel-004: Placeholder advisory: new activity against GCC financial sector. Used by: OilRig, MuddyWater, APT33, APT39. Priority high. |

## Not proposed again (rejected before)

- `new:T1105`: rejected in week-1 (Already alerted by the EDR; a SIEM use case would duplicate it)

## Top open gaps (next actions)

| Technique | Name | Used by |
| --- | --- | --- |
| T1105 | Ingress Tool Transfer | OilRig, MuddyWater, APT33, APT39 |
| T1204.001 | User Execution: Malicious Link | OilRig, MuddyWater, APT33, APT39 |
| T1555 | Credentials from Password Stores | OilRig, MuddyWater, APT33, APT39 |
| T1566.001 | Phishing: Spearphishing Attachment | OilRig, MuddyWater, APT33, APT39 |
| T1566.002 | Phishing: Spearphishing Link | OilRig, MuddyWater, APT33, APT39 |
| T1588.002 | Obtain Capabilities: Tool | OilRig, MuddyWater, APT33, APT39 |
| T1003.004 | OS Credential Dumping: LSA Secrets | OilRig, MuddyWater, APT33 |
| T1003.005 | OS Credential Dumping: Cached Domain Credentials | OilRig, MuddyWater, APT33 |
| T1027.013 | Obfuscated Files or Information: Encrypted/Encoded File | OilRig, APT33, APT39 |
| T1036.005 | Masquerading: Match Legitimate Resource Name or Location | OilRig, MuddyWater, APT39 |

Navigator layer: `navigator-layer.json` (load it at https://mitre-attack.github.io/attack-navigator/).
