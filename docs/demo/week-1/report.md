# Weekly posture report: week-1

Organisation profile: Example Gulf Bank (fictional) · threat groups: OilRig (G0049), MuddyWater (G0069), APT33 (G0064), APT39 (G0087) · ATT&CK v20.0 · LLM: mock

> Prototype run on placeholder use cases and placeholder intel. It proves the agents work together; it does not measure real detection quality.

## Summary

Coverage of priority techniques moved from 6.0% to 8.2%. 7 proposals merged, 1 rejected, 122 priority gaps still open.

## Coverage of priority techniques

| | Start of week | End of week |
| --- | --- | --- |
| Covered | 8 of 134 (6.0%) | 11 of 134 (8.2%) |
| No log source | 1 | 1 |

## Agent activity

| Event | Count |
| --- | --- |
| `new_ttp` | 6 |
| `intel_ignored` | 1 |
| `exposure` | 1 |
| `gap` | 4 |
| `covered` | 1 |
| `needs_log_source` | 1 |
| `broken_rule` | 3 |
| `noisy_rule` | 2 |
| `proposal_opened` | 10 |
| `validation_passed` | 8 |
| `validation_failed` | 2 |
| `review_requested` | 0 |
| `rule_merged` | 7 |
| `proposal_rejected` | 1 |
| `skipped_previously_rejected` | 0 |

## Proposals (pull requests)

| ID | Kind | Use case | Status | Reason |
| --- | --- | --- | --- | --- |
| PR-001 | watchlist | WL-user01 | merged | Account seen in leak-site tracker (sample) on 2026-10-14; watch its sign-ins until reset. |
| PR-002 | fix | UC-003 | merged | needs 'email_gateway', which is not collected. Proposed: pause until the log source is onboarded |
| PR-003 | fix | UC-005 | merged | T1562.001 not in ATT&CK v20.0. Proposed: remap T1562.001 -> T1685 |
| PR-004 | fix | UC-006 | merged | no owner set. Proposed: assign owner detection-engineering |
| PR-005 | tuning | UC-001 | merged | 412 alerts in 7 days, 94% closed as false positive; 91% come from one pattern (account=svc_backup, host=SRV-BKP01). Expected after exclusion: about 37 alerts. |
| PR-006 | tuning | UC-004 | failed | Failed checks: exclusion_is_narrow |
| PR-007 | new_use_case | UC-T1003.001 | merged | T1003.001 (OS Credential Dumping: LSASS Memory) has no validated use case. Trigger: intel intel-001: Placeholder advisory: activity against GCC banks. Used by: OilRig, MuddyWater, APT33, APT39. Priority high. |
| PR-008 | new_use_case | UC-T1071.001 | merged | T1071.001 (Application Layer Protocol: Web Protocols) has no validated use case. Trigger: intel intel-001: Placeholder advisory: activity against GCC banks. Used by: OilRig, MuddyWater, APT33, APT39. Priority high. |
| PR-009 | new_use_case | UC-T1105 | rejected | Rejected: Already alerted by the EDR; a SIEM use case would duplicate it |
| PR-010 | new_use_case | UC-T1547.001 | failed | Failed checks: no_duplicate |

## Needs a log source, not a rule

- T1505.003 Server Software Component: Web Shell

## Top open gaps (next actions)

| Technique | Name | Used by |
| --- | --- | --- |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | OilRig, MuddyWater, APT33, APT39 |
| T1105 | Ingress Tool Transfer | OilRig, MuddyWater, APT33, APT39 |
| T1204.001 | User Execution: Malicious Link | OilRig, MuddyWater, APT33, APT39 |
| T1204.002 | User Execution: Malicious File | OilRig, MuddyWater, APT33, APT39 |
| T1555 | Credentials from Password Stores | OilRig, MuddyWater, APT33, APT39 |
| T1566.001 | Phishing: Spearphishing Attachment | OilRig, MuddyWater, APT33, APT39 |
| T1566.002 | Phishing: Spearphishing Link | OilRig, MuddyWater, APT33, APT39 |
| T1588.002 | Obtain Capabilities: Tool | OilRig, MuddyWater, APT33, APT39 |
| T1003.004 | OS Credential Dumping: LSA Secrets | OilRig, MuddyWater, APT33 |
| T1003.005 | OS Credential Dumping: Cached Domain Credentials | OilRig, MuddyWater, APT33 |

Navigator layer: `navigator-layer.json` (load it at https://mitre-attack.github.io/attack-navigator/).
