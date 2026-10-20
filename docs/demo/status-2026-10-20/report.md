# Status report: 2026-10-20 23:49

Example Gulf Bank (fictional) · threat groups: OilRig, MuddyWater, APT33, APT39 · ATT&CK v20.0 · LLM: mock

## Summary

As of 2026-10-20, priority coverage is 9.7% (13 of 134). 0 proposals are waiting for review and 12 decision(s) were made since the last report. The top recommended gap is T1204.001.

## Coverage of priority techniques

- Covered: 13 of 134 (9.7% (first status report))
- Need a log source first: 1

## Waiting for your review

- Nothing waiting.

## Decisions since the last report

- PR-001: merged by review_policy (approved)
- PR-002: merged by review_policy (approved)
- PR-003: merged by review_policy (approved)
- PR-004: merged by review_policy (approved)
- PR-005: merged by review_policy (approved)
- PR-007: merged by review_policy (approved)
- PR-008: merged by review_policy (approved)
- PR-009: rejected by review_policy (Already alerted by the EDR; a SIEM use case would duplicate it)
- PR-011: merged by review_policy (approved)
- PR-012: merged by review_policy (approved)
- PR-013: merged by review_policy (approved)
- PR-014: merged by review_policy (approved)

## Recommended next use cases

| Technique | Name | Score | Used by |
| --- | --- | --- | --- |
| T1204.001 | User Execution: Malicious Link | 80 | OilRig, MuddyWater, APT33, APT39 |
| T1555 | Credentials from Password Stores | 80 | OilRig, MuddyWater, APT33, APT39 |
| T1566.001 | Phishing: Spearphishing Attachment | 80 | OilRig, MuddyWater, APT33, APT39 |
| T1566.002 | Phishing: Spearphishing Link | 80 | OilRig, MuddyWater, APT33, APT39 |
| T1588.002 | Obtain Capabilities: Tool | 80 | OilRig, MuddyWater, APT33, APT39 |

Test before writing new ones: UC-010 (T1547.001)

Onboard a log source first: T1505.003 Server Software Component: Web Shell

> Prototype on placeholder data: the method is real, the inputs are not.
