# Leverage your detection: prototype design

Status: design stage · October 2026

## Why a prototype first

The prototype tests whether the idea works on public and synthetic data, before any client or money is involved. If it passes its exit criteria, the next step is an MVP with pilot SOCs; if not, the scope is narrowed or the idea stopped after weeks, not months.

| Stage | Question it answers | Who uses it |
| --- | --- | --- |
| Prototype | Does the full loop work end to end? | The author, on public and synthetic data |
| MVP | Will a real SOC use it and pay? | 1-3 pilot SOCs or MSSPs |
| Product | Can it scale and sell repeatedly? | Many clients |

## Problem and value

SOCs don't know which ATT&CK techniques they can actually detect, and writing and testing each rule by hand takes days. New threat intel arrives faster than engineers can turn it into detections.

The platform closes that loop: it finds the gap, drafts the use case with the reason it is needed, tests it, and hands it to an engineer to approve. The engineer stays in control; the AI does the research and the first draft.

**Who it is for**

- MSSPs running many client SOCs (one engine, many tenants)
- Mid-size in-house SOCs without a dedicated detection engineering team
- Regulated Gulf organisations (banks, government, critical infrastructure) that need data kept on-prem

## Platform nodes

| Node | Job | Triggered by | Output to the engineer |
| --- | --- | --- | --- |
| Coverage (DeTT&CT) | Scores ATT&CK coverage from rules and data sources; finds gaps | Schedule, chat, merged PR | Gap list by priority, Navigator layers |
| Threat intel | Tracks new TTPs and exposure, scores relevance | New intel item | Alert + coverage check |
| Use-case builder | Drafts use cases in Sigma, with justification | Gap, intel, chat | Pull request with a tested draft |
| Noise tuning | Finds the likely benign pattern behind noisy rules, proposes a narrow exclusion | Alert-volume threshold, chat | Pull request with alerts before vs after |
| Rule health | Finds broken rules: syntax errors, missing fields or log sources, rules that never fire | Schedule | Error report + pull request with the fix |
| Validation | Runs the tests: lint, conversion, replay | Every pull request (CI) | Pass / fail on the PR |
| Posture | Rolls coverage, health and noise into one maturity score and trend | Weekly, monthly | Weekly report, monthly advisory |

**Code vs LLM.** In every node, code does anything that must be exact or provable (counts, scores, tests); the LLM does reading, reasoning and writing.

### Coverage node

- Uses DeTT&CT. Its inputs are generated from the repo instead of maintained by hand: data sources from the log types actually present, detections from each rule's ATT&CK tags.
- Detection score comes from evidence: rule exists but untested (low), passes replay tests in CI (higher), healthy and low noise (highest).
- Outputs ATT&CK Navigator layers (visibility, detection, threat-group overlay) and re-scores after every merge.
- Separates "no rule" from "no data", so it can recommend onboarding a log source instead of writing a rule.

### Threat intel node

Two kinds of intel, two kinds of output:

| Intel | Sources | Output |
| --- | --- | --- |
| TTPs: how attackers act | MITRE ATT&CK (STIX), MISP feeds, public advisories | Coverage check; behavioural use cases for gaps |
| Exposure: what attackers have on you | Ransomware leak-site trackers, leaked-account records, lookalike domains, access-broker listings | Watchlists and targeted use cases (e.g. unusual sign-ins for exposed accounts) |

- Relevance score against an organisation profile: sector, region, technology stack, available log sources. Only high scores notify.
- Exposure handling: never store leaked passwords (account, source and date only); use trackers and monitoring services, not direct access to criminal forums; watchlists expire (e.g. after 90 days or a password reset).

### Noise tuning node

The node does not decide that something is a false positive. It finds alerts that look like false positives, explains why, and proposes a narrow fix. Evidence:

1. Analyst verdicts from the SIEM or ticketing tool (strongest signal)
2. Stable, repetitive alert clusters (same account, host, process, time pattern, never linked to an incident)
3. Environment context: service-account lists, admin hosts, approved software, maintenance windows
4. Safety checks: the exclusion must be narrow, replay tests must still pass, alerts before vs after are shown, an engineer approves

## How the nodes connect

Nodes never call each other directly. Each node emits events and an orchestrator routes them:

1. Threat intel emits `new_ttp` (relevance high)
2. The orchestrator asks Coverage; Coverage replies `gap` (data available)
3. The orchestrator sends the gap to the builder, which opens a pull request
4. CI validation runs; the engineer is notified
5. The engineer merges, which emits `rule_merged`
6. Coverage and Posture re-score

Rule health (`broken_rule`) and noise tuning (`noisy_rule`) plug in the same way. Chat requests become events too.

Prototype implementation: a plain Python orchestrator with an event table in SQLite. It can be swapped for Redis or Kafka later.

## Detection-as-Code integration

Git is the single source of truth: no node edits the SIEM directly.

1. **Repository:** every use case is a file (Sigma YAML + metadata: ATT&CK mapping, owner, justification, test case, FP notes)
2. **Branch and pull request:** a node that builds, tunes or fixes a rule opens a PR with the change and its reason
3. **CI checks:** Sigma lint, conversion to each SIEM, replay tests
4. **Engineer review:** approve and merge, request changes, or close with a reason (logged as feedback; the reason is a required field)
5. **CD deploy:** on merge, the pipeline converts with pySigma and pushes to the SIEM through its API
6. **Close the loop:** coverage and posture re-score from the repo

If a client already runs Detection-as-Code, the platform plugs into their existing repo and pipeline (GitHub, GitLab or Azure DevOps).

## Use-case template

| Field | What it holds |
| --- | --- |
| Name and ID | Short descriptive name, internal ID |
| ATT&CK mapping | Tactic, technique, sub-technique |
| Trigger and justification | Which gap or intel item started it, and why this organisation needs it |
| Priority | High / medium / low, with the reason |
| Required log sources | Sources, and whether the organisation has them |
| Detection logic | Sigma rule + converted query for the target SIEM |
| Test results | Lint, replay results, estimated alerts per day, duplicate check |
| Expected false positives | Known benign causes and suggested exclusions |
| Triage guidance | What the analyst checks first when it fires |
| Review | Engineer decision, reason, date |

## Outputs

**Weekly posture report** (scheduled job): rebuilds DeTT&CT inputs from the repo, generates Navigator layers, compares with last week, collects the week's events, computes scores in code, and has the LLM write the narrative. Contents: coverage and change, heatmap and threat-group overlay, top gaps ("needs a rule" or "needs a log source"), new relevant TTPs, engineering activity, health and noise, next actions.

**Monthly use-case advisory:** code ranks open gaps by threat relevance, threat-group usage, data availability and effort; the LLM reads the top candidates plus history from memory and writes the recommendations. One click can ask the builder to open the PRs.

**On demand:** chatbot answers and pull requests.

## Memory

Each week's results and every engineer decision with its reason go into the RAG memory. The platform matures, not the model: drafts approach the team's standards and rejected ideas stop returning. Conditions: reasons are required on rejections, superseded entries are marked, and tests remain the gatekeeper. Maturity is measured by approval rate, edits per merged PR, false-positive rate of new rules and coverage of priority techniques. Months of decisions later become a fine-tuning dataset (MVP or later).

## Tech stack (candidates)

| Layer | Choice | Why |
| --- | --- | --- |
| LLM | Open-weight model (Llama, Qwen, Mistral) served with Ollama | Runs locally |
| Memory | Vector or TF-IDF store | Rules, ATT&CK, intel, schemas, decisions |
| Orchestration | Plain Python + SQLite event bus | Transparent, testable, no lock-in |
| Rule format | Sigma + pySigma backends | One rule, many SIEM query languages |
| Coverage | DeTT&CT + ATT&CK Navigator | Data-source and detection scoring, heatmaps |
| Threat intel | MITRE ATT&CK, MISP, advisories, leak-site trackers | Free, standard formats |
| Code and rules | Git + CI (GitHub Actions or GitLab CI) | Detection-as-Code |

## Market positioning

The problem is proven and the category is crowded (CardinalOps, Anvilogic, SOC Prime, Prophet AI, Intezer, AiStrike, Cymulate). The angle: sovereign, MSSP-ready AI detection engineering for Gulf SOCs: on-prem open-source model, any SIEM via Sigma, regional threat intel, priced for mid-size teams. Go-to-market: start as a service ("coverage assessment + gap closure in 30 days") powered by the tool, then sell the tool as a product once the flow is repeatable.

## Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Client onboarding takes weeks (field mappings, parsers, missing logs) | Sell onboarding as a fixed 2-4 week service |
| LLM drafts wrong or noisy rules | Mandatory tests + human approval; never auto-deploy |
| Threat intel floods engineers | Relevance scoring; only high scores notify |
| Prompt injection via intel reports | Treat intel as untrusted data; review every output |
| Well-funded competitors | Focus on Gulf, on-prem, MSSPs, mid-size price point |
| Employer IP and conflict of interest | Check the employment contract; own time and hardware; no employer or client data |
| Client data handling | On-prem deployment; data never leaves the client |

## Open questions

- Which open-source model, and what hardware for local testing?
- Which threat intel feeds are free and relevant to the Gulf?
- Solo build, or a co-founder for engineering or sales?
- Which SOCs or MSSPs could review a prototype demo?
- Pricing model: per tenant, per data source, or detection packs?
