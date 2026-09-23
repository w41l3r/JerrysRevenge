---
name: tomcat-enumeration
description: Plan, perform, and document authorized Apache Tomcat enumeration and adjacent surfaces such as Manager, Host Manager, AJP, JMX/RMI, and proxies. Use for penetration tests and exposure validation; begin with offline artifacts and require specific approval before any target traffic. Do not use for a generic Java application without evidence of Tomcat.
---

# Tomcat Enumeration

Produce low-noise, evidence-based, reproducible enumeration. Distinguish the Tomcat container, deployed applications, proxy layer, and adjacent Java services.

## Authorization boundary

- Keep every host, IP address, virtual host, port, protocol, and credential within the explicitly supplied scope.
- Analyze existing output, configuration, code, responses, and captures first. Offline artifacts do not authorize additional target contact.
- Once the operator has opted into this skill and a Tomcat version has been identified, ordinary read-only CVE and public-PoC research against public Internet sources is standing-authorized. It is not target traffic: do not pause for per-query approval, and never send these research requests to the assessed target.
- Delegate that passive CVE research to a dedicated subagent. The subagent must not contact the assessed target or download, clone, build, adapt, or execute a PoC. Do not expose intermediate CVE findings to the operator; the primary agent reviews the evidence and presents only the consolidated results in the final response and engagement report. If the runtime has no subagent capability, disclose that limitation rather than silently claiming delegation.
- Prefer the runtime's read-only web research tools and batch related lookups. Avoid shell networking when it would create repeated permission prompts for ordinary public-source research.
- Before any potentially detectable active action, present the exact command, exact targets and ports, request count or ceiling, likely telemetry, and operational risk. Wait for explicit approval for that action.
- Approval does not carry over to retries, more paths, more credentials, another virtual host, another port, or a more invasive phase.
- Treat authentication, directory enumeration, NSE, AJP, RMI/JMX, and normalization tests as active even when a tool labels them `safe`.
- Do not perform brute force, password spraying, upload/PUT, deployment/undeployment/reload, MBean invocation, deserialization, callbacks, access-control bypass, AJP file reads, payload delivery, or exploitation without specific authorization. These actions are not part of default enumeration.
- When stealth and certainty conflict, preserve stealth and mark what remains unverified.

## Required start

1. Fix the scope, authorized network source, time window, noise budget, and already available artifacts. If missing information would materially change an active action, stop before sending traffic.
2. Read [references/reporting.md](references/reporting.md) and initialize the runbook with `scripts/init_engagement.py` when an engagement workspace is available.
3. Extract everything possible offline. Build an `evidence -> observation -> hypothesis -> minimum next test` matrix.
4. Propose only the smallest test that reduces the relevant uncertainty. Run only the approved batch, recording negative results and errors as well.
5. Reassess before each new phase. Stop when the authorized question is answered, the noise budget is exhausted, or the next step requires new authority.

## Reference routing

- For HTTP, fingerprinting, default applications, Manager/Host Manager, and proxy differences, read [references/http-and-management.md](references/http-and-management.md).
- For AJP, RMI, JMX, Jolokia, and Java application clues, read [references/connectors-and-java-management.md](references/connectors-and-java-management.md).
- To correlate versions, support status, and CVEs without false positives, read [references/version-and-prerequisites.md](references/version-and-prerequisites.md).
- To understand the origin and limitations of the heuristics, read [references/source-notes.md](references/source-notes.md). It is not required for routine enumeration.

## Technical workflow

### 1. Separate the layers

Model these components explicitly:

- external endpoint and TLS;
- proxy, WAF, or load balancer;
- Tomcat HTTP(S) connector;
- virtual host and context paths;
- Manager, Host Manager, docs, and examples;
- business applications and libraries;
- AJP;
- RMI registry, JMX endpoint, and any advertised secondary port;
- local access or configuration artifacts.

A common port is only a clue. Do not identify Tomcat solely from `8080`, AJP solely from `8009`, or RMI solely from `1099`.

### 2. Grade the evidence

Use `CONFIRMED`, `INFERRED`, `POTENTIAL`, or `UNVERIFIED` for every material conclusion.

- `CONFIRMED`: direct and unambiguous observation, such as a version-bearing banner or error, an authorized local file, an installed package, or a validated protocol. Record possible spoofing or backports where applicable.
- `INFERRED`: multiple consistent clues without direct proof.
- `POTENTIAL`: a version or configuration may satisfy part of a condition, but prerequisites remain unverified.
- `UNVERIFIED`: a hypothesis without an authorized test or sufficient evidence.

A product or version never confirms a vulnerability by itself. Distribution builds may contain backports, and banners may be changed.

### 3. Handle authentication and credentials

- Treat supplied credentials as non-administrative unless the operator states otherwise.
- Do not test a credential against another service based on a reuse hypothesis.
- Even one login is an active event that may cause lockout, alerts, or an audit trail; obtain specific approval.
- When a credential is found, stop exposing it in normal output, assign a stable ID, and store the complete value only in the mode-`0600` restricted inventory. Use only its ID in the sanitized report.

### 4. Deliver actionable results

Deliver:

- a surface and trust-boundary map;
- a complete timeline of `EXECUTED` and `EVALUATED — NOT EXECUTED` steps;
- preserved raw evidence and sanitized copies;
- classified findings with observations separated from interpretation;
- a prerequisite matrix for each relevant CVE or attack path;
- limitations, likely telemetry, and open questions;
- the next minimum test as a recommendation, without running it if new approval is required.

When a Tomcat version has been identified, have the dedicated research subagent produce the CVSS-greater-than-6.0 CVE table required by [references/version-and-prerequisites.md](references/version-and-prerequisites.md). Sort it from most to least critical and include a brief description and time-bounded public-PoC status for every retained CVE. Keep the research results internal until the primary agent delivers the consolidated final response and report.

Do not turn write-up material into captured output, and do not describe a proposed command as executed.
