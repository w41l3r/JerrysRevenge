# Instructions for AI assistants

These instructions apply to Codex, Claude Code, and any other AI agent working in this repository.

## Opt-in Tomcat enumeration skill

The local `tomcat-enumeration` skill is available at:

```text
.agents/skills/tomcat-enumeration/SKILL.md
```

When a request involves Apache Tomcat security enumeration, fingerprinting, Manager or Host Manager, authentication, proxies, AJP, JMX/RMI, CVEs, or exposure validation:

1. Tell the operator that `tomcat-enumeration` is available and summarize in one sentence what it adds.
2. Ask exactly: **"Would you like me to load and use the `tomcat-enumeration` skill for this task?"**
3. Wait for an affirmative response before applying its workflow, reading its conditional references, or running its scripts.
4. If the operator declines, do not invoke the skill or silently replace it with equivalent automation.
5. An explicit invocation by name (`$tomcat-enumeration`, `/tomcat-enumeration`, or an unequivocal request to use it) already counts as consent to load the skill.

After consent, Claude Code should read the `SKILL.md` at the path above. Codex should use the local skill with the same name.

## Scope of consent

Consent to use the skill authorizes only loading its instructions and preparing analysis or a plan. It does not authorize network traffic, authentication, credential validation, brute force, path-bypass checks, uploads, PUT requests, deployment, undeployment, payload execution, callbacks, data access, or any target-side change.

Before every potentially detectable active action:

- present the exact command or operation;
- fix the exact hostname or IP, port, protocol, paths, and credential identifiers;
- state the maximum request count, concurrency, delay, and retry behavior;
- describe likely telemetry, operational risks, effects, and rollback where applicable;
- obtain explicit, action-specific operator approval for that batch.

Approval does not carry over to retries, new paths, other ports, other services, additional credentials, or a more invasive phase.

## Evidence and credential handling

- Start with local code and artifacts; offline analysis never authorizes target contact.
- Maintain a chronological runbook containing exact commands, timestamps with timezone, real captured output, limitations, execution status, dependencies, and confidence classifications.
- Never invent output for an action that was not executed.
- Use stable credential identifiers in chat and sanitized reports.
- Store complete credential values only in the engagement's restricted inventory with mode `0600`.
- Do not validate possible credential reuse against another service without separate explicit authorization.
- Preserve historical evidence verbatim. Keep engagement-specific reports and restricted inventories outside normal public exports and version control.

## CVE research after version identification

After a Tomcat version is identified and the operator has consented to use the `tomcat-enumeration` skill, perform current passive CVE research without sending additional traffic to the target:

- Delegate the research to a dedicated subagent. Public-source, read-only lookups are standing-authorized after skill consent and do not require approval per query. Prefer read-only web research tools and batch lookups; never contact the assessed target or download or execute a PoC.
- Do not stream partial CVE findings to the operator. The primary agent must review the subagent's evidence and present only the consolidated results in the final response and engagement report. If subagents are unavailable, disclose that limitation rather than claiming delegation.

1. Record whether the version evidence is `CONFIRMED` or `INFERRED` and its exact source.
2. Consult the official Apache Tomcat security page for the matching branch, the authoritative CVE record, and an authoritative CVSS source. Record every source URL and the research timestamp with timezone.
3. Retain only CVEs whose affected range includes the identified upstream version and whose published CVSS base score is strictly greater than `6.0`. Never treat version range alone as proof that configuration-dependent prerequisites are present.
4. State the CVSS specification (`4.0`, `3.1`, or `3.0`), vector, score, and scoring authority. Prefer the newest authoritative metric; if authorities disagree, display the differing scores and explain which value controls sorting.
5. Sort the retained CVEs from highest to lowest selected CVSS base score. Use CVE ID as the deterministic tie-breaker.
6. For each CVE, provide a short description, affected and fixed ranges, relevant prerequisites, applicability classification (`CONFIRMED`, `INFERRED`, `POTENTIAL`, or `UNVERIFIED`), and source links.
7. Search for a public PoC and classify it as `CONFIRMED PUBLIC POC`, `CLAIMED/UNVERIFIED`, or `NO PUBLIC POC FOUND AS OF <TIMESTAMP>`. Link the original repository or researcher publication and distinguish exploit code from a detection-only template or descriptive advisory.
8. Do not download, build, run, or adapt a PoC as part of this research. Any such action requires its own review and explicit operator approval; target execution requires separate exploitation authorization.

If no CVE meets the threshold, say so explicitly and list the consulted sources. Put CVEs with no usable CVSS score or uncertain version applicability in a separate excluded/unresolved section rather than silently dropping them.

Always include a dedicated CVE-2020-1938/Ghostcat assessment for every precise
Tomcat version. If an EOL or ambiguous branch does not fit the main ranked
table, retain it in the excluded/unresolved section with its prerequisites and
public-PoC status. This is passive research only and never authorizes an AJP
connection or file read.

## Project safety boundary

Jerry's Revenge may implement and validate the reversible static-canary
deployment workflow and the bounded Ghostcat file-read workflow documented in
`README.md`. Ghostcat is limited to one operator-selected,
web-application-relative resource per target, an explicit `--ghostcat
--execute` gate, no retry, a 1 MiB response cap, and mode-`0600` restricted raw
evidence. It must not be chained automatically from version detection.

Do not add command execution, Ghostcat JSP evaluation, server-side payloads,
web shells, callbacks, persistence, bulk file collection, arbitrary executable
WAR handling, or a bypass-assisted deployment path without a new explicit
design decision from the project owner and an appropriate safety review.
