# Version, support, and vulnerability triage

Use this reference whenever the task correlates a Tomcat version with CVEs or support status.

## Dynamic source of truth

Version and support information changes. At analysis time, consult:

- support and releases: `https://tomcat.apache.org/whichversion.html`;
- security index: `https://tomcat.apache.org/security.html`;
- branches: `https://tomcat.apache.org/security-11`, `security-10`, `security-9`, `security-8`, and `security-7` as applicable;
- documentation for the exact observed branch, not only `latest`.

Record the URL, access time, and branch. Do not copy a static “latest patch” value from this file.

## Triage process

1. Determine the family and most precise version, including the evidence source.
2. Identify the package, vendor, and build; look for backports and distribution versions.
3. Determine whether the branch is supported on the engagement date.
4. On the official branch page, capture the affected range, fixed version, project severity, and every prerequisite.
5. Build a matrix for each CVE: `condition | CONFIRMED | ABSENT | UNVERIFIED | evidence`.
6. Classify the case as `POTENTIAL` while any indispensable condition remains unverified.
7. Never run a PoC automatically. Propose the minimum test and its risk for separate approval.

A version below the upstream fix confirms, at most, relevance to the upstream affected range. It does not confirm vulnerable configuration, reachability, an auxiliary primitive, or absence of a backport.

## Mandatory Ghostcat entry

For every precisely identified Tomcat version, evaluate CVE-2020-1938
explicitly and retain the result in the final report. This applies even when a
branch is end-of-life, outside the advisory's explicit range, apparently fixed,
or relegated to the excluded/unresolved appendix. Record:

- the observed version and evidence quality;
- the official affected/fixed range when one exists;
- whether AJP enablement, reachability, bind controls, shared-secret controls,
  virtual host/context, and the selected resource are confirmed or unverified;
- a `POTENTIAL` or `UNVERIFIED` applicability classification unless authorized
  behavior confirms every relevant prerequisite;
- public-PoC status using the same source and timestamp rules as the ranked
  table.

This mandatory check is passive version and public-source research. It does not
authorize connecting to AJP, reading a file, evaluating JSP, or executing a
PoC. Any active AJP action needs its own exact endpoint, file, request budget,
risk disclosure, and operator approval.

## Required CVSS > 6.0 ranked output

After a Tomcat version is identified, perform current passive research and produce a ranked table. This is Internet research against public sources, not permission to send any additional request to the assessed target.

Run this research in a dedicated subagent. Once the operator has opted into the skill, public-source, read-only lookups are standing-authorized and must not trigger a separate approval request for each query. The subagent must use only public sources, must not contact the assessed target, and must not download or execute PoCs. Prefer read-only web research tools and batch related lookups instead of shell networking that would create repeated permission prompts. Return evidence and the consolidated table to the primary agent without streaming partial findings to the operator; only the final response and engagement report should expose the results. If the runtime cannot delegate to a subagent, disclose that limitation rather than claiming this workflow was followed.

Use this source order:

1. the official Apache Tomcat security page for the matching branch, to establish affected and fixed upstream ranges and prerequisites;
2. the authoritative CVE record and NVD entry for CVSS metrics and references;
3. CISA KEV, when applicable, for known-exploitation status;
4. the original researcher publication or source repository when assessing whether a public PoC exists.

Apply these rules:

- The numeric threshold is strict: retain only a published CVSS base score greater than `6.0`.
- Record the CVSS specification (`4.0`, `3.1`, or `3.0`), vector, score, authority, source URL, and research timestamp with timezone.
- Prefer the newest authoritative CVSS metric. If Apache/CNA and NVD scores differ, show both, state which one controls sorting, and do not conceal the disagreement.
- Confirm that the identified upstream version falls in the official affected range. A vendor package may contain a backport, so package/build provenance remains a limitation.
- Sort by the selected numeric score descending, then by CVE ID as a deterministic tie-breaker.
- Keep configuration-dependent cases `POTENTIAL` until every indispensable prerequisite is evidenced. Version applicability is not vulnerability confirmation.
- Put entries with missing scores, ambiguous branches, or unresolved applicability in an excluded/unresolved appendix.
- Never silently drop CVE-2020-1938; if it does not fit the main table, place
  its dedicated assessment in that excluded/unresolved appendix.
- If no entry survives the filter, state that result and list the sources searched.

Use at least these columns:

| Rank | CVE | CVSS score, version, vector, authority | Apache severity | Affected/fixed range | Applicability | Brief description and prerequisites | Public PoC status | Sources |
|---|---|---|---|---|---|---|---|---|

For public PoC research:

- `CONFIRMED PUBLIC POC` means a publicly accessible original repository or researcher publication contains code or reproducible exploitation steps tied directly to that CVE.
- `CLAIMED/UNVERIFIED` means a secondary reference claims a PoC exists but the original artifact or applicability was not verified.
- `NO PUBLIC POC FOUND AS OF <TIMESTAMP>` is a time-bounded negative search result, never proof that no PoC exists.
- A Nuclei rule, Nessus check, banner matcher, or other detection-only template is not an exploitation PoC; label it separately.
- Link to the original artifact and record its commit/tag when practical. Do not download, clone, build, execute, adapt, or test it without separate approval. Target-side PoC execution is exploitation and always requires action-specific authorization.

## Illustrative historical matrices

These entries demonstrate the reasoning pattern; verify them again on the official branch page.

### CVE-2020-1938 / AJP

- Tomcat is within the branch's affected range;
- the AJP connector is enabled;
- AJP is reachable from an untrusted source;
- bind and shared-credential controls were evaluated;
- for file read, a resource inside the web application is reachable through the primitive;
- for RCE, attacker-controlled content exists inside the web application and can be processed as JSP.

An open port or an old version alone does not confirm exploitation. A file read would be a separately authorized exploitation step.

### CVE-2020-9484 / session persistence

Official guidance requires concurrent conditions including:

- control of file content and filename on the server;
- `PersistenceManager` with `FileStore`;
- an absent or permissive session-attribute class filter;
- knowledge of a relative path from the storage location;
- a compatible gadget on the classpath for code-execution impact.

Upload, `JSESSIONID`, or an affected version alone leaves the case `POTENTIAL`.

### PUT / DefaultServlet

For PUT-upload CVEs, confirm the exact branch range and that writes through DefaultServlet were enabled. Some cases also depend on the operating system and path parsing. `OPTIONS` or an `Allow` header does not prove a JSP can be written or executed. Do not send PUT during routine enumeration.

### CVE-2019-0232 / CGI on Windows

Confirm all of the following:

- Windows;
- CGI Servlet enabled;
- `enableCmdLineArguments` enabled;
- version in the official affected range;
- reachable CGI route.

CGI and the vulnerable option are disabled by default in relevant branches.

### CVE-2025-24813 / partial PUT

Separate the impacts and validate the official branch description. Conditions include writes enabled in DefaultServlet and partial PUT. Content exposure or modification requires a specific relationship between upload paths and known filenames. RCE adds file-backed session persistence and a usable deserialization library. Do not turn a version banner alone into a confirmed finding.

## Cases that are not Tomcat CVEs by themselves

- SnakeYAML or other application-library deserialization;
- unsafe upload implemented by the application;
- weak Manager credentials;
- unauthenticated JMX exposure;
- normalization differences between NGINX/httpd and Tomcat;
- credentials in a repository, backup, or configuration file.

These may be serious findings, but each needs its own taxonomy and evidence.

## Conclusion language

Prefer:

> `POTENTIAL`: the banner indicates Tomcat X.Y.Z, which falls within the upstream affected range. Required configuration A and primitive B were not verified; no PoC was executed.

Use `CONFIRMED` for the vulnerability only when every relevant prerequisite and the vulnerable behavior have authorized evidence. If confirmation would require a dangerous effect, preserve safety and report the limitation.
