# Runbooks, evidence, and credentials

Read this reference whenever the skill is used.

## Initialize the workspace

Use an absolute path inside the engagement workspace:

```bash
python3 <SKILL_DIR>/scripts/init_engagement.py \
  /absolute/path/to/tomcat-run \
  --scope 'app.example:443; 10.0.0.8:8080; TCP/HTTP only' \
  --timezone 'America/Sao_Paulo' \
  --operator '<OPERATOR>'
```

The script never replaces existing files. It creates directories for raw evidence, sanitized evidence, notes, and restricted material. Confirm permissions before storing a credential value.

## Chronological record

Use a monotonic step identifier (`T-001`, `T-002`, and so on) and preserve actual execution order. Every step must contain:

```markdown
### T-001 — <short title>

- Status: EXECUTED | EVALUATED — NOT EXECUTED
- Resulting classification: CONFIRMED | INFERRED | POTENTIAL | UNVERIFIED
- Dependencies: <previous IDs or none>
- Objective: <question answered>
- Timestamp: <ISO-8601 with timezone>
- Working directory: <absolute path or N/A>
- Prerequisites: <scope, approval, credential ID, network source>
- Tool/version: <name and version; "not exposed" if unavailable>
- Exact command/operation: <exact structure with credential values replaced by IDs/placeholders>
- Exit code/tool result: <actual value>
- Evidence: <files and SHA-256 hashes>
- Captured output: <literal sanitized excerpt or "none; not executed">
- Direct observation: <only what the evidence shows>
- Interpretation: <conclusion and confidence>
- Limitations/assumptions: <include negative and ambiguous results>
- Telemetry/risk: <logs, IDS/WAF, authentication, load, artifacts>
```

For `EVALUATED — NOT EXECUTED` steps, never invent an exit code or output. Include the proposed command, why it was not run, and what remains unverified.

## Command capture

- Record the command before execution, then add the real exit code and hashes.
- Record the working directory; a relative path without its working directory is not reproducible.
- Record `curl --version`, `nmap --version`, Java, and JAR version/hash when material.
- Avoid putting a password, token, cookie, or key in process arguments, shell history, filenames, or URLs.
- Do not use `tee` on output that may contain credential material until the restricted destination is fixed.
- Preserve errors, timeouts, `401`, `403`, empty responses, and nonzero exit codes.

## Evidence

- Save raw bytes under `evidence/raw/` when doing so does not expose credential material outside the appropriate area.
- If a response contains credential material, place it under `restricted/evidence/`, apply mode `0600`, and create a sanitized copy under `evidence/sanitized/`.
- Use stable names such as `T-003-http-root.headers`, `T-003-http-root.body`, and `T-004-nmap.xml`.
- Calculate `sha256sum` after capture. A hash does not replace preservation of the file.
- Never alter raw evidence to improve the report's appearance.

## Restricted inventory

`restricted/credentials.jsonl` must remain outside version control and use mode `0600`. Each line is an independent JSON object:

```json
{"credential_id":"CRED-001","value":"<FULL_VALUE>","secret_type":"password","origin":{"host":"<HOST>","url_or_path":"<ORIGIN>","evidence_ref":"T-007","timestamp":"<ISO-8601>"},"identity":"<ACCOUNT>","associations":[{"service":"<SERVICE>","endpoint":"<ENDPOINT>","rationale":"<WHY>","confidence":"CONFIRMED|INFERRED|POTENTIAL","use_status":"CONFIRMED|NOT TESTED|DISCARDED"}]}
```

Write the value through a mechanism that does not expose it in chat, command-line arguments, or terminal output. If the environment provides no safe channel, stop and ask the operator for a secure procedure. Possible reuse remains a hypothesis; do not validate it against another service without explicit authorization.

## Finding summary

For every material finding, include:

1. confidence classification;
2. exact asset and component;
3. evidence and dependent steps;
4. observed impact versus potential impact;
5. confirmed, absent, and unverified prerequisites;
6. limitations and false-positive risk;
7. defensive recommendation;
8. minimum additional test, marked not executed when unauthorized.
