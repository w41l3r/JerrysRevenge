# Validation

Jerry's Revenge `0.3.0` is covered by unit and loopback integration tests for CLI parsing, Tomcat fingerprinting, Manager detection, semicolon path variants, brute-force stopping behavior, credential handoff, Manager HTML session/CSRF handling, multipart static-WAR upload, report redaction, redirect suppression, strict static-WAR validation, canary verification, and cleanup.

Run the local checks from the repository root:

```bash
GOCACHE=/tmp/jerrysrevenge-go-cache go test -count=1 ./...
GOCACHE=/tmp/jerrysrevenge-go-cache go vet ./...
GOCACHE=/tmp/jerrysrevenge-go-cache go build -buildvcs=false -trimpath -o bin/jerrysrevenge ./cmd/jerrysrevenge
```

The final local validation completed successfully with Go `1.24.9`. The built `bin/jerrysrevenge` artifact had SHA-256:

```text
ad4f5077f789a491dc5ae41d6a355b93f5e785eda7c458a7e479fa10351b32aa
```

The deployment workflow enforces these safety invariants:

- it accepts only a canonical one-file static `index.html` canary WAR;
- it rejects JSP, classes, JARs, JavaScript, extra archive entries, symlinks, and traversal paths;
- it requires an authenticated Manager HTML page, session cookie, and valid CSRF nonce before any upload;
- it uploads through the `deployWar` multipart field and redacts session and CSRF values from reports;
- it never follows redirects and performs no automatic retries;
- it attempts immediate undeployment after a successful upload, including after marker-verification failure;
- it records cleanup failure and the random context path for manual review;
- it does not implement command execution, callbacks, persistence, web shells, or arbitrary executable WAR deployment.

Active target validation requires explicit action-specific authorization and `--execute`. Engagement-specific commands, targets, credentials, and captured evidence belong under the gitignored `reports/` and `restricted/` directories and are intentionally excluded from public documentation.
