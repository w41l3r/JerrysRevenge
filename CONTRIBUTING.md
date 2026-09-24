# Contributing to Jerry's Revenge

Thank you for helping improve Jerry's Revenge. Contributions should preserve
the project's evidence-first behavior and conservative safety defaults.

## Development setup

Jerry's Revenge requires Go 1.24 or a compatible newer release and has no
third-party Go dependencies.

```bash
make test
make vet
make build
```

HTTP and AJP tests must use local ephemeral listeners. Tests and examples must
never contact a public system or an engagement target. A deliberately
vulnerable Docker fixture must bind every published port to loopback, use a
pinned image digest, and document teardown and retained artifacts.

## Pull requests

Please keep each change focused and include:

- the problem being solved;
- tests for new or changed behavior;
- documentation for operator-visible changes;
- the expected request count and telemetry for any active feature;
- confirmation that secrets, target evidence, reports, and binaries are absent
  from the commit.

Run `gofmt` on changed Go files and ensure `go test -race ./...`, `go vet ./...`,
and the build all pass.

## Safety requirements

Changes must fail closed and keep dry-run behavior as the default. Do not submit
command-execution payloads, JSP/web-shell deployment, callbacks, persistence,
automatic target expansion, silent retries, or credential logging. A new active
workflow must expose its precise scope, request ceiling, likely telemetry,
side effects, and cleanup behavior before execution.

Never add real credentials, session material, customer names, private targets,
raw engagement evidence, or files from `reports/` and `restricted/`. Ghostcat
response bodies are acquired target data and must remain restricted even when
the selected resource appears benign.

## Security issues

Do not open a public issue for a vulnerability that could expose users or their
assessment data. Follow the private reporting process in
[`SECURITY.md`](SECURITY.md).
