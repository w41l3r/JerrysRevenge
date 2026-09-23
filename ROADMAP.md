# Roadmap

This file records design topics that have been accepted for later review. It is
not a commitment that a feature is implemented, safe to run, or authorized
against any target.

## Explicit workflow selection

**Status:** design pending; not implemented.

Support repeated assessments in which an operator wants to run discovery once
and later invoke one narrowly scoped validation without repeating the discovery
requests.

The interface still needs a design decision. Candidates include an explicit
workflow selector or subcommands; `--no-enum` may be retained as convenience
syntax, but a negative flag alone is ambiguous about what the tool will run.

Required properties:

- the default workflow remains backward compatible and starts with a dry run;
- skipping discovery never implies that a prerequisite was confirmed;
- the operator must provide every input needed by the selected action;
- the plan and report must name all skipped phases and any prior evidence on
  which the action depends;
- request ceilings, concurrency, delay, retries, telemetry, side effects, and
  rollback must be calculated for the selected workflow only;
- `--execute` and action-specific authorization remain mandatory for target
  traffic;
- incompatible combinations must fail closed instead of silently selecting a
  workflow.

## CVE-2020-1938 (Ghostcat) and AJP

**Status:** design pending; not implemented; no target traffic performed.

Add AJP as an independently scoped surface. An HTTP Tomcat endpoint does not
authorize probing the same host on an AJP port, and an open AJP port does not by
itself confirm CVE-2020-1938.

Keep the future workflow split into explicit levels:

1. **Offline applicability:** correlate reliable Tomcat version evidence with
   the official affected ranges and record all unverified prerequisites.
2. **AJP discovery:** test only an operator-supplied host and port for the AJP
   protocol and relevant access controls. This is active enumeration and must
   have its own reviewed request budget and approval.
3. **Controlled validation:** demonstrate the file-read primitive only with an
   operator-supplied, known-benign resource where practical. Do not use a
   sensitive path as an automatic default.
4. **Arbitrary-file-read mode:** require an explicit action, exact context and
   path, and separate exploitation approval. Treat returned content as acquired
   sensitive data: keep raw bytes in restricted mode-`0600` evidence and put
   only metadata, hashes, and a sanitized interpretation in the main report.

Additional design requirements:

- accept a non-default AJP port and optional AJP shared secret without exposing
  the secret in process arguments, terminal output, or sanitized reports;
- do not automatically chain discovery into file access;
- do not retry file reads automatically;
- preserve a strict response-size limit and reject traversal outside the
  operator-supplied context and path;
- classify version-only applicability as `POTENTIAL`, not `CONFIRMED`;
- distinguish AJP reachability, missing/incorrect secret behavior, successful
  benign validation, and confirmed acquisition of the requested file;
- record exact request counts and every negative result in the chronological
  runbook.

Ghostcat-assisted JSP inclusion or command execution is not part of this
roadmap item. It would require a separate project-owner design decision, safety
review, implementation boundary, and action-specific authorization.
