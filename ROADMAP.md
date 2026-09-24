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

**Status:** bounded version assessment and single-file validation implemented
in `0.4.0`; broader AJP discovery remains out of scope.

The implemented workflow keeps AJP as an independently scoped surface. An HTTP
Tomcat endpoint does not authorize probing the same host on an AJP port, and an
open AJP port does not by itself confirm CVE-2020-1938.

Current behavior:

1. **Offline applicability:** correlate reliable Tomcat version evidence with
   the official affected ranges on every completed discovery run and record all
   unverified prerequisites. This step is local and sends no additional
   request.
2. **Controlled validation:** `--ghostcat --execute` sends one AJP13 request to
   the exact planned host and port for one web-application-relative file. The
   default is `WEB-INF/web.xml`; `--ghostcat-file` can select another in-scope
   resource. There are no automatic retries.
3. **Evidence handling:** returned bytes are capped at 1 MiB and stored only in
   mode-`0600` restricted evidence below a mode-`0700` directory. Normal output
   and the sanitized report contain metadata and a SHA-256, not the body.

Implemented constraints:

- accept a non-default AJP host and port;
- never turn the always-on version assessment into automatic file access;
- do not retry file reads automatically;
- preserve a strict response-size limit and reject traversal outside the
  selected web-application-relative path;
- classify version-only applicability as `POTENTIAL`, not `CONFIRMED`;
- distinguish AJP protocol confirmation and body acquisition from confirmed
  identity of the requested file; non-default content remains `INFERRED` until
  operator review;
- record exact request counts and every negative result in the chronological
  runbook.

Future design topics include shared-secret input without exposing the secret,
explicit virtual-host/context selection, and an AJP-only workflow that can use
previously collected HTTP evidence without repeating discovery.

Ghostcat-assisted JSP inclusion, upload, command execution, callbacks, and bulk
file collection are not part of this project boundary.
