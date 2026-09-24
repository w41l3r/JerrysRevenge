package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/w41l3r/JerrysRevenge/internal/cli"
	"github.com/w41l3r/JerrysRevenge/internal/evidence"
	"github.com/w41l3r/JerrysRevenge/internal/tomcat"
)

const version = "0.4.0"

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	now := time.Now()
	cfg, err := cli.Parse(args[1:], stderr, now)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "error: %v\n", err)
		cli.Usage(stderr)
		return 2
	}
	if cfg.ShowVersion {
		fmt.Fprintf(stdout, "jerrysrevenge %s %s\n", version, buildRevision())
		return 0
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(stderr, "error: get working directory: %v\n", err)
		return 2
	}
	runID := "JR-" + now.Format("20060102T150405.000000000-0700")
	reporter, err := evidence.NewReporter(evidence.ReportConfig{
		Path:           cfg.Report,
		RunID:          runID,
		Command:        args,
		WorkingDir:     cwd,
		Timeout:        cfg.Timeout,
		Insecure:       cfg.Insecure,
		UserAgent:      cfg.UserAgent,
		ToolVersion:    version,
		RuntimeVersion: runtime.Version(),
	})
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}
	defer reporter.Close()

	targets, err := resolveTargets(cfg)
	if err != nil {
		recordInputFailure(reporter, "validate the target source", err)
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	var credentials []tomcat.Credential
	var candidateSummary tomcat.CandidateSummary
	if cfg.Brute {
		credentials, candidateSummary, err = tomcat.LoadCredentialCandidates(cfg.Wordlist, cfg.Company, now.Year())
		if err != nil {
			recordInputFailure(reporter, "validate the credential wordlist", err)
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
	}
	if cfg.Ghostcat {
		normalizedFile, normalizeErr := tomcat.NormalizeGhostcatFile(cfg.GhostcatFile)
		if normalizeErr != nil {
			recordInputFailure(reporter, "validate the Ghostcat file path", normalizeErr)
			fmt.Fprintf(stderr, "error: %v\n", normalizeErr)
			return 2
		}
		cfg.GhostcatFile = normalizedFile
		if outputErr := tomcat.ValidateGhostcatOutputDir(cfg.GhostcatOutputDir); outputErr != nil {
			recordInputFailure(reporter, "validate the Ghostcat restricted evidence directory", outputErr)
			fmt.Fprintf(stderr, "error: %v\n", outputErr)
			return 2
		}
		for _, target := range targets {
			host := cfg.AJPHost
			if host == "" {
				host = target.Hostname()
			}
			if hostErr := tomcat.ValidateAJPHost(host); hostErr != nil {
				recordInputFailure(reporter, "validate the Ghostcat AJP host", hostErr)
				fmt.Fprintf(stderr, "error: %v\n", hostErr)
				return 2
			}
		}
	}

	var deployCredential *tomcat.Credential
	if cfg.DeployCheck && !cfg.Brute {
		if cfg.CredentialsFile != "" {
			credential, loadErr := tomcat.LoadCredentialFile(cfg.CredentialsFile)
			if loadErr != nil {
				recordInputFailure(reporter, "validate the single-credential file", loadErr)
				fmt.Fprintf(stderr, "error: %v\n", loadErr)
				return 2
			}
			deployCredential = &credential
		} else {
			deployCredential = &tomcat.Credential{
				Username: cfg.Username,
				Password: cfg.Password,
				Ref:      "DIRECT-CLI",
			}
		}
	}

	var canary *tomcat.CanaryArtifact
	if cfg.DeployCheck {
		if cfg.WarFile != "" {
			canary, err = tomcat.LoadStaticCanaryWAR(cfg.WarFile)
		} else {
			canary, err = tomcat.BuildDefaultCanary()
		}
		if err != nil {
			recordInputFailure(reporter, "validate the static canary WAR", err)
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
	}

	plan := renderPlan(cfg, targets, candidateSummary, canary)
	planInterpretation := "The plan is limited to HTTP(S) on the supplied targets. The deployment option, when selected, permits only a static canary with immediate cleanup; it never deploys executable server-side content."
	planLimitations := "Requests generate access and error logs and may trigger WAF or SIEM alerts. Credential validation can cause account lockout or rate limiting; HTTP 429 stops new attempts for that target. Redirects are recorded but never followed."
	if cfg.Ghostcat {
		planInterpretation += " --ghostcat additionally authorizes one AJP13 file-read attempt per target against the exact host, port, and path printed in this plan; returned bytes are restricted evidence."
		planLimitations += " AJP traffic and access to WEB-INF or another selected resource may trigger firewall, IDS, Tomcat connector, process, or data-access telemetry."
	}
	reporter.RecordStep(evidence.Step{
		Timestamp:      now,
		Objective:      "define scope, request volume, operational risk, and authorization gate",
		Operation:      evidence.Command(args),
		Prerequisites:  "explicit authorization for every listed target; --execute acts as the operator's confirmation after reviewing this plan",
		CapturedOutput: plan,
		Interpretation: planInterpretation,
		Limitations:    planLimitations,
		Status:         evidence.EvaluatedNotExecuted,
		Classification: tomcat.Unverified,
		Dependencies:   "target, wordlist, credential, and WAR files were read locally only",
	})

	fmt.Fprintln(stdout, plan)
	if !cfg.Execute {
		fmt.Fprintln(stdout, "\n[EVALUATED — NOT EXECUTED] No HTTP or AJP requests were sent.")
		fmt.Fprintf(stdout, "Sanitized runbook: %s\n", cfg.Report)
		if err := reporter.Close(); err != nil {
			fmt.Fprintf(stderr, "error: finalize report: %v\n", err)
			return 2
		}
		return 0
	}
	if cfg.Ghostcat {
		if err := tomcat.PrepareGhostcatOutputDir(cfg.GhostcatOutputDir); err != nil {
			recordInputFailure(reporter, "prepare the Ghostcat restricted evidence directory before target traffic", err)
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	requester, err := tomcat.NewRequester(tomcat.RequesterConfig{
		Timeout:   cfg.Timeout,
		Threads:   cfg.Threads,
		Delay:     cfg.Delay,
		Insecure:  cfg.Insecure,
		UserAgent: cfg.UserAgent,
		Observer:  reporter.RecordProbe,
	})
	if err != nil {
		fmt.Fprintf(stderr, "error: configure HTTP client: %v\n", err)
		return 2
	}

	results := scanTargets(ctx, requester, targets, tomcat.ScanOptions{
		TryBypass:          cfg.TryBypass,
		Brute:              cfg.Brute,
		ContinueOnSuccess:  cfg.ContinueOnSuccess,
		Threads:            cfg.Threads,
		Credentials:        credentials,
		Ghostcat:           cfg.Ghostcat,
		GhostcatFile:       cfg.GhostcatFile,
		GhostcatOutputDir:  cfg.GhostcatOutputDir,
		GhostcatEvidenceID: runID,
		AJPHost:            cfg.AJPHost,
		AJPPort:            cfg.AJPPort,
		Timeout:            cfg.Timeout,
		DeployCheck:        cfg.DeployCheck,
		DeployCredential:   deployCredential,
		Canary:             canary,
	}, cfg.Threads)

	inventory := evidence.NewInventory(cfg.CredentialOutput)
	inventoryUsed := false
	cleanupFailure := false
	for _, result := range results {
		for _, finding := range result.Brute.Findings {
			if err := inventory.Append(finding); err != nil {
				fmt.Fprintf(stderr, "error: write restricted credential inventory: %v\n", err)
				return 2
			}
			inventoryUsed = true
		}
		printResult(stdout, result)
		recordConclusions(reporter, result)
		for _, finding := range result.Brute.Findings {
			fmt.Fprintf(stdout, "  [%s] %s account=[REDACTED:%s] secret=[REDACTED; restricted inventory]\n", finding.Classification, finding.ID, finding.ID)
		}
		if result.Deployment.Deployed && !result.Deployment.CleanupSucceeded {
			cleanupFailure = true
		}
	}
	if inventoryUsed {
		fmt.Fprintf(stdout, "Restricted inventory (0600): %s\n", inventory.Path())
	}
	fmt.Fprintf(stdout, "Sanitized runbook: %s\n", cfg.Report)
	closeErr := reporter.Close()

	if ctx.Err() != nil {
		if closeErr != nil {
			fmt.Fprintf(stderr, "additional error while finalizing report: %v\n", closeErr)
		}
		fmt.Fprintln(stderr, "execution interrupted; partial results were preserved")
		return 130
	}
	if closeErr != nil {
		fmt.Fprintf(stderr, "error: %v\n", closeErr)
		return 2
	}
	if cleanupFailure {
		fmt.Fprintln(stderr, "error: at least one deployed canary was not confirmed as removed; review the reported context path manually")
		return 1
	}
	return 0
}

func recordInputFailure(reporter *evidence.Reporter, objective string, err error) {
	reporter.RecordStep(evidence.Step{
		Objective:      objective,
		Operation:      "Local validation of arguments and input files; no HTTP request.",
		CapturedOutput: "error=" + err.Error(),
		Interpretation: "The input was rejected before any active action.",
		Limitations:    "The error records only the line number and cause; credential and WAR contents are not copied into the report.",
		Status:         evidence.EvaluatedNotExecuted,
		Classification: tomcat.Confirmed,
		Dependencies:   "the main command recorded in the report header",
	})
}

func resolveTargets(cfg cli.Config) ([]*url.URL, error) {
	if cfg.URL != "" {
		target, err := tomcat.ParseTarget(cfg.URL)
		if err != nil {
			return nil, err
		}
		return []*url.URL{target}, nil
	}
	return tomcat.LoadTargets(cfg.List)
}

func renderPlan(cfg cli.Config, targets []*url.URL, candidates tomcat.CandidateSummary, canary *tomcat.CanaryArtifact) string {
	baseRequests := 4
	if cfg.TryBypass {
		baseRequests += 2
	}
	perTargetMax := baseRequests
	if cfg.Brute {
		perTargetMax += 1 + candidates.TotalCount
	}
	if cfg.DeployCheck {
		perTargetMax += 5
	}
	var lines []string
	lines = append(lines,
		"Active validation plan:",
		fmt.Sprintf("- Scope: %d HTTP(S) base URL(s)", len(targets)),
	)
	for _, target := range targets {
		lines = append(lines, "  - "+target.String())
	}
	lines = append(lines,
		"- Discovery per target: base URL, controlled 404, /docs/, and /manager/html (4 requests)",
		"- CVE-2020-1938: always correlate any identified Tomcat version with the authoritative affected ranges locally; version matching alone remains POTENTIAL and sends no additional request",
		fmt.Sprintf("- Global maximum concurrency: %d; timeout: %s; delay: %s; retries: 0", cfg.Threads, cfg.Timeout, cfg.Delay),
	)
	if cfg.TryBypass {
		lines = append(lines, "- Tomcat-conditioned path variants: /jr/..;/manager/html and /;a=b/manager/html (up to 2 requests per target)")
	}
	if cfg.Brute {
		stopBehavior := "stop after the first confirmed credential"
		if cfg.ContinueOnSuccess {
			stopBehavior = "continue after findings"
		}
		lines = append(lines,
			fmt.Sprintf("- Credential source: %s (%d base candidates), company-derived additions=%d, deduplicated total=%d", candidates.BaseSource, candidates.BaseCount, candidates.CompanyCount, candidates.TotalCount),
			fmt.Sprintf("- Credential validation: 1 deliberately invalid control plus up to %d candidates per Manager; %s", candidates.TotalCount, stopBehavior),
		)
		if candidates.CompanyCount > 0 {
			lines = append(lines, fmt.Sprintf("- Company candidate generation year: %d; organization value and generated pairs are omitted from this sanitized plan", candidates.CompanyYear))
		}
	}
	if cfg.Ghostcat {
		lines = append(lines, "- Ghostcat AJP scope (one FORWARD_REQUEST and no retry per HTTP target):")
		for _, target := range targets {
			host := cfg.AJPHost
			if host == "" {
				host = target.Hostname()
			}
			lines = append(lines, fmt.Sprintf("  - ajp13://%s file=%s", net.JoinHostPort(host, fmt.Sprintf("%d", cfg.AJPPort)), cfg.GhostcatFile))
		}
		lines = append(lines,
			fmt.Sprintf("- Ghostcat acquisition: up to %d AJP request(s); concurrency no greater than %d; timeout=%s; AJP delay=not applicable to the single request per endpoint; redirects=0; retries=0", len(targets), minInt(cfg.Threads, len(targets)), cfg.Timeout),
			"- Ghostcat response handling: at most 1 MiB is retained; raw bytes go only to mode-0600 files under "+cfg.GhostcatOutputDir+"; terminal and sanitized report receive metadata and hashes only",
			"- Ghostcat side effects: no target-side file is created or modified and no rollback is required; the operation does acquire the selected server-side resource when vulnerable",
		)
	}
	if cfg.DeployCheck && canary != nil {
		credentialSource := "one operator-supplied credential"
		if cfg.Brute {
			credentialSource = "the first CONFIRMED brute-force finding"
		}
		lines = append(lines,
			fmt.Sprintf("- Static deployment canary: source=%s source_sha256=%s upload_sha256=%s context=%s", canary.Source, canary.SourceSHA256, canary.SHA256, canary.ContextPath),
			"- Deployment sequence per eligible target: authenticated Manager HTML session/CSRF preflight, multipart WAR upload, GET marker, session/CSRF refresh, and authenticated undeploy POST (up to 5 requests)",
			"- Deployment credential source: "+credentialSource,
			"- State change and rollback: a temporary context is created only after an authenticated CSRF-protected preflight; undeploy is attempted immediately, including after verification failure or cancellation.",
		)
		if cfg.Password != "" {
			lines = append(lines, "- Credential caution: -P/--password is redacted from reports but remains visible to local process-list observers; --creds-file is safer.")
		}
	}
	lines = append(lines,
		fmt.Sprintf("- Theoretical upper bound: %d HTTP requests", perTargetMax*len(targets)),
		"- Likely telemetry: access/error logs, proxy/WAF logs, authentication events, deployment audit events, AJP/firewall/IDS events when selected, and traversal or brute-force alerts.",
		"- Risks: account lockout, rate limiting, defensive alerts, concurrent load, acquisition of sensitive application data through --ghostcat, and a residual static context if canary cleanup fails; HTTP 429 stops new credential attempts.",
		"- Always out of scope: command execution, Ghostcat JSP evaluation, bulk file collection, server-side payloads, web shells, callbacks, persistence, and arbitrary executable WAR upload.",
	)
	return strings.Join(lines, "\n")
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func scanTargets(ctx context.Context, requester *tomcat.Requester, targets []*url.URL, opts tomcat.ScanOptions, threads int) []tomcat.Result {
	results := make([]tomcat.Result, len(targets))
	type job struct {
		index  int
		target *url.URL
	}
	jobs := make(chan job)
	workers := threads
	if workers > len(targets) {
		workers = len(targets)
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				results[item.index] = tomcat.ScanTarget(ctx, requester, item.target, opts)
			}
		}()
	}
	for index, target := range targets {
		select {
		case jobs <- job{index: index, target: target}:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return results
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

func printResult(stdout *os.File, result tomcat.Result) {
	if result.Target == nil {
		return
	}
	version := result.Fingerprint.Version
	if version == "" {
		version = "not identified"
	}
	fmt.Fprintf(stdout, "\n[%s] %s Tomcat=%t version=%s\n", result.Fingerprint.Classification, result.Target, result.Fingerprint.IsTomcat, version)
	fmt.Fprintf(stdout, "[%s] CVE-2020-1938 version_match=%t active_requested=%t assessment=%s\n",
		result.Ghostcat.Assessment.Classification, result.Ghostcat.Assessment.VersionMatched,
		result.Ghostcat.Requested, result.Ghostcat.Assessment.Interpretation)
	if result.Ghostcat.Requested {
		switch {
		case result.Ghostcat.FileReadConfirmed:
			fmt.Fprintf(stdout, "[%s] ghostcat endpoint=%s file=%s protocol=%t status=%d bytes=%d sha256=%s restricted_evidence=%s\n",
				result.Ghostcat.Classification, result.Ghostcat.Endpoint, result.Ghostcat.RequestedFile,
				result.Ghostcat.ProtocolConfirmed, result.Ghostcat.ResponseStatusCode,
				result.Ghostcat.BodyBytes, result.Ghostcat.BodySHA256, result.Ghostcat.EvidencePath)
		case result.Ghostcat.BodyAcquired:
			fmt.Fprintf(stdout, "[%s] ghostcat endpoint=%s file=%s protocol=%t status=%d body_acquired=true file_read_confirmed=false bytes=%d sha256=%s restricted_evidence=%s\n",
				result.Ghostcat.Classification, result.Ghostcat.Endpoint, result.Ghostcat.RequestedFile,
				result.Ghostcat.ProtocolConfirmed, result.Ghostcat.ResponseStatusCode,
				result.Ghostcat.BodyBytes, result.Ghostcat.BodySHA256, result.Ghostcat.EvidencePath)
		case result.Ghostcat.Executed:
			fmt.Fprintf(stdout, "[%s] ghostcat endpoint=%s file=%s protocol=%t status=%d confirmed=false error=%s\n",
				result.Ghostcat.Classification, result.Ghostcat.Endpoint, result.Ghostcat.RequestedFile,
				result.Ghostcat.ProtocolConfirmed, result.Ghostcat.ResponseStatusCode, result.Ghostcat.Error)
		default:
			fmt.Fprintf(stdout, "[EVALUATED — NOT EXECUTED] ghostcat omitted: %s\n", result.Ghostcat.Interpretation)
		}
	}
	fmt.Fprintf(stdout, "[%s] Manager present=%t open=%t basic_auth=%t\n", result.Manager.Classification, result.Manager.Present, result.Manager.Open, result.Manager.AuthRequired)
	probeErrors := 0
	for _, probe := range result.Probes {
		if probe.Error != "" {
			probeErrors++
		}
	}
	if probeErrors > 0 {
		fmt.Fprintf(stdout, "[UNVERIFIED] transport/probe errors=%d; see the runbook\n", probeErrors)
	}
	for _, bypass := range result.Manager.Bypasses {
		fmt.Fprintf(stdout, "[%s] bypass=%s reaches_manager=%t changed_routing=%t\n", bypass.Classification, bypass.Path, bypass.ReachesManager, bypass.ChangedRouting)
	}
	if result.Manager.BypassRequested && len(result.Manager.Bypasses) == 0 {
		fmt.Fprintf(stdout, "[EVALUATED — NOT EXECUTED] bypass omitted: %s\n", result.Manager.BypassSkipReason)
	}
	if result.Brute.Requested {
		if !result.Brute.Executed {
			fmt.Fprintf(stdout, "[UNVERIFIED] credential validation not executed: %s\n", result.Brute.SkipReason)
		} else {
			fmt.Fprintf(stdout, "[EXECUTED] credential attempts=%d invalid=%d potential=%d errors=%d rate_limited=%t findings=%d\n",
				result.Brute.Attempted, result.Brute.Invalid, result.Brute.Potential, result.Brute.Errors, result.Brute.RateLimited, len(result.Brute.Findings))
		}
	}
	if result.Deployment.Requested {
		if !result.Deployment.Executed {
			fmt.Fprintf(stdout, "[EVALUATED — NOT EXECUTED] static deployment check omitted: %s\n", result.Deployment.SkipReason)
		} else {
			fmt.Fprintf(stdout, "[%s] static_deploy interface=%s session=%t csrf=%t deployed=%t marker_verified=%t cleanup_attempted=%t cleanup_confirmed=%t context=%s\n",
				result.Deployment.Classification, result.Deployment.Interface, result.Deployment.SessionEstablished,
				result.Deployment.CSRFTokenFound, result.Deployment.Deployed, result.Deployment.Verified,
				result.Deployment.CleanupAttempted, result.Deployment.CleanupSucceeded, result.Deployment.ContextPath)
			if result.Deployment.SkipReason != "" {
				fmt.Fprintf(stdout, "[UNVERIFIED] static deployment detail: %s\n", result.Deployment.SkipReason)
			}
		}
	}
}

func recordConclusions(reporter *evidence.Reporter, result tomcat.Result) {
	if result.Target == nil {
		return
	}
	fingerprintOutput := fmt.Sprintf("target=%s\nis_tomcat=%t\nversion=%s\nevidence=%s", result.Target, result.Fingerprint.IsTomcat, result.Fingerprint.Version, strings.Join(result.Fingerprint.Evidence, " | "))
	reporter.RecordStep(evidence.Step{
		Objective:      "consolidate the server fingerprint and version",
		Operation:      "Local correlation of previous HTTP probes; no new request.",
		CapturedOutput: fingerprintOutput,
		Interpretation: "CONFIRMED requires a Tomcat-specific marker in a header, authentication realm, or response body. Missing markers remain UNVERIFIED and do not prove that Tomcat is absent behind a customized page.",
		Limitations:    "Reverse proxies, customized pages, and caches can hide or mix version evidence. Conflicting versions are preserved.",
		Status:         evidence.Executed,
		Classification: result.Fingerprint.Classification,
		Dependencies:   "base URL, controlled 404, /docs/, and /manager/html probes",
	})
	ghostcatAssessment := result.Ghostcat.Assessment
	assessmentOutput := fmt.Sprintf("cve=CVE-2020-1938\nversion=%s\nversion_matched=%t\nauthoritative_range=%t\naffected_range=%s\nfirst_fixed=%s\nactive_test_requested=%t",
		ghostcatAssessment.Version, ghostcatAssessment.VersionMatched, ghostcatAssessment.Authoritative,
		ghostcatAssessment.AffectedRange, ghostcatAssessment.FirstFixed, result.Ghostcat.Requested)
	reporter.RecordStep(evidence.Step{
		Objective:      "correlate the identified Tomcat version with CVE-2020-1938",
		Operation:      "Local version-range correlation against the authoritative Apache advisory; no additional target request.",
		CapturedOutput: assessmentOutput,
		Interpretation: ghostcatAssessment.Interpretation,
		Limitations:    "Version matching alone does not establish that AJP is enabled, reachable, unauthenticated, missing a shared secret, or capable of returning the selected web-application resource. Vendor backports and altered banners remain possible.",
		Status:         evidence.Executed,
		Classification: ghostcatAssessment.Classification,
		Dependencies:   "the consolidated Tomcat fingerprint and version evidence",
	})
	if result.Ghostcat.Requested {
		status := evidence.EvaluatedNotExecuted
		if result.Ghostcat.Executed {
			status = evidence.Executed
		}
		ghostcatOutput := fmt.Sprintf("endpoint=%s\nfile=%s\nrequest_count=%d\nrequest_sent=%t\nresponse_magic=%s\nresponse_status=%d\nresponse_content_type=%s\nprotocol_confirmed=%t\nbody_acquired=%t\nfile_read_confirmed=%t\nbody_bytes=%d\nbody_sha256=%s\nbody_truncated=%t\nrestricted_evidence=%s\nerror=%s\nstarted_at=%s\nfinished_at=%s\nduration=%s",
			result.Ghostcat.Endpoint, result.Ghostcat.RequestedFile, result.Ghostcat.RequestCount,
			result.Ghostcat.RequestSent, result.Ghostcat.ResponseMagic, result.Ghostcat.ResponseStatusCode,
			result.Ghostcat.ResponseContentType, result.Ghostcat.ProtocolConfirmed, result.Ghostcat.BodyAcquired, result.Ghostcat.FileReadConfirmed,
			result.Ghostcat.BodyBytes, result.Ghostcat.BodySHA256, result.Ghostcat.BodyTruncated,
			result.Ghostcat.EvidencePath, result.Ghostcat.Error,
			result.Ghostcat.StartedAt.Format(time.RFC3339Nano), result.Ghostcat.FinishedAt.Format(time.RFC3339Nano), result.Ghostcat.Duration)
		reporter.RecordStep(evidence.Step{
			Objective:      "perform the explicitly requested CVE-2020-1938 AJP file-read validation",
			Operation:      "One TCP connection and at most one AJP13 FORWARD_REQUEST with javax.servlet.include request attributes, initiated by the command in the report header. No retry, upload, JSP evaluation, or command execution.",
			CapturedOutput: ghostcatOutput,
			Interpretation: result.Ghostcat.Interpretation,
			Limitations:    "The operation tests only the exact AJP host, port, and web-application-relative file in the plan. A negative result can reflect filtering, a shared secret, a patched build, a different virtual host/context, or an absent resource. A successful response is sensitive data acquisition; raw bytes remain only in mode-0600 restricted evidence. Likely telemetry includes TCP/AJP, firewall, IDS, Tomcat connector, and file-access events.",
			Status:         status,
			Classification: result.Ghostcat.Classification,
			Dependencies:   "--ghostcat, --execute, the exact AJP endpoint and file printed in the authorization plan",
		})
	}
	managerOutput := fmt.Sprintf("target=%s\npresent=%t\nopen=%t\nauth_required=%t\nauth_endpoint=%s\nbypass_requested=%t\nbypass_skip_reason=%s\nevidence=%s", result.Target, result.Manager.Present, result.Manager.Open, result.Manager.AuthRequired, result.Manager.AuthEndpoint, result.Manager.BypassRequested, result.Manager.BypassSkipReason, strings.Join(result.Manager.Evidence, " | "))
	reporter.RecordStep(evidence.Step{
		Objective:      "consolidate Tomcat Manager access and path-variant results",
		Operation:      "Local correlation of the direct path and, when requested, two semicolon variants; no new request.",
		CapturedOutput: managerOutput,
		Interpretation: "ChangedRouting is confirmed only when a variant reaches Manager markers and the direct path does not. If both work, the variant is accepted but an access-control bypass was not demonstrated.",
		Limitations:    "HTTP 200 without Manager markers is not treated as success. HTTP 403 without specific evidence remains inconclusive.",
		Status:         evidence.Executed,
		Classification: result.Manager.Classification,
		Dependencies:   "direct Manager probe and --trybypass probes, if enabled",
	})
	if result.Brute.Requested {
		findingRefs := make([]string, 0, len(result.Brute.Findings))
		class := tomcat.Unverified
		for _, finding := range result.Brute.Findings {
			findingRefs = append(findingRefs, fmt.Sprintf("%s(account=[REDACTED:%s],password=[REDACTED:%s],classification=%s)", finding.ID, finding.ID, finding.ID, finding.Classification))
			if finding.Classification == tomcat.Confirmed {
				class = tomcat.Confirmed
			} else if class != tomcat.Confirmed {
				class = finding.Classification
			}
		}
		sort.Strings(findingRefs)
		status := evidence.EvaluatedNotExecuted
		if result.Brute.Executed {
			status = evidence.Executed
		}
		output := fmt.Sprintf("endpoint=%s\nexecuted=%t\nskip_reason=%s\ninvalid_control_status=%d\nattempted=%d\ninvalid=%d\npotential=%d\nerrors=%d\nrate_limited=%t\nfindings=%s",
			result.Brute.Endpoint, result.Brute.Executed, result.Brute.SkipReason, result.Brute.InvalidControlStatus, result.Brute.Attempted, result.Brute.Invalid, result.Brute.Potential, result.Brute.Errors, result.Brute.RateLimited, strings.Join(findingRefs, ", "))
		reporter.RecordStep(evidence.Step{
			Objective:      "consolidate Tomcat Manager credential validation",
			Operation:      "Local correlation of the deliberately invalid control and wordlist entries; passwords remain outside this report.",
			CapturedOutput: output,
			Interpretation: "HTTP 200 with Manager content confirms access. A change from the invalid control's 401 to 403 is INFERRED because it may represent an authenticated account without the required role. Other differences are POTENTIAL and do not create a confirmed credential.",
			Limitations:    "Concurrency may leave a small number of requests in flight after a success. HTTP 429 cancels new attempts. Complete values remain only in the mode-0600 restricted inventory.",
			Status:         status,
			Classification: class,
			Dependencies:   "Manager with an unambiguous Basic challenge, -b, a bundled or operator-supplied candidate set, and --execute",
		})
	}
	if result.Deployment.Requested {
		status := evidence.EvaluatedNotExecuted
		if result.Deployment.Executed {
			status = evidence.Executed
		}
		output := fmt.Sprintf("target=%s\nexecuted=%t\nskip_reason=%s\ninterface=%s\ncredential_ref=%s\nsession_established=%t\ncsrf_nonce_found=%t\nartifact_source=%s\nartifact_source_sha256=%s\nartifact_upload_sha256=%s\ncontext_path=%s\ndeployed=%t\nmarker_verified=%t\ncleanup_attempted=%t\ncleanup_confirmed=%t",
			result.Target, result.Deployment.Executed, result.Deployment.SkipReason, result.Deployment.Interface, result.Deployment.CredentialRef,
			result.Deployment.SessionEstablished, result.Deployment.CSRFTokenFound,
			result.Deployment.ArtifactSource, result.Deployment.ArtifactSourceSHA256, result.Deployment.ArtifactSHA256, result.Deployment.ContextPath,
			result.Deployment.Deployed, result.Deployment.Verified, result.Deployment.CleanupAttempted, result.Deployment.CleanupSucceeded)
		reporter.RecordStep(evidence.Step{
			Objective:      "consolidate the reversible static-canary deployment check",
			Operation:      "Local correlation of Manager HTML authentication, CSRF/session handling, multipart deployment, marker verification, and undeployment observations; no new request.",
			CapturedOutput: output,
			Interpretation: result.Deployment.Interpretation,
			Limitations:    deploymentLimitations(result.Deployment),
			Status:         status,
			Classification: result.Deployment.Classification,
			Dependencies:   "--exploit, --execute, a validated static canary, and either a direct credential or a CONFIRMED brute-force finding",
		})
	}
}

func deploymentLimitations(result tomcat.DeploymentResult) string {
	const telemetry = "The attempted activity can generate authentication, upload, deployment, access, and undeployment telemetry."
	switch {
	case !result.Executed:
		return "No active deployment validation was executed, so deployment capability, token retrieval, and cleanup remain unverified. " + telemetry
	case !result.Deployed:
		return "No successful deployment was observed, so deployment capability, token retrieval, and cleanup remain unverified. " + telemetry
	case result.Verified && result.CleanupSucceeded:
		return "This confirms only deployment, retrieval, and removal of the constrained static canary through the Manager HTML interface. It does not execute code or establish general command execution. " + telemetry
	case result.CleanupSucceeded:
		return "Tomcat confirmed deployment and removal of the constrained static canary, but retrieval of the expected marker was not confirmed. It does not establish general command execution. " + telemetry
	default:
		return "Tomcat confirmed deployment of the constrained static canary, but cleanup was not confirmed. The reported context path requires manual review and may remain deployed. It does not establish general command execution. " + telemetry
	}
}

func buildRevision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "devel"
	}
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" && setting.Value != "" {
			return setting.Value
		}
	}
	return "devel"
}
