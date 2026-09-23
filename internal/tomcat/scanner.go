package tomcat

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
)

type ScanOptions struct {
	TryBypass         bool
	Brute             bool
	ContinueOnSuccess bool
	Threads           int
	Credentials       []Credential
	DeployCheck       bool
	DeployCredential  *Credential
	Canary            *CanaryArtifact
}

func ScanTarget(ctx context.Context, requester *Requester, target *url.URL, opts ScanOptions) Result {
	result := Result{Target: target}
	probe := func(suffix, objective string) Probe {
		endpoint, err := BuildEndpoint(target, suffix)
		if err != nil {
			return Probe{Objective: objective, URL: target.String(), Error: err.Error()}
		}
		p := requester.Do(ctx, RequestSpec{URL: endpoint, Objective: objective})
		result.Probes = append(result.Probes, p)
		return p
	}

	probe("", "inspect the base URL for Apache Tomcat indicators")
	invalidSuffix := "/.jerrysrevenge-404-" + targetToken(target.String())
	probe(invalidSuffix, "request a controlled 404 response to identify the default Tomcat error page")
	probe("/docs/", "inspect the default documentation for Tomcat and version indicators")
	direct := probe(managerPath, "check Tomcat Manager presence and access control")

	result.Manager = analyzeManagerDirect(direct)
	preliminaryFingerprint := AnalyzeFingerprint(result.Probes)
	if opts.TryBypass {
		result.Manager.BypassRequested = true
		if !preliminaryFingerprint.IsTomcat && !result.Manager.Present {
			result.Manager.BypassSkipReason = "the fingerprint did not identify Tomcat; active path variants were omitted"
		} else {
			directAssessment := result.Manager
			for _, path := range bypassPaths() {
				p := probe(path, "test a normalization discrepancy with a semicolon-delimited path parameter")
				assessment := assessBypass(path, p, directAssessment)
				result.Manager.Bypasses = append(result.Manager.Bypasses, assessment)
				if assessment.ReachesManager {
					result.Manager.Present = true
					result.Manager.Evidence = append(result.Manager.Evidence, assessment.Interpretation)
					if p.StatusCode >= 200 && p.StatusCode < 300 && managerBody(p.body) {
						result.Manager.Open = true
					}
					if p.StatusCode == 401 && managerRealm(p) && result.Manager.AuthEndpoint == "" {
						result.Manager.AuthRequired = true
						result.Manager.AuthEndpoint = p.URL
					}
					if assessment.Classification == Confirmed {
						result.Manager.Classification = Confirmed
					} else if assessment.Classification == Inferred && result.Manager.Classification == Unverified {
						result.Manager.Classification = Inferred
					}
				}
			}
		}
	}

	result.Fingerprint = AnalyzeFingerprint(result.Probes)
	result.Manager.Evidence = uniqueStrings(result.Manager.Evidence)

	result.Brute.Requested = opts.Brute
	if opts.Brute {
		switch {
		case result.Manager.Open:
			result.Brute.SkipReason = "Manager is already accessible without authentication; credential validation is unnecessary"
		case result.Manager.AuthEndpoint == "":
			result.Brute.SkipReason = "no Manager endpoint with an unambiguous Basic challenge was found"
		default:
			result.Brute = BruteForce(ctx, requester, result.Manager.AuthEndpoint, opts.Credentials, BruteOptions{
				Threads:           opts.Threads,
				ContinueOnSuccess: opts.ContinueOnSuccess,
			})
		}
	}

	result.Deployment.Requested = opts.DeployCheck
	result.Deployment.Classification = Unverified
	if opts.DeployCheck {
		if opts.Canary != nil {
			result.Deployment.ArtifactSource = opts.Canary.Source
			result.Deployment.ArtifactSHA256 = opts.Canary.SHA256
			result.Deployment.ArtifactSourceSHA256 = opts.Canary.SourceSHA256
			result.Deployment.ContextPath = opts.Canary.ContextPath
			result.Deployment.Marker = opts.Canary.Marker
		}
		var deploymentCredential *Credential
		if opts.Brute {
			for _, finding := range result.Brute.Findings {
				if finding.Classification != Confirmed {
					continue
				}
				deploymentCredential = &Credential{
					Username: finding.Username,
					Password: finding.Password,
					Ref:      finding.ID,
					Line:     finding.SourceLine,
				}
				break
			}
			if deploymentCredential == nil {
				result.Deployment.SkipReason = "brute-force validation produced no CONFIRMED credential"
			}
		} else {
			deploymentCredential = opts.DeployCredential
			if deploymentCredential == nil {
				result.Deployment.SkipReason = "no direct deployment credential was supplied"
			}
		}
		switch {
		case !result.Fingerprint.IsTomcat:
			result.Deployment.SkipReason = "Tomcat was not identified; the state-changing deployment check was omitted"
		case deploymentCredential == nil:
			// The specific reason was set above.
		case opts.Canary == nil:
			result.Deployment.SkipReason = "no locally validated static canary WAR is available"
		default:
			result.Deployment = ValidateStaticCanaryDeployment(ctx, requester, target, *deploymentCredential, opts.Canary)
		}
		if result.Deployment.Interpretation == "" {
			result.Deployment.Interpretation = result.Deployment.SkipReason
		}
	}
	return result
}

func analyzeManagerDirect(probe Probe) ManagerResult {
	result := ManagerResult{Classification: Unverified, Direct: probe}
	if managerRealm(probe) {
		result.Present = true
		result.AuthRequired = probe.StatusCode == 401
		result.Classification = Confirmed
		result.Evidence = append(result.Evidence, fmt.Sprintf("direct endpoint returned HTTP %d with the Tomcat Manager realm", probe.StatusCode))
		if probe.StatusCode == 401 {
			result.AuthEndpoint = probe.URL
		}
	}
	if probe.StatusCode >= 200 && probe.StatusCode < 300 && managerBody(probe.body) {
		result.Present = true
		result.Open = true
		result.Classification = Confirmed
		result.Evidence = append(result.Evidence, "direct endpoint displayed Tomcat Manager without authentication")
	}
	if probe.StatusCode == 403 && managerBody(probe.body) {
		result.Present = true
		result.Classification = Inferred
		result.Evidence = append(result.Evidence, "direct endpoint appears to be Manager but returned HTTP 403")
	}
	return result
}

func assessBypass(path string, probe Probe, direct ManagerResult) BypassResult {
	result := BypassResult{
		Path:           path,
		Probe:          probe,
		Classification: Unverified,
		Interpretation: fmt.Sprintf("variant %s did not provide unambiguous Manager evidence", path),
	}
	bypassOpen := probe.StatusCode >= 200 && probe.StatusCode < 300 && managerBody(probe.body)
	bypassAuth := probe.StatusCode == 401 && managerRealm(probe)
	bypassRestricted := probe.StatusCode == 403 && managerBody(probe.body)
	present := managerRealm(probe) || bypassOpen || bypassRestricted
	if !present {
		return result
	}
	result.ReachesManager = true
	if bypassRestricted {
		result.Classification = Inferred
		result.Interpretation = fmt.Sprintf("variant %s appears to have reached Manager but remained restricted with HTTP 403", path)
		if !direct.Present {
			result.ChangedRouting = true
		}
		return result
	}
	securityBehaviorChanged := (bypassOpen && !direct.Open) ||
		(bypassAuth && !direct.AuthRequired && direct.Direct.StatusCode == 403)
	if !direct.Present || securityBehaviorChanged {
		result.ChangedRouting = true
		result.Classification = Confirmed
		if !direct.Present {
			result.Interpretation = fmt.Sprintf("variant %s reached Manager while the direct path did not identify it", path)
		} else {
			result.Interpretation = fmt.Sprintf("variant %s reached Manager with access behavior different from the direct path", path)
		}
		return result
	}
	result.Classification = Inferred
	result.Interpretation = fmt.Sprintf("variant %s also reached Manager; because the direct path already worked, an access-control bypass was not demonstrated", path)
	return result
}

func targetToken(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:4])
}
