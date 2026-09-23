package tomcat

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type BruteOptions struct {
	Threads           int
	ContinueOnSuccess bool
}

func BruteForce(ctx context.Context, requester *Requester, endpoint string, credentials []Credential, opts BruteOptions) BruteResult {
	result := BruteResult{
		Requested: true,
		Executed:  true,
		Endpoint:  endpoint,
	}
	if len(credentials) == 0 {
		result.Executed = false
		result.SkipReason = "no credentials were loaded"
		return result
	}
	if opts.Threads < 1 {
		result.Executed = false
		result.SkipReason = "threads must be greater than zero"
		return result
	}

	control := invalidControlCredential()
	baseline := requester.Do(ctx, RequestSpec{
		URL:           endpoint,
		Objective:     "calibrate the response with a deliberately invalid credential",
		CredentialRef: control.Ref,
		Credential:    &control,
	})
	result.InvalidControlStatus = baseline.StatusCode
	if baseline.Error != "" {
		result.Executed = false
		result.SkipReason = "invalid-control request failed: " + baseline.Error
		return result
	}
	if baseline.StatusCode == 429 {
		result.RateLimited = true
		result.SkipReason = "invalid control received HTTP 429; credential validation stopped"
		return result
	}
	if baseline.StatusCode != 401 {
		result.Executed = false
		result.SkipReason = fmt.Sprintf("invalid control returned HTTP %d instead of 401; authentication results would be ambiguous", baseline.StatusCode)
		return result
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan Credential)
	var wg sync.WaitGroup
	var mu sync.Mutex

	worker := func() {
		defer wg.Done()
		for credential := range jobs {
			probe := requester.Do(runCtx, RequestSpec{
				URL:           endpoint,
				Objective:     "validate one wordlist entry with HTTP Basic authentication against Tomcat Manager",
				CredentialRef: credential.Ref,
				Credential:    &credential,
			})

			mu.Lock()
			if probe.Error != "" {
				// Context cancellation after a success is expected and not an
				// independent transport failure.
				if runCtx.Err() == nil {
					result.Errors++
				}
				mu.Unlock()
				continue
			}
			result.Attempted++
			if probe.StatusCode == 429 {
				result.RateLimited = true
				mu.Unlock()
				cancel()
				continue
			}

			finding, valid, potential := assessCredential(endpoint, credential, baseline, probe)
			if valid {
				result.Findings = append(result.Findings, finding)
				if !opts.ContinueOnSuccess {
					result.StoppedOnSuccess = true
					mu.Unlock()
					cancel()
					continue
				}
			} else if potential {
				result.Potential++
			} else {
				result.Invalid++
			}
			mu.Unlock()
		}
	}

	workerCount := opts.Threads
	if workerCount > len(credentials) {
		workerCount = len(credentials)
	}
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker()
	}

feed:
	for _, credential := range credentials {
		select {
		case jobs <- credential:
		case <-runCtx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()

	sort.Slice(result.Findings, func(i, j int) bool {
		return result.Findings[i].CredentialRef < result.Findings[j].CredentialRef
	})
	return result
}

func assessCredential(endpoint string, credential Credential, baseline, probe Probe) (CredentialFinding, bool, bool) {
	finding := CredentialFinding{
		Username:      credential.Username,
		Password:      credential.Password,
		CredentialRef: credential.Ref,
		SourceLine:    credential.Line,
		Endpoint:      endpoint,
		StatusCode:    probe.StatusCode,
		ObservedAt:    probe.FinishedAt,
	}

	if probe.StatusCode >= 200 && probe.StatusCode < 300 && managerBody(probe.body) {
		finding.ID = credentialID()
		finding.Classification = Confirmed
		finding.Outcome = "credential authenticated and accessed Tomcat Manager"
		return finding, true, false
	}
	if baseline.StatusCode == 401 && probe.StatusCode == 403 {
		finding.ID = credentialID()
		finding.Classification = Inferred
		finding.Outcome = "authentication was probably accepted, but the account lacks the required Manager role"
		return finding, true, false
	}
	if probe.StatusCode == 401 {
		return CredentialFinding{}, false, false
	}
	if probe.StatusCode != baseline.StatusCode || probe.BodySHA256 != baseline.BodySHA256 {
		return CredentialFinding{}, false, true
	}
	return CredentialFinding{}, false, false
}

func invalidControlCredential() Credential {
	random := make([]byte, 8)
	var token string
	if _, err := rand.Read(random); err != nil {
		token = fmt.Sprintf("%x%06x", time.Now().UnixNano(), fallbackIDCounter.Add(1))
	} else {
		token = hex.EncodeToString(random)
	}
	return Credential{
		Username: "__jr_invalid_" + token,
		Password: "__jr_invalid_" + token,
		Ref:      "CONTROL-INVALID",
	}
}

var fallbackIDCounter atomic.Uint64

func credentialID() string {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err == nil {
		return "CRED-TOMCAT-" + stringsUpperHex(random)
	}
	return fmt.Sprintf("CRED-TOMCAT-%X-%06X", time.Now().UnixNano(), fallbackIDCounter.Add(1))
}

func stringsUpperHex(value []byte) string {
	const alphabet = "0123456789ABCDEF"
	result := make([]byte, hex.EncodedLen(len(value)))
	hex.Encode(result, value)
	for i, b := range result {
		if b >= 'a' && b <= 'f' {
			result[i] = alphabet[10+(b-'a')]
		}
	}
	return string(result)
}
