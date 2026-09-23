package tomcat

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const csrfParameterName = "org.apache.catalina.filters.CSRF_NONCE"

var csrfTokenPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)

// ValidateStaticCanaryDeployment authenticates to the CSRF-protected Manager
// HTML interface, uploads one non-executable static canary, verifies its marker,
// and attempts undeployment immediately. This deliberately matches the
// manager-gui capability validated by the credential check instead of requiring
// the separate manager-script role used by /manager/text.
func ValidateStaticCanaryDeployment(
	ctx context.Context,
	requester *Requester,
	target *url.URL,
	credential Credential,
	artifact *CanaryArtifact,
) DeploymentResult {
	result := DeploymentResult{
		Requested:      true,
		Interface:      "manager-html",
		CredentialRef:  credential.Ref,
		Classification: Unverified,
	}
	if artifact == nil {
		result.SkipReason = "no validated static canary artifact is available"
		result.Interpretation = result.SkipReason
		return result
	}
	result.ArtifactSource = artifact.Source
	result.ArtifactSHA256 = artifact.SHA256
	result.ArtifactSourceSHA256 = artifact.SourceSHA256
	result.ContextPath = artifact.ContextPath
	result.Marker = artifact.Marker

	managerURL, err := managerHTMLEndpoint(target, "", nil)
	if err != nil {
		result.SkipReason = err.Error()
		result.Interpretation = "the Manager HTML preflight URL could not be constructed"
		return result
	}
	result.Preflight = requester.Do(ctx, RequestSpec{
		URL:           managerURL,
		Objective:     "authenticate to Tomcat Manager HTML and obtain a session plus CSRF nonce",
		CredentialRef: credential.Ref,
		Credential:    &credential,
	})
	result.Executed = result.Preflight.RequestSent
	if result.Preflight.Error != "" {
		result.SkipReason = "Manager HTML preflight failed: " + result.Preflight.Error
		result.Interpretation = "no deployment request was sent"
		return result
	}
	if result.Preflight.StatusCode < 200 || result.Preflight.StatusCode >= 300 || !managerBody(result.Preflight.body) {
		result.SkipReason = fmt.Sprintf("Manager HTML preflight was not accepted (HTTP %d)", result.Preflight.StatusCode)
		result.Interpretation = "the credential did not obtain an authenticated Manager HTML page; no deployment request was sent"
		return result
	}

	sessionCookies := mergeCookies(nil, result.Preflight.responseCookies)
	result.SessionEstablished = len(sessionCookies) > 0
	csrfToken, tokenFound := extractCSRFToken(result.Preflight.body)
	result.CSRFTokenFound = tokenFound
	if !result.SessionEstablished {
		result.SkipReason = "Manager HTML did not establish a session cookie"
		result.Interpretation = "the CSRF-protected upload was not attempted"
		return result
	}
	if !tokenFound {
		result.SkipReason = "Manager HTML did not expose a valid CSRF nonce"
		result.Interpretation = "the CSRF-protected upload was not attempted"
		return result
	}

	multipartBody, contentType, uploadFilename, err := buildManagerHTMLUpload(artifact)
	if err != nil {
		result.SkipReason = err.Error()
		result.Interpretation = "the static canary multipart body could not be constructed"
		return result
	}
	uploadURL, err := managerHTMLEndpoint(target, "upload", url.Values{
		"path":            []string{strings.TrimPrefix(artifact.ContextPath, "/")},
		csrfParameterName: []string{csrfToken},
	})
	if err != nil {
		result.SkipReason = err.Error()
		result.Interpretation = "the Manager HTML upload URL could not be constructed"
		return result
	}
	result.Deploy = requester.Do(ctx, RequestSpec{
		URL:                    uploadURL,
		Objective:              "upload and deploy the validated non-executable static canary through Tomcat Manager HTML",
		CredentialRef:          credential.Ref,
		Credential:             &credential,
		Method:                 http.MethodPost,
		Body:                   multipartBody,
		ContentType:            contentType,
		Cookies:                sessionCookies,
		MultipartField:         "deployWar",
		UploadFilename:         uploadFilename,
		UploadedArtifactBytes:  len(artifact.Bytes),
		UploadedArtifactSHA256: artifact.SHA256,
	})
	if result.Deploy.Error != "" {
		result.SkipReason = "static canary upload request failed: " + result.Deploy.Error
		result.Interpretation = "deployment was not confirmed; no undeploy request was sent"
		return result
	}
	if !managerHTMLActionSucceeded(result.Deploy) {
		result.SkipReason = fmt.Sprintf("Tomcat Manager HTML did not accept the static canary upload (HTTP %d)", result.Deploy.StatusCode)
		result.Interpretation = "deployment was not confirmed; no undeploy request was sent"
		return result
	}
	result.Deployed = true

	verifyURL, err := BuildEndpoint(target, artifact.ContextPath+"/")
	if err != nil {
		result.Interpretation = "deployment was accepted, but the canary verification URL could not be constructed"
	} else {
		result.Verify = requester.Do(ctx, RequestSpec{
			URL:       verifyURL,
			Objective: "verify the deployed static canary marker without executing server-side code",
		})
		result.Verified = result.Verify.Error == "" &&
			result.Verify.StatusCode >= 200 &&
			result.Verify.StatusCode < 300 &&
			strings.Contains(string(result.Verify.body), artifact.Marker)
	}

	// Refresh the Manager page as Metasploit's tomcat_mgr_upload module does.
	// A successful state-changing POST can rotate either the session or CSRF
	// nonce. Cleanup still falls back to the last valid values if refresh fails.
	cleanupCookies := mergeCookies(sessionCookies, result.Deploy.responseCookies)
	cleanupToken := csrfToken
	if token, ok := extractCSRFToken(result.Deploy.body); ok {
		cleanupToken = token
	}
	result.Refresh = requester.Do(context.Background(), RequestSpec{
		URL:           managerURL,
		Objective:     "refresh the Tomcat Manager HTML session and CSRF nonce before cleanup",
		CredentialRef: credential.Ref,
		Credential:    &credential,
		Cookies:       cleanupCookies,
	})
	if result.Refresh.Error == "" && result.Refresh.StatusCode >= 200 && result.Refresh.StatusCode < 300 {
		cleanupCookies = mergeCookies(cleanupCookies, result.Refresh.responseCookies)
		if token, ok := extractCSRFToken(result.Refresh.body); ok {
			cleanupToken = token
		}
	}

	cleanupURL, cleanupURLErr := managerHTMLEndpoint(target, "undeploy", url.Values{
		"path":            []string{artifact.ContextPath},
		csrfParameterName: []string{cleanupToken},
	})
	if cleanupURLErr == nil && cleanupToken != "" && len(cleanupCookies) > 0 {
		result.CleanupAttempted = true
		result.Undeploy = requester.Do(context.Background(), RequestSpec{
			URL:           cleanupURL,
			Objective:     "undeploy the static canary through Tomcat Manager HTML immediately after validation",
			CredentialRef: credential.Ref,
			Credential:    &credential,
			Method:        http.MethodPost,
			Cookies:       cleanupCookies,
		})
		result.CleanupSucceeded = result.Undeploy.Error == "" && managerHTMLActionSucceeded(result.Undeploy)
	}

	switch {
	case result.Verified && result.CleanupSucceeded:
		result.Classification = Confirmed
		result.Interpretation = "Tomcat Manager HTML accepted the static WAR, served the expected marker, and confirmed undeployment"
	case result.CleanupSucceeded:
		result.Classification = Potential
		result.Interpretation = "Tomcat Manager HTML confirmed deployment and cleanup, but the static marker was not verified"
	case result.CleanupAttempted:
		result.Classification = Potential
		result.Interpretation = "Tomcat Manager HTML accepted deployment, but automatic cleanup was not confirmed; manual review is required"
	default:
		result.Classification = Potential
		result.Interpretation = "Tomcat Manager HTML accepted deployment, but a valid CSRF-protected cleanup request could not be completed; manual review is required"
	}
	return result
}

func managerHTMLEndpoint(target *url.URL, action string, query url.Values) (string, error) {
	suffix := managerPath
	if action != "" {
		suffix += "/" + action
	}
	endpoint, err := BuildEndpoint(target, suffix)
	if err != nil {
		return "", fmt.Errorf("build Manager HTML endpoint: %w", err)
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse Manager HTML endpoint: %w", err)
	}
	if query != nil {
		parsed.RawQuery = query.Encode()
	}
	return parsed.String(), nil
}

func buildManagerHTMLUpload(artifact *CanaryArtifact) ([]byte, string, string, error) {
	if artifact == nil {
		return nil, "", "", fmt.Errorf("build Manager HTML upload: no static canary artifact")
	}
	filename := strings.TrimPrefix(artifact.ContextPath, "/") + ".war"
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("deployWar", filename)
	if err != nil {
		return nil, "", "", fmt.Errorf("build Manager HTML upload field: %w", err)
	}
	if _, err := part.Write(artifact.Bytes); err != nil {
		return nil, "", "", fmt.Errorf("write static canary to Manager HTML upload: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, "", "", fmt.Errorf("finalize Manager HTML upload: %w", err)
	}
	return body.Bytes(), writer.FormDataContentType(), filename, nil
}

func extractCSRFToken(body []byte) (string, bool) {
	search := html.UnescapeString(string(body))
	marker := csrfParameterName + "="
	for {
		index := strings.Index(search, marker)
		if index < 0 {
			return "", false
		}
		candidate := search[index+len(marker):]
		if end := strings.IndexAny(candidate, "&\"'<> \t\r\n"); end >= 0 {
			candidate = candidate[:end]
		}
		if decoded, err := url.QueryUnescape(candidate); err == nil {
			candidate = decoded
		}
		if csrfTokenPattern.MatchString(candidate) {
			return candidate, true
		}
		search = search[index+len(marker):]
	}
}

func mergeCookies(existing []*http.Cookie, updates ...[]*http.Cookie) []*http.Cookie {
	byName := make(map[string]*http.Cookie)
	order := make([]string, 0, len(existing))
	apply := func(cookies []*http.Cookie) {
		for _, cookie := range cookies {
			if cookie == nil || cookie.Name == "" {
				continue
			}
			if cookie.MaxAge < 0 || cookie.Value == "" {
				delete(byName, cookie.Name)
				continue
			}
			if _, seen := byName[cookie.Name]; !seen {
				order = append(order, cookie.Name)
			}
			clone := *cookie
			byName[cookie.Name] = &clone
		}
	}
	apply(existing)
	for _, cookies := range updates {
		apply(cookies)
	}
	result := make([]*http.Cookie, 0, len(byName))
	for _, name := range order {
		if cookie, ok := byName[name]; ok {
			result = append(result, cookie)
		}
	}
	return result
}

func managerHTMLActionSucceeded(probe Probe) bool {
	if probe.StatusCode < 200 || probe.StatusCode >= 300 {
		return false
	}
	lower := strings.ToLower(string(probe.body))
	return !strings.Contains(lower, "fail -") && !strings.Contains(lower, "403 access denied")
}
