package tomcat

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var (
	tomcatSlashVersion = regexp.MustCompile(`(?i)Apache\s+Tomcat(?:/|\s+(?:Version\s+)?)([0-9]+(?:\.[0-9]+){1,3}(?:[-._+A-Za-z0-9]*)?)`)
	tomcatDocsVersion  = regexp.MustCompile(`(?i)Apache\s+Tomcat\s+[0-9]+\s*\(\s*([0-9]+(?:\.[0-9]+){1,3}(?:[-._+A-Za-z0-9]*)?)\s*\)`)
)

func extractEvidence(p Probe) ([]string, []string) {
	var signals []string
	versions := make(map[string]struct{})
	body := string(p.body)
	lowerBody := strings.ToLower(body)
	lowerServer := strings.ToLower(p.Server)
	lowerRealm := strings.ToLower(p.WWWAuthenticate)

	if strings.Contains(lowerServer, "apache-coyote") {
		signals = append(signals, "Server header contains Apache-Coyote")
	}
	if strings.Contains(lowerServer, "apache tomcat") || strings.Contains(lowerServer, "tomcat/") {
		signals = append(signals, "Server header identifies Apache Tomcat")
	}
	if strings.Contains(lowerRealm, "tomcat manager application") || strings.Contains(lowerRealm, "tomcat host manager application") {
		signals = append(signals, "HTTP Basic realm identifies Tomcat Manager")
	}
	if strings.Contains(lowerBody, "apache tomcat/") {
		signals = append(signals, "response body contains an Apache Tomcat/<version> signature")
	}
	if strings.Contains(lowerBody, "<title>apache tomcat") {
		signals = append(signals, "page title identifies Apache Tomcat")
	}
	if strings.Contains(lowerBody, "tomcat documentation") {
		signals = append(signals, "response body identifies the Tomcat documentation")
	}
	if managerBody(p.body) {
		signals = append(signals, "response body identifies the Tomcat Web Application Manager")
	}

	for _, source := range []string{p.Server, body} {
		for _, match := range tomcatDocsVersion.FindAllStringSubmatch(source, -1) {
			versions[match[1]] = struct{}{}
		}
		for _, match := range tomcatSlashVersion.FindAllStringSubmatch(source, -1) {
			versions[match[1]] = struct{}{}
		}
	}

	versionList := make([]string, 0, len(versions))
	for version := range versions {
		versionList = append(versionList, version)
	}
	sort.Strings(versionList)
	return uniqueStrings(signals), versionList
}

func AnalyzeFingerprint(probes []Probe) FingerprintResult {
	result := FingerprintResult{Classification: Unverified}
	versions := make(map[string]struct{})
	confirmed := false
	weakEvidence := false
	for _, probe := range probes {
		for _, signal := range probe.Signals {
			result.Evidence = append(result.Evidence, fmt.Sprintf("%s: %s", probe.URL, signal))
			weakEvidence = true
		}
		if probeConfirmsTomcat(probe) {
			confirmed = true
		}
		for _, version := range probe.DetectedVersions {
			versions[version] = struct{}{}
		}
	}
	if confirmed {
		result.IsTomcat = true
		result.Classification = Confirmed
	} else if weakEvidence {
		result.IsTomcat = true
		result.Classification = Inferred
	}
	for version := range versions {
		result.Versions = append(result.Versions, version)
	}
	sort.Strings(result.Versions)
	result.Versions, result.Evidence = preferSpecificVersions(result.Versions, result.Evidence)
	if len(result.Versions) == 1 {
		result.Version = result.Versions[0]
	} else if len(result.Versions) > 1 {
		result.Version = strings.Join(result.Versions, ", ")
		result.Evidence = append(result.Evidence, "conflicting versions were observed; review proxy and cache behavior")
	}
	result.Evidence = uniqueStrings(result.Evidence)
	return result
}

func preferSpecificVersions(versions, evidence []string) ([]string, []string) {
	if len(versions) < 2 {
		return versions, evidence
	}
	keep := make([]bool, len(versions))
	for index := range keep {
		keep[index] = true
	}
	for index, version := range versions {
		for otherIndex, candidate := range versions {
			if index == otherIndex {
				continue
			}
			if strings.HasPrefix(candidate, version+".") {
				keep[index] = false
				evidence = append(evidence, fmt.Sprintf("less-specific version %s suppressed in favor of %s", version, candidate))
				break
			}
		}
	}
	result := make([]string, 0, len(versions))
	for index, version := range versions {
		if keep[index] {
			result = append(result, version)
		}
	}
	return result, uniqueStrings(evidence)
}

func probeConfirmsTomcat(probe Probe) bool {
	server := strings.ToLower(probe.Server)
	realm := strings.ToLower(probe.WWWAuthenticate)
	body := strings.ToLower(string(probe.body))
	return strings.Contains(server, "apache-coyote") ||
		strings.Contains(server, "apache tomcat") ||
		strings.Contains(server, "tomcat/") ||
		strings.Contains(realm, "tomcat manager application") ||
		strings.Contains(realm, "tomcat host manager application") ||
		strings.Contains(body, "apache tomcat/") ||
		strings.Contains(body, "<title>apache tomcat") ||
		strings.Contains(body, "tomcat web application manager")
}

func managerBody(body []byte) bool {
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "tomcat web application manager") ||
		strings.Contains(lower, "tomcat manager application") ||
		strings.Contains(lower, "<title>tomcat manager")
}

func managerRealm(p Probe) bool {
	realm := strings.ToLower(p.WWWAuthenticate)
	return strings.Contains(realm, "tomcat manager application") ||
		strings.Contains(realm, "tomcat host manager application")
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
