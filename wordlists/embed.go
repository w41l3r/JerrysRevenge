// Package wordlists exposes the small, auditable credential corpus bundled
// with Jerry's Revenge. Operators can inspect the exact candidates in the
// adjacent text file before authorizing a validation run.
package wordlists

import _ "embed"

// TomcatCommon contains one username:password candidate per non-comment line.
//
//go:embed tomcat-common.txt
var TomcatCommon string
