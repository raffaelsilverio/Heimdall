package recon

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

// ApplyRequestProfile enforces the program's mandatory User-Agent and headers
// on one outbound HTTP request. It normalizes the profile first so an invalid
// operator configuration fails closed before a request is sent. Header values
// are never logged by this package.
func ApplyRequestProfile(request *http.Request, profile assessment.RequestProfile) error {
	if request == nil {
		return errors.New("request profile middleware requires a request")
	}
	normalized, err := assessment.NormalizeRequestProfile(profile)
	if err != nil {
		return fmt.Errorf("request profile: %w", err)
	}
	request.Header.Set("User-Agent", normalized.UserAgent)
	for _, header := range normalized.Headers {
		request.Header.Set(header.Name, header.Value)
	}
	return nil
}

// RequestProfileHTTPArgs renders the profile as ProjectDiscovery HTTP header
// flags. Values are passed as separate argv entries, never through a shell,
// and the profile validation rejects credential and framing headers.
func RequestProfileHTTPArgs(profile assessment.RequestProfile) ([]string, error) {
	_, args, err := requestProfileForStage("", profile)
	return args, err
}

// requestProfileForStage validates the profile before a stage spawns a tool or
// opens a connection, and renders the mandatory headers for its HTTP requests.
func requestProfileForStage(stage string, profile assessment.RequestProfile) (assessment.RequestProfile, []string, error) {
	normalized, err := assessment.NormalizeRequestProfile(profile)
	if err != nil {
		if stage == "" {
			return assessment.RequestProfile{}, nil, fmt.Errorf("request profile: %w", err)
		}
		return assessment.RequestProfile{}, nil, fmt.Errorf("%s stage request profile: %w", stage, err)
	}
	args := make([]string, 0, 2*(len(normalized.Headers)+1))
	args = append(args, "-H", "User-Agent: "+normalized.UserAgent)
	for _, header := range normalized.Headers {
		args = append(args, "-H", header.Name+": "+header.Value)
	}
	return normalized, args, nil
}

// requestProfileFingerprint is a deterministic digest of the mandatory
// headers, used to make a profile change a material change for a stage.
func requestProfileFingerprint(profile assessment.RequestProfile) string {
	normalized, err := assessment.NormalizeRequestProfile(profile)
	if err != nil {
		return "invalid"
	}
	material := normalized.UserAgent
	for _, header := range normalized.Headers {
		material += "\n" + header.Name + ":" + header.Value
	}
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:8])
}

// RequestProfileSummary is safe for logs and persisted metadata: it exposes
// only the revision and header count, never a header value.
func RequestProfileSummary(profile assessment.RequestProfile) string {
	return fmt.Sprintf("revision=%d headers=%d", profile.RevisionOrDefault(), len(profile.Headers))
}
