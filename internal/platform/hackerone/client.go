package hackerone

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

const (
	apiBaseURL              = "https://api.hackerone.com"
	maxResponseBytes        = 8 << 20
	maxSnapshotBytes        = 32 << 20
	maxPaginatedScopeAssets = 10_000
	pageSize                = 100
	scopeRequestInterval    = 1300 * time.Millisecond
)

// Client reads HackerOne's documented Hacker API. It only uses fixed API
// endpoints; the program URL is parsed for its handle and is never fetched.
type Client struct {
	username  string
	token     string
	http      *http.Client
	baseURL   string
	pageDelay time.Duration
}

func NewClientFromEnv() (*Client, error) {
	username := strings.TrimSpace(os.Getenv("HEIMDALL_HACKERONE_API_USERNAME"))
	token := strings.TrimSpace(os.Getenv("HEIMDALL_HACKERONE_API_TOKEN"))
	if username == "" || token == "" {
		return nil, errors.New("set HEIMDALL_HACKERONE_API_USERNAME and HEIMDALL_HACKERONE_API_TOKEN to use the HackerOne API")
	}
	return NewClient(username, token)
}

func NewClient(username, token string) (*Client, error) {
	username = strings.TrimSpace(username)
	token = strings.TrimSpace(token)
	if username == "" || token == "" {
		return nil, errors.New("HackerOne API username and token are required")
	}
	return &Client{
		username: username,
		token:    token,
		http: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		baseURL:   apiBaseURL,
		pageDelay: scopeRequestInterval,
	}, nil
}

// ProgramSource is the stable, reviewable subset of the HackerOne program
// response. User-specific counters and timestamps are intentionally omitted
// so they do not create false scope revisions.
type ProgramSource struct {
	Handle          string `json:"handle"`
	Name            string `json:"name"`
	Policy          string `json:"policy"`
	State           string `json:"state"`
	SubmissionState string `json:"submission_state"`
	OpenScope       *bool  `json:"open_scope"`
	OffersBounties  *bool  `json:"offers_bounties"`
}

type StructuredScope struct {
	ID                         string `json:"id"`
	AssetType                  string `json:"asset_type"`
	AssetIdentifier            string `json:"asset_identifier"`
	EligibleForSubmission      *bool  `json:"eligible_for_submission"`
	EligibleForBounty          *bool  `json:"eligible_for_bounty"`
	Instruction                string `json:"instruction"`
	MaxSeverity                string `json:"max_severity"`
	ConfidentialityRequirement string `json:"confidentiality_requirement"`
	IntegrityRequirement       string `json:"integrity_requirement"`
	AvailabilityRequirement    string `json:"availability_requirement"`
}

type ScopeExclusion struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Details  string `json:"details"`
}

type SourceData struct {
	SchemaVersion    int               `json:"schema_version"`
	Program          ProgramSource     `json:"program"`
	StructuredScopes []StructuredScope `json:"structured_scopes"`
	ScopeExclusions  []ScopeExclusion  `json:"scope_exclusions"`
}

type Snapshot struct {
	SourceData SourceData
	Scope      *assessment.Scope
	Warnings   []string
	Blockers   []string
}

func (s Snapshot) SourceJSON() ([]byte, error) {
	encoded, err := json.Marshal(s.SourceData)
	if err != nil {
		return nil, fmt.Errorf("encode HackerOne source snapshot: %w", err)
	}
	if len(encoded) > maxSnapshotBytes {
		return nil, fmt.Errorf("HackerOne source snapshot exceeds %d bytes", maxSnapshotBytes)
	}
	return encoded, nil
}

func (s Snapshot) SourceHash() (string, error) {
	encoded, err := s.SourceJSON()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func (c *Client) FetchSnapshot(ctx context.Context, sourceURL string) (Snapshot, error) {
	handle, err := programHandle(sourceURL)
	if err != nil {
		return Snapshot{}, err
	}
	program, err := c.fetchProgram(ctx, handle)
	if err != nil {
		return Snapshot{}, err
	}
	if !strings.EqualFold(program.Handle, handle) {
		return Snapshot{}, fmt.Errorf("HackerOne API returned a different program handle")
	}

	scopes, err := c.fetchStructuredScopes(ctx, handle)
	if err != nil {
		return Snapshot{}, err
	}
	exclusions, err := c.fetchScopeExclusions(ctx, handle)
	if err != nil {
		return Snapshot{}, err
	}

	data := SourceData{
		SchemaVersion:    1,
		Program:          program,
		StructuredScopes: scopes,
		ScopeExclusions:  exclusions,
	}
	return buildSnapshot(data), nil
}

func programHandle(sourceURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(sourceURL))
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery {
		return "", errors.New("HackerOne source must be an absolute HTTPS program URL without credentials or query parameters")
	}
	if port := parsed.Port(); port != "" && port != "443" {
		return "", errors.New("HackerOne source URL must use the standard HTTPS port")
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host != "hackerone.com" && host != "www.hackerone.com" {
		return "", errors.New("HackerOne source URL must use hackerone.com")
	}
	path := strings.Trim(parsed.EscapedPath(), "/")
	if path == "" || strings.Contains(path, "/") {
		return "", errors.New("HackerOne program URL must have a single handle path segment")
	}
	handle, err := url.PathUnescape(path)
	if err != nil || handle == "" {
		return "", errors.New("HackerOne program URL has an invalid handle")
	}
	for _, char := range handle {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_') {
			return "", errors.New("HackerOne program handle contains unsupported characters")
		}
	}
	return handle, nil
}

type apiProgram struct {
	Attributes struct {
		Handle          string `json:"handle"`
		Name            string `json:"name"`
		Policy          string `json:"policy"`
		State           string `json:"state"`
		SubmissionState string `json:"submission_state"`
		OpenScope       *bool  `json:"open_scope"`
		OffersBounties  *bool  `json:"offers_bounties"`
	} `json:"attributes"`
}

type apiStructuredScope struct {
	ID         flexibleID `json:"id"`
	Attributes struct {
		AssetType                  string `json:"asset_type"`
		AssetIdentifier            string `json:"asset_identifier"`
		EligibleForSubmission      *bool  `json:"eligible_for_submission"`
		EligibleForBounty          *bool  `json:"eligible_for_bounty"`
		Instruction                string `json:"instruction"`
		MaxSeverity                string `json:"max_severity"`
		ConfidentialityRequirement string `json:"confidentiality_requirement"`
		IntegrityRequirement       string `json:"integrity_requirement"`
		AvailabilityRequirement    string `json:"availability_requirement"`
	} `json:"attributes"`
}

type apiScopeExclusion struct {
	ID         flexibleID `json:"id"`
	Attributes struct {
		Category string `json:"category"`
		Details  string `json:"details"`
	} `json:"attributes"`
}

type flexibleID string

func (id *flexibleID) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		*id = flexibleID(text)
		return nil
	}
	var number json.Number
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err != nil {
		return errors.New("resource id must be a string or number")
	}
	*id = flexibleID(number.String())
	return nil
}

func (c *Client) fetchProgram(ctx context.Context, handle string) (ProgramSource, error) {
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	path := "/v1/hackers/programs/" + url.PathEscape(handle)
	if err := c.getJSON(ctx, path, nil, &envelope); err != nil {
		return ProgramSource{}, err
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return ProgramSource{}, errors.New("HackerOne API returned an empty program response")
	}
	var response apiProgram
	if err := json.Unmarshal(envelope.Data, &response); err != nil {
		return ProgramSource{}, fmt.Errorf("decode HackerOne program response: %w", err)
	}
	return ProgramSource{
		Handle:          response.Attributes.Handle,
		Name:            response.Attributes.Name,
		Policy:          response.Attributes.Policy,
		State:           response.Attributes.State,
		SubmissionState: response.Attributes.SubmissionState,
		OpenScope:       response.Attributes.OpenScope,
		OffersBounties:  response.Attributes.OffersBounties,
	}, nil
}

func (c *Client) fetchStructuredScopes(ctx context.Context, handle string) ([]StructuredScope, error) {
	var scopes []StructuredScope
	for page := 1; ; page++ {
		if page > 1 && c.pageDelay > 0 {
			if err := waitContext(ctx, c.pageDelay); err != nil {
				return nil, err
			}
		}
		query := url.Values{"page[number]": {strconv.Itoa(page)}, "page[size]": {strconv.Itoa(pageSize)}}
		var records []apiStructuredScope
		if err := c.getList(ctx, "/v1/hackers/programs/"+url.PathEscape(handle)+"/structured_scopes", query, &records); err != nil {
			return nil, err
		}
		if len(scopes)+len(records) > maxPaginatedScopeAssets {
			return nil, fmt.Errorf("HackerOne program exceeds the documented %d-item structured-scope pagination limit", maxPaginatedScopeAssets)
		}
		for _, record := range records {
			if record.ID == "" {
				return nil, errors.New("HackerOne structured scope is missing its id")
			}
			scopes = append(scopes, StructuredScope{
				ID:                         string(record.ID),
				AssetType:                  strings.TrimSpace(record.Attributes.AssetType),
				AssetIdentifier:            strings.TrimSpace(record.Attributes.AssetIdentifier),
				EligibleForSubmission:      record.Attributes.EligibleForSubmission,
				EligibleForBounty:          record.Attributes.EligibleForBounty,
				Instruction:                record.Attributes.Instruction,
				MaxSeverity:                record.Attributes.MaxSeverity,
				ConfidentialityRequirement: record.Attributes.ConfidentialityRequirement,
				IntegrityRequirement:       record.Attributes.IntegrityRequirement,
				AvailabilityRequirement:    record.Attributes.AvailabilityRequirement,
			})
		}
		if len(records) < pageSize {
			break
		}
	}
	sort.Slice(scopes, func(i, j int) bool { return scopes[i].ID < scopes[j].ID })
	return scopes, nil
}

func (c *Client) fetchScopeExclusions(ctx context.Context, handle string) ([]ScopeExclusion, error) {
	var records []apiScopeExclusion
	if err := c.getList(ctx, "/v1/hackers/programs/"+url.PathEscape(handle)+"/scope_exclusions", nil, &records); err != nil {
		return nil, err
	}
	if len(records) > maxPaginatedScopeAssets {
		return nil, fmt.Errorf("HackerOne program has more than %d scope-exclusion records", maxPaginatedScopeAssets)
	}
	exclusions := make([]ScopeExclusion, 0, len(records))
	for _, record := range records {
		if record.ID == "" {
			return nil, errors.New("HackerOne scope exclusion is missing its id")
		}
		exclusions = append(exclusions, ScopeExclusion{
			ID:       string(record.ID),
			Category: strings.TrimSpace(record.Attributes.Category),
			Details:  strings.TrimSpace(record.Attributes.Details),
		})
	}
	sort.Slice(exclusions, func(i, j int) bool { return exclusions[i].ID < exclusions[j].ID })
	return exclusions, nil
}

func (c *Client) getList(ctx context.Context, path string, query url.Values, destination any) error {
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := c.getJSON(ctx, path, query, &envelope); err != nil {
		return err
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return errors.New("HackerOne API returned an invalid list response")
	}
	if err := json.Unmarshal(envelope.Data, destination); err != nil {
		return fmt.Errorf("decode HackerOne list response: %w", err)
	}
	return nil
}

func (c *Client) getJSON(ctx context.Context, path string, query url.Values, destination any) error {
	endpoint, err := url.Parse(c.baseURL)
	if err != nil {
		return errors.New("invalid HackerOne API endpoint configuration")
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + path
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return fmt.Errorf("create HackerOne API request: %w", err)
	}
	request.SetBasicAuth(c.username, c.token)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "Heimdall-source-sync")
	response, err := c.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("request HackerOne API %s: %w", path, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("HackerOne API %s returned HTTP %d", path, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read HackerOne API %s response: %w", path, err)
	}
	if len(body) > maxResponseBytes {
		return fmt.Errorf("HackerOne API %s response exceeds %d bytes", path, maxResponseBytes)
	}
	if err := json.Unmarshal(body, destination); err != nil {
		return fmt.Errorf("decode HackerOne API %s response: %w", path, err)
	}
	return nil
}

func waitContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func buildSnapshot(data SourceData) Snapshot {
	snapshot := Snapshot{SourceData: data}
	if data.Program.OpenScope == nil {
		snapshot.Blockers = append(snapshot.Blockers, "HackerOne omitted open_scope; completeness of the finite asset list cannot be confirmed")
	} else if *data.Program.OpenScope {
		snapshot.Blockers = append(snapshot.Blockers, "HackerOne marks this program as open scope; Heimdall will not synthesize an unrestricted scope")
	}

	entries := make([]assessment.ScopeEntry, 0, len(data.StructuredScopes))
	for _, asset := range data.StructuredScopes {
		if asset.EligibleForSubmission == nil {
			snapshot.Blockers = append(snapshot.Blockers, fmt.Sprintf("asset %s has no eligible_for_submission value", asset.ID))
			continue
		}
		kind, value, err := mapAsset(asset)
		if err != nil {
			snapshot.Blockers = append(snapshot.Blockers, fmt.Sprintf("asset %s (%s): %s", asset.ID, asset.AssetType, err))
			continue
		}
		effect := assessment.ScopeInclude
		if !*asset.EligibleForSubmission {
			effect = assessment.ScopeExclude
		}
		entries = append(entries, assessment.ScopeEntry{Effect: effect, Type: kind, Value: value})
	}

	if len(entries) == 0 {
		snapshot.Blockers = append(snapshot.Blockers, "HackerOne returned no assets that Heimdall can represent as a finite scope")
	} else if scope, err := assessment.NormalizeScope(assessment.Scope{Entries: entries}); err != nil {
		snapshot.Blockers = append(snapshot.Blockers, "could not normalize HackerOne assets: "+err.Error())
	} else {
		snapshot.Scope = &scope
	}
	snapshot.Warnings = append(snapshot.Warnings,
		"HackerOne scope_exclusions are report-category exclusions, not excluded assets; they are saved as policy metadata only",
		"HackerOne structured scopes do not authorize ports for domain/IP/CIDR entries; add --port explicitly during approval if those ports are authorized")
	snapshot.Blockers = uniqueSorted(snapshot.Blockers)
	snapshot.Warnings = uniqueSorted(snapshot.Warnings)
	return snapshot
}

func mapAsset(asset StructuredScope) (assessment.ScopeType, string, error) {
	value := strings.TrimSpace(asset.AssetIdentifier)
	if value == "" {
		return "", "", errors.New("asset_identifier is empty")
	}
	switch strings.ToLower(strings.TrimSpace(asset.AssetType)) {
	case "url":
		parsed, err := url.Parse(value)
		if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
			return "", "", errors.New("URL asset is not an absolute HTTP(S) URL")
		}
		if parsed.RawQuery != "" || parsed.ForceQuery {
			return "", "", errors.New("URL asset contains a query; Heimdall cannot safely enforce query-specific scope")
		}
		if strings.Contains(parsed.Hostname(), "*") {
			return "", "", errors.New("URL asset uses a wildcard hostname that Heimdall cannot safely represent as a URL scope")
		}
		if strings.Contains(parsed.Path, "*") {
			return "", "", errors.New("URL asset uses a wildcard path that Heimdall cannot safely represent")
		}
		return assessment.ScopeURL, value, nil
	case "wildcard", "wildcard_domain":
		return assessment.ScopeWildcardDomain, value, nil
	case "domain", "hostname", "fqdn":
		return assessment.ScopeDomain, value, nil
	case "ip", "ip_address", "ipv4", "ipv6":
		return assessment.ScopeIP, value, nil
	case "cidr", "ip_range", "ip_address_range":
		return assessment.ScopeCIDR, value, nil
	default:
		return "", "", errors.New("asset type is not supported by Heimdall's current web scope model")
	}
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	values = append([]string(nil), values...)
	sort.Strings(values)
	unique := values[:0]
	for _, value := range values {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	return unique
}
