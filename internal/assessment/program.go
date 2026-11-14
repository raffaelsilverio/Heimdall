package assessment

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ProgramStatus string

const (
	ProgramDraft  ProgramStatus = "draft"
	ProgramActive ProgramStatus = "active"
	ProgramPaused ProgramStatus = "paused"
)

type ScopeType string

const (
	ScopeDomain         ScopeType = "domain"
	ScopeWildcardDomain ScopeType = "wildcard_domain"
	ScopeURL            ScopeType = "url"
	ScopeIP             ScopeType = "ip"
	ScopeCIDR           ScopeType = "cidr"
)

type ScopeEffect string

const (
	ScopeInclude ScopeEffect = "include"
	ScopeExclude ScopeEffect = "exclude"
)

type ScopeEntry struct {
	Effect ScopeEffect `json:"effect"`
	Type   ScopeType   `json:"type"`
	Value  string      `json:"value"`
	Ports  []uint16    `json:"ports,omitempty"`
}

type Scope struct {
	Entries []ScopeEntry `json:"entries"`
}

type Program struct {
	ID                     string
	Name                   string
	SourcePlatform         string
	SourceURL              string
	Status                 ProgramStatus
	AuthorizationReference string
	ExpiresAt              time.Time
	Scope                  Scope
	ScopeHash              string
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

func NormalizeScope(scope Scope) (Scope, error) {
	if len(scope.Entries) == 0 {
		return Scope{}, errors.New("at least one scope entry is required")
	}

	entries := make([]ScopeEntry, 0, len(scope.Entries))
	seen := make(map[string]struct{}, len(scope.Entries))
	hasInclude := false
	for _, entry := range scope.Entries {
		if entry.Effect == "" {
			entry.Effect = ScopeInclude
		}
		if entry.Effect != ScopeInclude && entry.Effect != ScopeExclude {
			return Scope{}, fmt.Errorf("invalid scope effect %q", entry.Effect)
		}
		if entry.Effect == ScopeInclude {
			hasInclude = true
		}

		value, err := normalizeScopeValue(entry.Type, entry.Value)
		if err != nil {
			return Scope{}, fmt.Errorf("invalid %s scope %q: %w", entry.Type, entry.Value, err)
		}
		entry.Value = value
		for _, port := range entry.Ports {
			if port == 0 {
				return Scope{}, errors.New("scope ports must be between 1 and 65535")
			}
		}
		entry.Ports = normalizePorts(entry.Ports)
		key := string(entry.Effect) + "\x00" + string(entry.Type) + "\x00" + entry.Value + "\x00" + fmt.Sprint(entry.Ports)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		entries = append(entries, entry)
	}
	if !hasInclude {
		return Scope{}, errors.New("scope must contain at least one inclusion")
	}

	sort.Slice(entries, func(i, j int) bool {
		left := fmt.Sprintf("%s:%s:%s:%v", entries[i].Effect, entries[i].Type, entries[i].Value, entries[i].Ports)
		right := fmt.Sprintf("%s:%s:%s:%v", entries[j].Effect, entries[j].Type, entries[j].Value, entries[j].Ports)
		return left < right
	})
	return Scope{Entries: entries}, nil
}

func ScopeFingerprint(scope Scope) (string, error) {
	normalized, err := NormalizeScope(scope)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("encode scope: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func (s Scope) AllowsHost(host string) bool {
	normalizedHost, err := NormalizeHost(host)
	if err != nil {
		return false
	}
	host = normalizedHost

	allowed := false
	for _, entry := range s.Entries {
		if !scopeEntryMatchesHost(entry, host) {
			continue
		}
		if entry.Effect == ScopeExclude {
			if entry.Type == ScopeURL || len(entry.Ports) > 0 {
				continue
			}
			return false
		}
		if entry.Effect == ScopeInclude {
			allowed = true
		}
	}
	return allowed
}

func (s Scope) AllowsURL(rawURL string) bool {
	parsed, host, port, valid := parseScopedURL(rawURL)
	return valid && s.allowsParsedURL(parsed, host, port)
}

func parseScopedURL(rawURL string) (*url.URL, string, uint16, bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
		return nil, "", 0, false
	}
	host, err := NormalizeHost(parsed.Hostname())
	if err != nil {
		return nil, "", 0, false
	}
	port := effectivePort(parsed)
	if port == 0 {
		return nil, "", 0, false
	}
	return parsed, host, port, true
}

func (s Scope) allowsParsedURL(parsed *url.URL, host string, port uint16) bool {
	allowed := false
	for _, entry := range s.Entries {
		if !scopeEntryMatchesHost(entry, host) || !portAllowed(entry.Ports, port) {
			continue
		}
		if entry.Effect == ScopeExclude {
			if entry.Type != ScopeURL || pathMatches(parsed.Path, entry.Value) {
				return false
			}
			continue
		}
		if entry.Effect != ScopeInclude {
			continue
		}
		if entry.Type == ScopeURL && !urlEntryMatches(parsed, entry.Value) {
			continue
		}
		allowed = true
	}
	return allowed
}

// AllowsActiveURL requires explicit port authorization for domain/IP/CIDR
// entries. A URL entry authorizes only its scheme, effective port, and path.
func (s Scope) AllowsActiveURL(rawURL string) bool {
	parsed, host, port, valid := parseScopedURL(rawURL)
	if !valid || !s.allowsParsedURL(parsed, host, port) {
		return false
	}
	for _, entry := range s.Entries {
		if entry.Effect != ScopeInclude || !scopeEntryMatchesHost(entry, host) {
			continue
		}
		if entry.Type == ScopeURL {
			if urlEntryMatches(parsed, entry.Value) && (len(entry.Ports) == 0 || portAllowed(entry.Ports, port)) {
				return true
			}
			continue
		}
		if len(entry.Ports) > 0 && portAllowed(entry.Ports, port) {
			return true
		}
	}
	return false
}

func (s Scope) ActiveURLsForHost(host string) []string {
	host, err := NormalizeHost(host)
	if err != nil || !s.AllowsHost(host) {
		return nil
	}
	targets := make(map[string]struct{})
	for _, entry := range s.Entries {
		if entry.Effect != ScopeInclude || !scopeEntryMatchesHost(entry, host) {
			continue
		}
		if entry.Type == ScopeURL {
			parsed, err := url.Parse(entry.Value)
			if err != nil {
				continue
			}
			parsed.RawQuery = ""
			parsed.ForceQuery = false
			parsed.Fragment = ""
			target := parsed.String()
			if s.AllowsActiveURL(target) {
				targets[target] = struct{}{}
			}
			continue
		}
		for _, port := range entry.Ports {
			scheme := "http"
			if port == 443 {
				scheme = "https"
			}
			urlHost := host
			if strings.Contains(host, ":") {
				urlHost = "[" + host + "]"
			}
			target := fmt.Sprintf("%s://%s", scheme, urlHost)
			if (scheme == "http" && port != 80) || (scheme == "https" && port != 443) {
				target = fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, strconv.Itoa(int(port))))
			}
			if s.AllowsActiveURL(target) {
				targets[target] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(targets))
	for target := range targets {
		result = append(result, target)
	}
	sort.Strings(result)
	return result
}

func (s Scope) AllowedPortsForHost(host string) []uint16 {
	host, err := NormalizeHost(host)
	if err != nil {
		return nil
	}
	allowed := make(map[uint16]struct{})
	for _, entry := range s.Entries {
		if entry.Type == ScopeURL || entry.Effect != ScopeInclude || !scopeEntryMatchesHost(entry, host) {
			continue
		}
		for _, port := range entry.Ports {
			allowed[port] = struct{}{}
		}
	}
	for _, entry := range s.Entries {
		if entry.Type == ScopeURL || entry.Effect != ScopeExclude || !scopeEntryMatchesHost(entry, host) {
			continue
		}
		if len(entry.Ports) == 0 {
			return nil
		}
		for _, port := range entry.Ports {
			delete(allowed, port)
		}
	}
	ports := make([]uint16, 0, len(allowed))
	for port := range allowed {
		ports = append(ports, port)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports
}

func (s Scope) AllowsActivePort(host string, port uint16) bool {
	if port == 0 {
		return false
	}
	for _, allowed := range s.AllowedPortsForHost(host) {
		if allowed == port {
			return true
		}
	}
	return false
}

func (s Scope) HasURLExclusionForHost(host string) bool {
	host, err := NormalizeHost(host)
	if err != nil {
		return false
	}
	for _, entry := range s.Entries {
		if entry.Effect != ScopeExclude || entry.Type != ScopeURL {
			continue
		}
		parsed, err := url.Parse(entry.Value)
		if err == nil && normalizeHost(parsed.Hostname()) == host {
			return true
		}
	}
	return false
}

func NormalizeHost(value string) (string, error) {
	host := normalizeHost(value)
	if host == "" {
		return "", errors.New("host is required")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if address.Zone() != "" {
			return "", errors.New("IPv6 zone identifiers are not valid program scope")
		}
		return address.Unmap().String(), nil
	}
	return normalizeDomain(host)
}

func (s Scope) DiscoveryDomains() []string {
	set := make(map[string]struct{})
	for _, entry := range s.Entries {
		if entry.Effect != ScopeInclude {
			continue
		}
		switch entry.Type {
		case ScopeDomain, ScopeWildcardDomain:
			set[entry.Value] = struct{}{}
		case ScopeURL:
			parsed, err := url.Parse(entry.Value)
			if err == nil {
				set[normalizeHost(parsed.Hostname())] = struct{}{}
			}
		}
	}
	domains := make([]string, 0, len(set))
	for domain := range set {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains
}

func scopeEntryMatchesHost(entry ScopeEntry, host string) bool {
	switch entry.Type {
	case ScopeDomain:
		return host == entry.Value
	case ScopeWildcardDomain:
		return strings.HasSuffix(host, "."+entry.Value) && host != entry.Value
	case ScopeURL:
		parsed, err := url.Parse(entry.Value)
		return err == nil && normalizeHost(parsed.Hostname()) == host
	case ScopeIP:
		address, err := netip.ParseAddr(host)
		if err != nil {
			return false
		}
		return address.Unmap().String() == entry.Value
	case ScopeCIDR:
		prefix, err := netip.ParsePrefix(entry.Value)
		if err != nil {
			return false
		}
		address, err := netip.ParseAddr(host)
		return err == nil && prefix.Contains(address.Unmap())
	default:
		return false
	}
}

func portAllowed(ports []uint16, port uint16) bool {
	if len(ports) == 0 {
		return true
	}
	for _, allowed := range ports {
		if allowed == port {
			return true
		}
	}
	return false
}

func effectivePort(parsed *url.URL) uint16 {
	if value := parsed.Port(); value != "" {
		port, err := strconv.ParseUint(value, 10, 16)
		if err == nil && port > 0 {
			return uint16(port)
		}
		return 0
	}
	if strings.EqualFold(parsed.Scheme, "https") {
		return 443
	}
	if strings.EqualFold(parsed.Scheme, "http") {
		return 80
	}
	return 0
}

func urlEntryMatches(target *url.URL, scopeValue string) bool {
	scopeURL, err := url.Parse(scopeValue)
	if err != nil || !strings.EqualFold(target.Scheme, scopeURL.Scheme) ||
		normalizeHost(target.Hostname()) != normalizeHost(scopeURL.Hostname()) || effectivePort(target) != effectivePort(scopeURL) {
		return false
	}
	return pathMatches(target.Path, scopeURL.Path)
}

func pathMatches(targetPath, scopeValue string) bool {
	scopeURL, err := url.Parse(scopeValue)
	if err != nil {
		return false
	}
	scopePath := scopeURL.Path
	if scopePath == "" {
		scopePath = "/"
	}
	if targetPath == "" {
		targetPath = "/"
	}
	if scopePath == "/" {
		return strings.HasPrefix(targetPath, "/")
	}
	if strings.HasSuffix(scopePath, "/") {
		return strings.HasPrefix(targetPath, scopePath)
	}
	return targetPath == scopePath || strings.HasPrefix(targetPath, scopePath+"/")
}
