package assessment

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"
)

func normalizeScopeValue(kind ScopeType, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("value is required")
	}
	switch kind {
	case ScopeDomain:
		if strings.Contains(value, "*") {
			return "", errors.New("wildcards must use wildcard_domain type")
		}
		return normalizeDomain(value)
	case ScopeWildcardDomain:
		value = strings.TrimPrefix(value, "*.")
		if strings.Contains(value, "*") {
			return "", errors.New("only a leading '*.' wildcard is supported")
		}
		return normalizeDomain(value)
	case ScopeURL:
		return normalizeScopeURL(value)
	case ScopeIP:
		address, err := netip.ParseAddr(value)
		if err != nil {
			return "", err
		}
		return address.Unmap().String(), nil
	case ScopeCIDR:
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return "", err
		}
		return prefix.Masked().String(), nil
	default:
		return "", fmt.Errorf("unsupported scope type %q", kind)
	}
}

func normalizeScopeURL(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", errors.New("URL must be an absolute http or https URL")
	}
	if parsed.User != nil {
		return "", errors.New("URL credentials are not allowed in scope")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	parsed.Fragment = ""
	return parsed.String(), nil
}

func normalizeDomain(value string) (string, error) {
	value = normalizeHost(value)
	if value == "" || strings.Contains(value, "/") || strings.Contains(value, ":") {
		return "", errors.New("expected a DNS name")
	}
	if net.ParseIP(value) != nil {
		return "", errors.New("IP addresses must use ip or cidr scope type")
	}
	if len(value) > 253 {
		return "", errors.New("DNS name exceeds 253 characters")
	}
	if err := validateDomainLabels(value); err != nil {
		return "", err
	}
	return value, nil
}

func validateDomainLabels(value string) error {
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid DNS label")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return errors.New("DNS names must use ASCII letters, digits, and hyphens")
			}
		}
	}
	return nil
}

func normalizeHost(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimSuffix(value, ".")
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	return strings.Trim(value, "[]")
}

func normalizePorts(ports []uint16) []uint16 {
	if len(ports) == 0 {
		return nil
	}
	result := append([]uint16(nil), ports...)
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	unique := result[:0]
	for _, port := range result {
		if port == 0 || (len(unique) > 0 && unique[len(unique)-1] == port) {
			continue
		}
		unique = append(unique, port)
	}
	return unique
}
