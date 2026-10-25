package recon

import (
	"os"
	"sort"
	"strings"
)

func safeToolEnvironment() []string {
	allowed := map[string]struct{}{
		"HOME": {}, "PATH": {}, "LANG": {}, "LC_ALL": {}, "TMPDIR": {}, "TZ": {}, "USER": {}, "LOGNAME": {},
	}
	values := make([]string, 0, len(allowed))
	for _, item := range os.Environ() {
		key, _, found := strings.Cut(item, "=")
		if !found {
			continue
		}
		if _, ok := allowed[key]; ok {
			values = append(values, item)
			delete(allowed, key)
		}
	}
	if _, ok := allowed["HOME"]; ok {
		if home, err := os.UserHomeDir(); err == nil {
			values = append(values, "HOME="+home)
		}
	}
	if _, ok := allowed["TMPDIR"]; ok {
		values = append(values, "TMPDIR="+os.TempDir())
	}
	sort.Strings(values)
	return values
}
