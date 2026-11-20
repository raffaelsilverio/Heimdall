package recon

import (
	"net/http"
	"strings"
	"testing"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
)

func TestRequestPolicyMiddlewareAppliesAndRendersTheProfile(t *testing.T) {
	profile := assessment.RequestProfile{
		UserAgent: "Heimdall-Middleware/2.0",
		Headers: []assessment.RequestHeader{
			{Name: "X-Program", Value: "example"},
			{Name: "X-Bug-Bounty", Value: "researcher-one"},
		},
	}
	request, err := http.NewRequest(http.MethodGet, "https://app.example.test/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyRequestProfile(request, profile); err != nil {
		t.Fatal(err)
	}
	if request.Header.Get("User-Agent") != "Heimdall-Middleware/2.0" ||
		request.Header.Get("X-Program") != "example" || request.Header.Get("X-Bug-Bounty") != "researcher-one" {
		t.Fatalf("middleware did not apply the profile: %v", request.Header)
	}
	args, err := RequestProfileHTTPArgs(profile)
	if err != nil {
		t.Fatal(err)
	}
	rendered := strings.Join(args, " ")
	if !strings.Contains(rendered, "-H User-Agent: Heimdall-Middleware/2.0") ||
		!strings.Contains(rendered, "-H X-Bug-Bounty: researcher-one") ||
		!strings.Contains(rendered, "-H X-Program: example") {
		t.Fatalf("rendered profile args are incomplete: %v", args)
	}
}

func TestRequestPolicyMiddlewareRejectsAnUnsafeProfile(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://app.example.test/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyRequestProfile(request, assessment.RequestProfile{
		Headers: []assessment.RequestHeader{{Name: "Authorization", Value: "secret"}},
	})
	if err == nil || !strings.Contains(err.Error(), "managed by the request middleware") {
		t.Fatalf("unsafe profile error = %v", err)
	}
	if request.Header.Get("User-Agent") != "" {
		t.Fatal("unsafe profile was partially applied")
	}
}
