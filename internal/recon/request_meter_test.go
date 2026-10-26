package recon

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type testRequestMeter struct {
	limit int
	used  int
}

func (m *testRequestMeter) ConsumeRequest(context.Context) error {
	if m.used >= m.limit {
		return errors.New("request budget exhausted")
	}
	m.used++
	return nil
}

type testRoundTripper struct {
	calls int
}

func (r *testRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls++
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok"))}, nil
}

func TestMeteredRoundTripperChargesBeforeEachNetworkAttempt(t *testing.T) {
	meter := &testRequestMeter{limit: 2}
	base := &testRoundTripper{}
	transport := MeteredRoundTripper{Meter: meter, Base: base}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		response, err := transport.RoundTrip(request)
		if err != nil {
			t.Fatalf("request %d failed: %v", attempt+1, err)
		}
		_ = response.Body.Close()
	}
	if _, err := transport.RoundTrip(request); err == nil || err.Error() != "request budget exhausted" {
		t.Fatalf("over-budget request error = %v", err)
	}
	if meter.used != 2 || base.calls != 2 {
		t.Fatalf("request accounting mismatch: meter used=%d transport calls=%d", meter.used, base.calls)
	}
}

func TestMeteredRoundTripperFailsClosedWithoutMeter(t *testing.T) {
	base := &testRoundTripper{}
	transport := MeteredRoundTripper{Base: base}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.RoundTrip(request); err == nil {
		t.Fatal("request was sent without a request meter")
	}
	if base.calls != 0 {
		t.Fatalf("transport was invoked %d times without a meter", base.calls)
	}
}
