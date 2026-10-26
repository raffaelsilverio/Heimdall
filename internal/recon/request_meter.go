package recon

import (
	"context"
	"errors"
	"net/http"
)

// RequestMeter atomically charges one outbound network attempt. Implementations
// must fail closed before the transport is invoked when authorization or budget
// has changed. Every retry/redirect RoundTrip is charged independently.
type RequestMeter interface {
	ConsumeRequest(context.Context) error
}

// MeteredRoundTripper ensures native HTTP adapters account for each request
// before it reaches the configured transport. It is not suitable for external
// subprocess tools, whose internal requests bypass this layer.
type MeteredRoundTripper struct {
	Meter RequestMeter
	Base  http.RoundTripper
}

func (t MeteredRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil {
		return nil, errors.New("metered HTTP transport received a nil request")
	}
	if t.Meter == nil {
		return nil, errors.New("metered HTTP transport has no request meter")
	}
	if err := t.Meter.ConsumeRequest(request.Context()); err != nil {
		return nil, err
	}
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(request)
}
