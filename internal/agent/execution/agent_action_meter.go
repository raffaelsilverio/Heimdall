package execution

import (
	"context"
	"errors"
	"strings"
	"time"
)

type AgentActionRequestLedger interface {
	ConsumeAgentActionRequest(context.Context, string, string, string, time.Time) error
}

// AgentActionRequestMeter adapts the durable ledger to native recon HTTP
// transports. A fresh ledger charge is required before every RoundTrip.
type AgentActionRequestMeter struct {
	Ledger    AgentActionRequestLedger
	ProgramID string
	RunID     string
	ActionID  string
	Now       func() time.Time
}

func (m AgentActionRequestMeter) ConsumeRequest(ctx context.Context) error {
	if m.Ledger == nil {
		return errors.New("agent action request meter has no durable ledger")
	}
	programID := strings.TrimSpace(m.ProgramID)
	runID := strings.TrimSpace(m.RunID)
	actionID := strings.TrimSpace(m.ActionID)
	if programID == "" || runID == "" || actionID == "" {
		return errors.New("agent action request meter is missing its program, run, or action identity")
	}
	now := time.Now().UTC()
	if m.Now != nil {
		now = m.Now().UTC()
	}
	return m.Ledger.ConsumeAgentActionRequest(ctx, programID, runID, actionID, now)
}
