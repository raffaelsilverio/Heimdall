package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"
)

type requestLedgerStub struct {
	programID string
	runID     string
	actionID  string
	now       time.Time
	calls     int
	err       error
}

func (s *requestLedgerStub) ConsumeAgentActionRequest(_ context.Context, programID, runID, actionID string, now time.Time) error {
	s.programID, s.runID, s.actionID, s.now = programID, runID, actionID, now
	s.calls++
	return s.err
}

func TestAgentActionRequestMeterChargesLedgerBeforeTransport(t *testing.T) {
	now := time.Date(2026, time.October, 25, 10, 0, 0, 0, time.UTC)
	ledger := &requestLedgerStub{}
	meter := AgentActionRequestMeter{
		Ledger: ledger, ProgramID: " program-a ", RunID: " run-a ", ActionID: " action-a ",
		Now: func() time.Time { return now },
	}
	if err := meter.ConsumeRequest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ledger.calls != 1 || ledger.programID != "program-a" || ledger.runID != "run-a" ||
		ledger.actionID != "action-a" || !ledger.now.Equal(now) {
		t.Fatalf("request meter did not charge its exact action identity: %+v", ledger)
	}
	ledger.err = errors.New("request budget exhausted")
	if err := meter.ConsumeRequest(context.Background()); err == nil || err.Error() != "request budget exhausted" {
		t.Fatalf("request budget rejection was not propagated: %v", err)
	}
}

func TestAgentActionRequestMeterFailsClosedWithoutLedgerIdentity(t *testing.T) {
	if err := (AgentActionRequestMeter{}).ConsumeRequest(context.Background()); err == nil {
		t.Fatal("request meter without a ledger unexpectedly succeeded")
	}
	if err := (AgentActionRequestMeter{Ledger: &requestLedgerStub{}, ProgramID: "program-a"}).ConsumeRequest(context.Background()); err == nil {
		t.Fatal("request meter without full action identity unexpectedly succeeded")
	}
}
