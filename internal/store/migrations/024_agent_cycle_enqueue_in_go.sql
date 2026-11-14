-- Adaptive cycle jobs are now enqueued by the store in Go, so they share the
-- caller's clock and remain deterministic in tests. Consent, authorization,
-- scope, policy, and quota validation remains authoritative in
-- ClaimAgentCycleJobs.
DROP TRIGGER IF EXISTS enqueue_consented_agent_cycle;
