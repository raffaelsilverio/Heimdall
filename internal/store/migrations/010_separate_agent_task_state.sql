DROP INDEX agent_tasks_for_triage;
ALTER TABLE agent_tasks DROP COLUMN triage_status;
ALTER TABLE agent_tasks DROP COLUMN triage_attempts;
ALTER TABLE agent_tasks DROP COLUMN triage_lease_until;
ALTER TABLE agent_tasks DROP COLUMN triaged_at;
ALTER TABLE agent_tasks DROP COLUMN triage_error;
