//go:build !darwin && !linux

package recon

// platformAgentExecSandbox returns nil on platforms without a reviewed
// isolation implementation. AgentExecRunner then fails closed instead of
// running an unconfined subprocess.
func platformAgentExecSandbox() agentExecSandbox { return nil }
