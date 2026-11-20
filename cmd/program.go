package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/raffaelsilverio/Heimdall/internal/assessment"
	"github.com/raffaelsilverio/Heimdall/internal/recon"
	"github.com/raffaelsilverio/Heimdall/internal/schedule"
	"github.com/raffaelsilverio/Heimdall/internal/store"
	"github.com/spf13/cobra"
)

func newProgramCommand() *cobra.Command {
	command := &cobra.Command{Use: "program", Short: "Manage authorized programs"}
	command.AddCommand(newProgramAddCommand(), newProgramListCommand(), newProgramShowCommand(), newProgramActivateCommand(), newProgramPauseCommand(), newProgramSourceCommand(), newProgramPolicyCommand(), newProgramAutomationCommand(), newProgramRequestProfileCommand(), newProgramAccountsCommand(), newProgramDataAccessCommand())
	return command
}

func newProgramAddCommand() *cobra.Command {
	var authorizationReference string
	var sourcePlatform string
	var programURL string
	var expiresAtValue string
	var timezone string
	var domains, wildcardDomains, urls, ips, cidrs []string
	var excludedDomains, excludedWildcards, excludedURLs, excludedIPs, excludedCIDRs []string
	var includePorts, excludePorts []string
	command := &cobra.Command{
		Use:   "add <name>",
		Short: "Create a program with an OSINT schedule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			expiresAt, err := time.Parse(time.RFC3339, expiresAtValue)
			if err != nil {
				return fmt.Errorf("parse --expires-at as RFC3339: %w", err)
			}
			scope := assessment.Scope{Entries: make([]assessment.ScopeEntry, 0)}
			appendEntries := func(effect assessment.ScopeEffect, kind assessment.ScopeType, values []string) {
				for _, value := range values {
					scope.Entries = append(scope.Entries, assessment.ScopeEntry{Effect: effect, Type: kind, Value: value})
				}
			}
			appendEntries(assessment.ScopeInclude, assessment.ScopeDomain, domains)
			appendEntries(assessment.ScopeInclude, assessment.ScopeWildcardDomain, wildcardDomains)
			appendEntries(assessment.ScopeInclude, assessment.ScopeURL, urls)
			appendEntries(assessment.ScopeInclude, assessment.ScopeIP, ips)
			appendEntries(assessment.ScopeInclude, assessment.ScopeCIDR, cidrs)
			appendEntries(assessment.ScopeExclude, assessment.ScopeDomain, excludedDomains)
			appendEntries(assessment.ScopeExclude, assessment.ScopeWildcardDomain, excludedWildcards)
			appendEntries(assessment.ScopeExclude, assessment.ScopeURL, excludedURLs)
			appendEntries(assessment.ScopeExclude, assessment.ScopeIP, excludedIPs)
			appendEntries(assessment.ScopeExclude, assessment.ScopeCIDR, excludedCIDRs)
			allowedPortNumbers, err := parsePorts(includePorts)
			if err != nil {
				return fmt.Errorf("parse --port: %w", err)
			}
			excludedPortNumbers, err := parsePorts(excludePorts)
			if err != nil {
				return fmt.Errorf("parse --exclude-port: %w", err)
			}
			for index := range scope.Entries {
				if scope.Entries[index].Effect == assessment.ScopeExclude {
					scope.Entries[index].Ports = excludedPortNumbers
				} else {
					scope.Entries[index].Ports = allowedPortNumbers
				}
			}

			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			program, err := database.CreateProgram(cmd.Context(), store.CreateProgramParams{
				Name:                   args[0],
				SourcePlatform:         sourcePlatform,
				SourceURL:              programURL,
				AuthorizationReference: authorizationReference,
				ExpiresAt:              expiresAt,
				Scope:                  scope,
				Timezone:               timezone,
			}, time.Now().UTC())
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Created program %q\nID: %s\nStatus: %s\nSource: %s %s\nOSINT schedule: %s (%s)\nActivate it with: heimdall program activate %s\n",
				program.Name, program.ID, program.Status, program.SourcePlatform, program.SourceURL, schedule.DefaultOSINTCron, timezone, program.ID)
			return err
		},
	}
	command.Flags().StringVar(&authorizationReference, "authorization-ref", "", "Authorization reference (program URL or internal ticket)")
	command.Flags().StringVar(&sourcePlatform, "platform", "", "Program source platform (hackerone, bugcrowd, intigriti, custom)")
	command.Flags().StringVar(&programURL, "program-url", "", "Read-only source URL for the platform program")
	command.Flags().StringVar(&expiresAtValue, "expires-at", "", "Authorization expiry in RFC3339 format")
	command.Flags().StringVar(&timezone, "timezone", schedule.DetectTimezone(), "IANA timezone for the default OSINT schedule")
	command.Flags().StringSliceVar(&domains, "domain", nil, "Include an exact domain (repeatable)")
	command.Flags().StringSliceVar(&wildcardDomains, "wildcard-domain", nil, "Include subdomains using an explicit wildcard (repeatable)")
	command.Flags().StringSliceVar(&urls, "url", nil, "Include an absolute HTTP(S) URL (repeatable)")
	command.Flags().StringSliceVar(&ips, "ip", nil, "Include an IP address (repeatable)")
	command.Flags().StringSliceVar(&cidrs, "cidr", nil, "Include an IP range (repeatable)")
	command.Flags().StringSliceVar(&includePorts, "port", nil, "Ports authorized for included domain/IP/CIDR entries (repeatable)")
	command.Flags().StringSliceVar(&excludedDomains, "exclude-domain", nil, "Exclude an exact domain (repeatable)")
	command.Flags().StringSliceVar(&excludedWildcards, "exclude-wildcard-domain", nil, "Exclude matching subdomains (repeatable)")
	command.Flags().StringSliceVar(&excludedURLs, "exclude-url", nil, "Exclude an absolute HTTP(S) URL (repeatable)")
	command.Flags().StringSliceVar(&excludedIPs, "exclude-ip", nil, "Exclude an IP address (repeatable)")
	command.Flags().StringSliceVar(&excludedCIDRs, "exclude-cidr", nil, "Exclude an IP range (repeatable)")
	command.Flags().StringSliceVar(&excludePorts, "exclude-port", nil, "Ports to exclude from excluded domain/IP/CIDR entries (repeatable)")
	_ = command.MarkFlagRequired("authorization-ref")
	_ = command.MarkFlagRequired("expires-at")
	return command
}

func parsePorts(values []string) ([]uint16, error) {
	ports := make([]uint16, 0, len(values))
	for _, value := range values {
		parsed, err := strconv.ParseUint(value, 10, 16)
		if err != nil || parsed == 0 {
			return nil, fmt.Errorf("%q is not a valid port number", value)
		}
		ports = append(ports, uint16(parsed))
	}
	return ports, nil
}

func newProgramListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List saved programs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) (resultErr error) {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer func() {
				resultErr = errors.Join(resultErr, database.Close())
			}()
			programs, err := database.ListPrograms(cmd.Context())
			if err != nil {
				return err
			}
			return writePrograms(cmd.OutOrStdout(), programs)
		},
	}
}

func newProgramShowCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "show <program-id>",
		Short: "Show authorization, scope, and stage schedules",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			program, err := database.GetProgram(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Name: %s\nID: %s\nStatus: %s\nAuthorization: %s\nExpires: %s\nSource: %s %s\nScope hash: %s\n",
				program.Name, program.ID, program.Status, program.AuthorizationReference, program.ExpiresAt.Format(time.RFC3339),
				program.SourcePlatform, program.SourceURL, program.ScopeHash); err != nil {
				return err
			}
			if err := writeProgramScope(cmd.OutOrStdout(), program.Scope); err != nil {
				return err
			}
			profile, err := database.GetProgramRequestProfile(cmd.Context(), program.ID)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Request profile: revision %d, user-agent %q, headers %d\n",
				profile.Revision, profile.UserAgent, len(profile.Headers)); err != nil {
				return err
			}
			if err := writeProgramDataAccessSummary(cmd.Context(), cmd.OutOrStdout(), database, program.ID); err != nil {
				return err
			}
			schedules, err := database.ListStageSchedules(cmd.Context(), program.ID)
			if err != nil {
				return err
			}
			return writeProgramSchedules(cmd.OutOrStdout(), schedules)
		},
	}
}

func writeProgramScope(output io.Writer, scope assessment.Scope) error {
	writer := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "EFFECT\tTYPE\tVALUE\tPORTS"); err != nil {
		return err
	}
	for _, entry := range scope.Entries {
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%v\n", entry.Effect, entry.Type, entry.Value, entry.Ports); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func writeProgramSchedules(output io.Writer, schedules []store.StageSchedule) error {
	writer := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "STAGE\tENABLED\tCRON\tTIMEZONE\tRATE/S\tCONCURRENCY\tMAX TARGETS\tTIMEOUT"); err != nil {
		return err
	}
	for _, item := range schedules {
		if _, err := fmt.Fprintf(writer, "%s\t%t\t%s\t%s\t%d\t%d\t%d\t%ds\n", item.Stage, item.Enabled,
			item.CronExpression, item.Timezone, item.Limits.RateLimitPerSecond, item.Limits.MaxConcurrency,
			item.Limits.MaxTargets, item.Limits.TimeoutSeconds); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func writePrograms(output io.Writer, programs []assessment.Program) error {
	writer := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "ID\tNAME\tSTATUS\tEXPIRES"); err != nil {
		return err
	}
	for _, program := range programs {
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", program.ID, program.Name, program.Status, program.ExpiresAt.Format(time.RFC3339)); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func newProgramActivateCommand() *cobra.Command {
	return newProgramStatusCommand(
		"activate", "Activate a program after validating authorization and scope",
		"Program %s is active. Enabled stages are queued for the daemon.\n",
		func(ctx context.Context, database *store.Store, programID string, now time.Time) error {
			return database.ActivateProgram(ctx, programID, now)
		},
	)
}

func newProgramPauseCommand() *cobra.Command {
	return newProgramStatusCommand(
		"pause", "Pause a program and its scheduled activity", "Program %s is paused.\n",
		func(ctx context.Context, database *store.Store, programID string, now time.Time) error {
			return database.PauseProgram(ctx, programID, now)
		},
	)
}

func newProgramStatusCommand(
	action, short, successFormat string,
	transition func(context.Context, *store.Store, string, time.Time) error,
) *cobra.Command {
	return &cobra.Command{
		Use:   action + " <program-id>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			if err := transition(cmd.Context(), database, args[0], time.Now().UTC()); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), successFormat, args[0])
			return err
		},
	}
}

func newScheduleCommand() *cobra.Command {
	command := &cobra.Command{Use: "schedule", Short: "Configure per-program recon schedules"}
	setCommand := &cobra.Command{
		Use:   "set <program-id>",
		Short: "Set a recon stage cron expression and timezone",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			expression, err := cmd.Flags().GetString("cron")
			if err != nil {
				return err
			}
			timezone, err := cmd.Flags().GetString("timezone")
			if err != nil {
				return err
			}
			enabled, err := cmd.Flags().GetBool("enabled")
			if err != nil {
				return err
			}
			stage, err := cmd.Flags().GetString("stage")
			if err != nil {
				return err
			}
			rateLimit, err := cmd.Flags().GetInt("rate-limit")
			if err != nil {
				return err
			}
			maxConcurrency, err := cmd.Flags().GetInt("max-concurrency")
			if err != nil {
				return err
			}
			maxTargets, err := cmd.Flags().GetInt("max-targets")
			if err != nil {
				return err
			}
			timeoutSeconds, err := cmd.Flags().GetInt("timeout")
			if err != nil {
				return err
			}
			database, err := openStore(cmd)
			if err != nil {
				return err
			}
			defer database.Close()
			limits := recon.StageLimits{
				RateLimitPerSecond: rateLimit,
				MaxConcurrency:     maxConcurrency,
				MaxTargets:         maxTargets,
				TimeoutSeconds:     timeoutSeconds,
			}
			if err := database.SetStageSchedule(cmd.Context(), args[0], stage, expression, timezone, enabled, time.Now().UTC(), limits); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s schedule updated for %s: %s (%s), enabled=%t\n", stage, args[0], expression, timezone, enabled)
			return err
		},
	}
	command.AddCommand(setCommand)
	setCommand.Flags().String("cron", schedule.DefaultOSINTCron, "Five-field cron expression")
	setCommand.Flags().String("timezone", schedule.DetectTimezone(), "IANA timezone")
	setCommand.Flags().String("stage", "osint", "Recon stage (osint, dns, web, nmap, crawl, ffuf, or nuclei)")
	setCommand.Flags().Bool("enabled", true, "Enable the schedule")
	setCommand.Flags().Int("rate-limit", 0, "Maximum requests per second (stage default when omitted)")
	setCommand.Flags().Int("max-concurrency", 0, "Maximum concurrent requests (stage default when omitted)")
	setCommand.Flags().Int("max-targets", 0, "Maximum targets per run (stage default when omitted)")
	setCommand.Flags().Int("timeout", 0, "Stage timeout in seconds (stage default when omitted)")
	return command
}
