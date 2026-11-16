package agent

import (
	"errors"
	"fmt"
	"strings"
)

const (
	maxPlanTasks         = 10
	maxPlanTaskObjective = 500
	maxPlanTaskActions   = 20
)

// PlanTask is one bounded objective with the actions that satisfy it. Tasks
// may depend on earlier tasks; the planner flattens them in dependency order
// so the executor still receives a deterministic action sequence.
type PlanTask struct {
	ID        string           `json:"id"`
	Objective string           `json:"objective"`
	DependsOn []string         `json:"depends_on,omitempty"`
	Actions   []ActionProposal `json:"actions"`
}

// PlanTaskSummary records the validated task graph next to the policy
// decisions so a reviewer can see why actions were ordered that way.
type PlanTaskSummary struct {
	ID        string   `json:"id"`
	Objective string   `json:"objective"`
	DependsOn []string `json:"depends_on,omitempty"`
	Actions   int      `json:"actions"`
}

// OrderPlanTasks validates a bounded task DAG and flattens it into actions.
// Dependencies always run first; ready tasks keep their original order. Every
// action carries its owning task id for audit.
func OrderPlanTasks(tasks []PlanTask) ([]ActionProposal, []PlanTaskSummary, error) {
	if err := validatePlanTaskSet(tasks); err != nil {
		return nil, nil, err
	}
	index := make(map[string]int, len(tasks))
	for position, task := range tasks {
		index[task.ID] = position
	}
	order, err := topologicalTaskOrder(tasks)
	if err != nil {
		return nil, nil, err
	}
	actions := make([]ActionProposal, 0, len(tasks))
	summaries := make([]PlanTaskSummary, 0, len(tasks))
	for _, position := range order {
		task := tasks[position]
		summaries = append(summaries, PlanTaskSummary{
			ID: task.ID, Objective: task.Objective,
			DependsOn: append([]string(nil), task.DependsOn...), Actions: len(task.Actions),
		})
		flattened, err := flattenTaskActions(task)
		if err != nil {
			return nil, nil, err
		}
		actions = append(actions, flattened...)
	}
	if len(actions) > maxPlanTaskActions {
		return nil, nil, fmt.Errorf("task plan may contain at most %d actions", maxPlanTaskActions)
	}
	if len(actions) == 0 {
		return nil, nil, errors.New("task plan contains no actions")
	}
	return actions, summaries, nil
}

func validatePlanTaskSet(tasks []PlanTask) error {
	if len(tasks) == 0 {
		return errors.New("task plan requires at least one task")
	}
	if len(tasks) > maxPlanTasks {
		return fmt.Errorf("task plan may contain at most %d tasks", maxPlanTasks)
	}
	seen := make(map[string]bool, len(tasks))
	for _, task := range tasks {
		if err := validatePlanTask(task); err != nil {
			return err
		}
		if seen[task.ID] {
			return fmt.Errorf("task id %q is duplicated", task.ID)
		}
		seen[task.ID] = true
	}
	for _, task := range tasks {
		for _, dependency := range task.DependsOn {
			if dependency == task.ID {
				return fmt.Errorf("task %q cannot depend on itself", task.ID)
			}
			if !seen[dependency] {
				return fmt.Errorf("task %q depends on unknown task %q", task.ID, dependency)
			}
		}
	}
	return nil
}

func validatePlanTask(task PlanTask) error {
	if task.ID == "" || strings.TrimSpace(task.ID) != task.ID {
		return errors.New("task ids must be non-empty without surrounding whitespace")
	}
	objective := strings.TrimSpace(task.Objective)
	if objective == "" {
		return fmt.Errorf("task %q requires an objective", task.ID)
	}
	if len(objective) > maxPlanTaskObjective {
		return fmt.Errorf("task %q objective exceeds %d bytes", task.ID, maxPlanTaskObjective)
	}
	if len(task.Actions) == 0 {
		return fmt.Errorf("task %q requires at least one action", task.ID)
	}
	seen := make(map[string]bool, len(task.DependsOn))
	for _, dependency := range task.DependsOn {
		if dependency == "" || strings.TrimSpace(dependency) != dependency {
			return fmt.Errorf("task %q has an invalid dependency", task.ID)
		}
		if seen[dependency] {
			return fmt.Errorf("task %q lists dependency %q more than once", task.ID, dependency)
		}
		seen[dependency] = true
	}
	return nil
}

func flattenTaskActions(task PlanTask) ([]ActionProposal, error) {
	actions := make([]ActionProposal, 0, len(task.Actions))
	for _, proposal := range task.Actions {
		if proposal.TaskID != "" && proposal.TaskID != task.ID {
			return nil, fmt.Errorf("action task id %q does not match owning task %q", proposal.TaskID, task.ID)
		}
		proposal.TaskID = task.ID
		actions = append(actions, proposal)
	}
	return actions, nil
}

func topologicalTaskOrder(tasks []PlanTask) ([]int, error) {
	remaining := make([]int, len(tasks))
	for position := range tasks {
		remaining[position] = len(tasks[position].DependsOn)
	}
	emitted := make([]bool, len(tasks))
	order := make([]int, 0, len(tasks))
	for len(order) < len(tasks) {
		progressed := false
		for position, task := range tasks {
			if emitted[position] || remaining[position] > 0 {
				continue
			}
			emitted[position] = true
			order = append(order, position)
			progressed = true
			releaseTaskDependents(tasks, emitted, remaining, task.ID)
		}
		if !progressed {
			return nil, errors.New("task plan contains a dependency cycle")
		}
	}
	return order, nil
}

func releaseTaskDependents(tasks []PlanTask, emitted []bool, remaining []int, completed string) {
	for position, task := range tasks {
		if emitted[position] {
			continue
		}
		for _, dependency := range task.DependsOn {
			if dependency == completed {
				remaining[position]--
			}
		}
	}
}

// validatePlanDraft rejects a task summary that does not match the flattened
// action list, so policy decisions cannot drift from the reviewed graph.
func validatePlanDraft(draft PlanDraft) error {
	if len(draft.Tasks) == 0 {
		return nil
	}
	ids := make(map[string]bool, len(draft.Tasks))
	expected := 0
	for _, task := range draft.Tasks {
		if task.ID == "" || ids[task.ID] {
			return errors.New("plan task summaries require unique non-empty ids")
		}
		if task.Actions <= 0 {
			return fmt.Errorf("plan task %q summary has no actions", task.ID)
		}
		ids[task.ID] = true
		expected += task.Actions
	}
	if expected != len(draft.Actions) {
		return errors.New("plan task summaries do not match the flattened actions")
	}
	for _, action := range draft.Actions {
		if !ids[action.TaskID] {
			return fmt.Errorf("flattened action references unknown task %q", action.TaskID)
		}
	}
	return nil
}
