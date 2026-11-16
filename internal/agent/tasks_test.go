package agent

import (
	"fmt"
	"strings"
	"testing"
)

func TestOrderPlanTasksRunsDependenciesFirst(t *testing.T) {
	tasks := []PlanTask{
		{ID: "probe", Objective: "Probe the discovered route", DependsOn: []string{"discover"}, Actions: []ActionProposal{{Stage: "web", Targets: []string{"https://app.example.test/health"}}}},
		{ID: "discover", Objective: "Discover routes", Actions: []ActionProposal{{Stage: "web", Targets: []string{"https://app.example.test/"}}}},
	}
	actions, summaries, err := OrderPlanTasks(tasks)
	if err != nil {
		t.Fatalf("OrderPlanTasks returned an error: %v", err)
	}
	if len(actions) != 2 || actions[0].TaskID != "discover" || actions[1].TaskID != "probe" {
		t.Fatalf("actions were not ordered by dependency: %+v", actions)
	}
	if len(summaries) != 2 || summaries[0].ID != "discover" || summaries[1].ID != "probe" {
		t.Fatalf("summaries were not ordered by dependency: %+v", summaries)
	}
	if summaries[1].DependsOn[0] != "discover" || summaries[1].Actions != 1 {
		t.Fatalf("dependent task summary lost its dependency: %+v", summaries[1])
	}
}

func TestOrderPlanTasksKeepsReadyTaskOrder(t *testing.T) {
	tasks := []PlanTask{
		{ID: "b", Objective: "Second independent task", Actions: []ActionProposal{{Stage: "web"}}},
		{ID: "a", Objective: "First independent task", Actions: []ActionProposal{{Stage: "web"}}},
	}
	actions, _, err := OrderPlanTasks(tasks)
	if err != nil {
		t.Fatal(err)
	}
	if actions[0].TaskID != "b" || actions[1].TaskID != "a" {
		t.Fatalf("independent tasks changed order: %+v", actions)
	}
}

func TestOrderPlanTasksRejectsInvalidGraphs(t *testing.T) {
	tests := []struct {
		name  string
		tasks []PlanTask
		want  string
	}{
		{name: "empty plan", want: "at least one task"},
		{name: "empty id", tasks: []PlanTask{{Objective: "x", Actions: []ActionProposal{{Stage: "web"}}}}, want: "task ids"},
		{name: "empty objective", tasks: []PlanTask{{ID: "t1", Actions: []ActionProposal{{Stage: "web"}}}}, want: "requires an objective"},
		{name: "no actions", tasks: []PlanTask{{ID: "t1", Objective: "x"}}, want: "requires at least one action"},
		{name: "duplicate id", tasks: []PlanTask{
			{ID: "t1", Objective: "x", Actions: []ActionProposal{{Stage: "web"}}},
			{ID: "t1", Objective: "y", Actions: []ActionProposal{{Stage: "web"}}},
		}, want: "duplicated"},
		{name: "self dependency", tasks: []PlanTask{{ID: "t1", Objective: "x", DependsOn: []string{"t1"}, Actions: []ActionProposal{{Stage: "web"}}}}, want: "cannot depend on itself"},
		{name: "unknown dependency", tasks: []PlanTask{{ID: "t1", Objective: "x", DependsOn: []string{"missing"}, Actions: []ActionProposal{{Stage: "web"}}}}, want: "unknown task"},
		{name: "cycle", tasks: []PlanTask{
			{ID: "a", Objective: "x", DependsOn: []string{"b"}, Actions: []ActionProposal{{Stage: "web"}}},
			{ID: "b", Objective: "y", DependsOn: []string{"a"}, Actions: []ActionProposal{{Stage: "web"}}},
		}, want: "cycle"},
		{name: "duplicate dependency", tasks: []PlanTask{
			{ID: "a", Objective: "x", Actions: []ActionProposal{{Stage: "web"}}},
			{ID: "b", Objective: "y", DependsOn: []string{"a", "a"}, Actions: []ActionProposal{{Stage: "web"}}},
		}, want: "more than once"},
		{name: "conflicting action task", tasks: []PlanTask{
			{ID: "a", Objective: "x", Actions: []ActionProposal{{Stage: "web", TaskID: "b"}}},
		}, want: "does not match owning task"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := OrderPlanTasks(test.tasks)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("OrderPlanTasks error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestOrderPlanTasksRejectsTooManyTasks(t *testing.T) {
	tasks := make([]PlanTask, maxPlanTasks+1)
	for index := range tasks {
		tasks[index] = PlanTask{
			ID: fmt.Sprintf("t%d", index), Objective: "bounded",
			Actions: []ActionProposal{{Stage: "web"}},
		}
	}
	if _, _, err := OrderPlanTasks(tasks); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("OrderPlanTasks error = %v, want a task-count limit", err)
	}
}

func TestValidatePlanDraftRejectsMismatchedSummaries(t *testing.T) {
	draft := PlanDraft{
		Tasks: []PlanTaskSummary{{ID: "t1", Objective: "x", Actions: 2}},
		Actions: []ActionProposal{
			{Stage: "web", TaskID: "t1"},
		},
	}
	if err := validatePlanDraft(draft); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("validatePlanDraft error = %v, want a summary mismatch", err)
	}
	draft.Actions = append(draft.Actions, ActionProposal{Stage: "web", TaskID: "unknown"})
	if err := validatePlanDraft(draft); err == nil || !strings.Contains(err.Error(), "unknown task") {
		t.Fatalf("validatePlanDraft error = %v, want an unknown task", err)
	}
}
