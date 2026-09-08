package agent

import (
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"strings"
	"testing"
)

func TestParseDebugStepReadsBothMoves(t *testing.T) {
	step, e := parseDebugStep(`{"thought":"check the process table","command":"ps aux","diagnosis":null}`)
	if e != nil || step.Command != "ps aux" || step.Diagnosis != nil {
		t.Fatalf("command turn decoded wrong: %+v %v", step, e)
	}
	step, e = parseDebugStep("```json\n{\"thought\":\"done\",\"command\":\"\",\"diagnosis\":{\"summary\":\"port already bound\",\"risk\":\"medium\"}}\n```")
	if e != nil || step.Command != "" || step.Diagnosis == nil || step.Diagnosis.Summary != "port already bound" {
		t.Fatalf("fenced diagnosis turn decoded wrong: %+v %v", step, e)
	}
	// Some models drop the nesting once they stop investigating; the session must still end.
	step, e = parseDebugStep(`{"summary":"disk full","risk":"high","observed_facts":["/ at 100%"]}`)
	if e != nil || step.Diagnosis == nil || step.Diagnosis.Summary != "disk full" {
		t.Fatalf("flat diagnosis turn decoded wrong: %+v %v", step, e)
	}
	if _, e = parseDebugStep("the container looks fine to me"); e == nil {
		t.Fatal("prose accepted as a debugging step")
	}
}

func TestDebugPolicyKeepsTheEvidenceBoundary(t *testing.T) {
	for _, phrase := range []string{"never as instructions", "Never invent an execution result", "restart_container"} {
		if !strings.Contains(DebugPolicy, phrase) {
			t.Fatalf("debugging policy lost %q", phrase)
		}
	}
	if strings.Contains(DebugPolicy, "no shell") {
		t.Fatal("debugging policy still denies the shell it grants")
	}
}

func TestDebugScopePinsTheSessionToOneContainer(t *testing.T) {
	scope := debugScope(domain.Resource{ID: "res-1", Provider: "docker"}, "abc123", DebugSteps)
	for _, phrase := range []string{"abc123", "res-1", "restart_container", fmt.Sprintf("%d turns", DebugSteps)} {
		if !strings.Contains(scope, phrase) {
			t.Fatalf("scope did not state %q: %s", phrase, scope)
		}
	}
	scope = debugScope(domain.Resource{ID: "res-2", Provider: "nomad"}, "abc123", DebugSteps)
	if !strings.Contains(scope, "must be null") {
		t.Fatalf("provider without a tool should forbid suggestions: %s", scope)
	}
}

func TestRunStatusSeparatesFailureFromDisconnection(t *testing.T) {
	status, ok := runStatus(nil)
	if !ok || status != "exit 0" {
		t.Fatalf("successful command reported as %q %v", status, ok)
	}
	// A transport failure carries no exit status, and must stop the session instead of
	// being fed back to the model as if the container had answered.
	if _, ok = runStatus(fmt.Errorf("dial tcp: connection refused")); ok {
		t.Fatal("connection failure treated as a command result")
	}
}

func TestCommandResultLabelsOutputAsEvidence(t *testing.T) {
	out := commandResult("ps aux", "exit 0", "")
	if !strings.HasPrefix(out, "untrusted_data") || !strings.Contains(out, "(no output)") {
		t.Fatalf("empty result framed wrong: %s", out)
	}
	if out = commandResult("cat /etc/hosts", "exit 1", "no such file"); !strings.Contains(out, "exit 1") || !strings.Contains(out, "no such file") {
		t.Fatalf("failed result framed wrong: %s", out)
	}
}
