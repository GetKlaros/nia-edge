package local

import (
	"testing"
	"time"
)

func TestAReleaseKeepsItsSessionAndIsSpentOnce(t *testing.T) {
	releases := &Releases{Prefix: "mcp__host__"}
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	releases.record("conv-7", []released{{"mcp__host__propose_task", `{"title":"x","steps":[]}`}, {"terminal", `{}`}}, nil, now)
	// Canonical arguments: the order of the keys does not matter.
	session, ok := releases.TakeSession("mcp__host__propose_task", `{"steps":[],"title":"x"}`, now)
	if !ok || session != "conv-7" {
		t.Fatalf("%q %v", session, ok)
	}
	if _, ok := releases.TakeSession("mcp__host__propose_task", `{"title":"x","steps":[]}`, now); ok {
		t.Error("spent twice")
	}
	// Only the host's tools are kept.
	if releases.Take("terminal", `{}`, now) {
		t.Error("kept a call that is not a host action")
	}
	releases.ReleaseIn("conv-8", "mcp__host__disk_usage", `{}`, now)
	if releases.Take("mcp__host__disk_usage", `{}`, now.Add(11*time.Minute)) {
		t.Error("a release outlived its ten minutes")
	}
}
