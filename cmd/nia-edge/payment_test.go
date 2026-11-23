package main

import (
	"testing"

	"github.com/GetKlaros/nia-edge/internal/local"
	"github.com/GetKlaros/nia-edge/internal/niaclient"
)

// The payment tool nia-edge serves has every part: Nia's plan, the chain and
// Nia's visa. v0.10.0 shipped without the plan and panicked on every payment.
func TestPayHandlerHasEveryPart(t *testing.T) {
	h := payHandler(&paymentAccount{}, &local.Releases{Prefix: "mcp__"}, &niaclient.Client{}, "key", "session", "run")
	if h.Account == nil || h.Releases == nil || h.Chain == nil || h.Plans == nil || h.Visas == nil || h.Prefix != "mcp__nia_pay__" {
		t.Fatalf("the payment tool misses a part: %+v", h)
	}
}
