package hostd

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/GetKlaros/nia-edge/internal/policy"
	"github.com/GetKlaros/nia-edge/internal/state"
)

// ChangesAction lists the last changes of the journal that can be undone,
// with what undid them: nia-edge reports them to Nia, which shows them with
// an undo button. The report decides nothing.
const ChangesAction = "changes"

// UndoOrderAction undoes one change on a person's order, which Nia signed
// with the key this machine pinned at enrollment. nia-edge only passes the
// order: nia-hostd verifies it itself, so nia-edge cannot forge one.
const UndoOrderAction = "undo_order"

// maxChanges is how many changes a report holds, the last first.
const maxChanges = 20

// ChangeReport is one change the journal holds that can be undone.
type ChangeReport struct {
	ID     string `json:"id"`
	At     string `json:"at"`
	Action string `json:"action"`
	Name   string `json:"name"`
	// UndoneBy is the entry that undid it, and Order the order it ran for.
	UndoneBy string `json:"undone_by,omitempty"`
	Order    string `json:"order,omitempty"`
}

func (s *Server) changes() Response {
	entries, err := s.Journal()
	if err != nil {
		return Response{Error: err.Error()}
	}
	undone := map[string]Entry{}
	for _, entry := range entries {
		if entry.Of != "" {
			undone[entry.Of] = entry
		}
	}
	list := []ChangeReport{}
	for i := len(entries) - 1; i >= 0 && len(list) < maxChanges; i-- {
		entry := entries[i]
		if !entry.OK || entry.Undo == nil {
			continue
		}
		report := ChangeReport{ID: entry.ID, At: entry.At.UTC().Format("2006-01-02T15:04:05Z"), Action: entry.Action, Name: entry.Name}
		if by, ok := undone[entry.ID]; ok {
			report.UndoneBy, report.Order = by.ID, by.Order
		}
		list = append(list, report)
	}
	text, _ := json.Marshal(list)
	return Response{OK: true, Output: string(text)}
}

// undoOrder verifies an order and undoes its entry, once. An order already
// run answers what it did. Called with s.mu held.
func (s *Server) undoOrder(ctx context.Context, signed *policy.Signed) Response {
	if signed == nil {
		return Response{Error: "no undo order"}
	}
	saved, err := state.Load(s.StatePath)
	if err != nil {
		return Response{Error: err.Error()}
	}
	if saved.PolicyKey == nil {
		return Response{Error: "this machine pinned no key at enrollment: no order can be verified"}
	}
	order, err := policy.OpenUndo(*signed, *saved.PolicyKey, saved.MachineID, s.now())
	if err != nil {
		s.log("undo order refused", "reason", err.Error())
		return Response{Error: err.Error()}
	}
	entries, err := s.Journal()
	if err != nil {
		return Response{Error: err.Error()}
	}
	for _, entry := range entries {
		if entry.Order == order.ID {
			if entry.Of != order.Entry {
				return Response{Error: "this order was spent on another entry"}
			}
			return Response{OK: entry.OK, Error: entry.Error, Journal: entry.ID}
		}
	}
	resp := s.undo(ctx, order.Entry, order.ID)
	s.log("undo order", "order", order.ID, "entry", order.Entry, "ok", resp.OK)
	if resp.Error == "" && !resp.OK {
		resp.Error = errors.New("the undo failed").Error()
	}
	return resp
}
