//go:build !linux

package hostd

import "context"

func (s *Server) dryRun(context.Context, *Catalogue, Request) Response {
	return Response{Error: "dry runs need Linux"}
}

// DefaultSandbox is none outside Linux.
func DefaultSandbox() Sandbox { return nil }

func (s *Server) apply(context.Context, Request) Response {
	return Response{Error: "applying a plan needs Linux"}
}

func (s *Server) restoreEntry(target Entry) Entry {
	return Entry{ID: newID(), Action: "restore", Of: target.ID, Error: "restoring needs Linux"}
}

func (s *Server) planReview(string) Response {
	return Response{Error: "plans need Linux"}
}
