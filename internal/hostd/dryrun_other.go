//go:build !linux

package hostd

import "context"

func (s *Server) dryRun(context.Context, *Catalogue, Request) Response {
	return Response{Error: "dry runs need Linux"}
}

// DefaultSandbox is none outside Linux.
func DefaultSandbox() Sandbox { return nil }
