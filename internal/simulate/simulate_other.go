//go:build !linux

package simulate

import "context"

type layer struct{}

// Run is unsupported outside Linux.
func Run(context.Context, Options) (*Result, error) { return nil, ErrUnsupported }

// Child is never started outside Linux.
func Child() int { return 125 }

// Apply is unsupported outside Linux.
func (r *Result) Apply() error { return ErrUnsupported }

// Close forgets the result.
func (r *Result) Close() error { return nil }
