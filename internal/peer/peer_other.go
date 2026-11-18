//go:build !linux

// Package peer tells who is at the other end of a Unix socket.
package peer

import (
	"errors"
	"net"
)

// UID is not known outside Linux: nothing is served there.
func UID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("peer: the peer of a socket is known on Linux only")
}
