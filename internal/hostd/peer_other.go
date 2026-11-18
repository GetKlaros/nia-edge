//go:build !linux

package hostd

import (
	"errors"
	"net"
)

// peerUID is not known outside Linux: nia-hostd serves no one there.
func peerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("hostd: the peer of a socket is known on Linux only")
}
