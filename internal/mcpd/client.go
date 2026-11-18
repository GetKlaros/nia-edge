package mcpd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Client asks nia-mcp for servers, over its socket.
type Client struct {
	Socket string
}

// Stream is a running server's standard input and output. Closing it ends
// the server.
type Stream interface {
	io.ReadWriteCloser
}

type stream struct {
	net.Conn
	reader *bufio.Reader
}

func (s *stream) Read(p []byte) (int, error) { return s.reader.Read(p) }

// Launch starts a server and returns its stream once nia-mcp started it.
func (c *Client) Launch(ctx context.Context, launch Launch) (Stream, error) {
	if err := launch.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(launch)
	if err != nil {
		return nil, err
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return nil, fmt.Errorf("nia-mcp cannot be reached: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write(append(encoded, '\n')); err != nil {
		conn.Close()
		return nil, err
	}
	reader := bufio.NewReaderSize(conn, 64<<10)
	line, err := readLine(reader, 4096)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("nia-mcp gave no answer: %w", err)
	}
	var ack Ack
	if json.Unmarshal(line, &ack) != nil {
		conn.Close()
		return nil, errors.New("nia-mcp's answer cannot be read")
	}
	if !ack.OK {
		conn.Close()
		if ack.Error == "" {
			ack.Error = "refused"
		}
		return nil, fmt.Errorf("nia-mcp: %s", ack.Error)
	}
	_ = conn.SetDeadline(time.Time{})
	return &stream{Conn: conn, reader: reader}, nil
}
