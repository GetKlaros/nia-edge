package localmcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"sync"
)

// maxMessage bounds one message from a server.
const maxMessage = 8 << 20

// rpcError is a JSON-RPC error.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	result json.RawMessage
	err    *rpcError
}

// process is one running server, spoken to as an MCP client over its
// standard input and output. Requests carry nia-edge's own ids: the agent's
// never reach the server.
type process struct {
	stream io.ReadWriteCloser

	writeMu sync.Mutex
	mu      sync.Mutex
	next    int64
	pending map[string]chan response
	done    chan struct{}
	failure error
}

var errEnded = errors.New("the MCP server ended")

func start(stream io.ReadWriteCloser) *process {
	p := &process{stream: stream, pending: map[string]chan response{}, done: make(chan struct{})}
	go p.read()
	return p
}

func (p *process) read() {
	scanner := bufio.NewScanner(p.stream)
	scanner.Buffer(make([]byte, 64<<10), maxMessage)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var msg struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
			Result  json.RawMessage `json:"result"`
			Error   *rpcError       `json:"error"`
		}
		if json.Unmarshal(line, &msg) != nil || msg.JSONRPC != "2.0" {
			continue
		}
		if msg.Method != "" {
			// The server asks something (sampling, roots, elicitation): it
			// gets nothing from the agent or its model.
			if len(msg.ID) > 0 && string(msg.ID) != "null" {
				// Answered aside: reading must go on while the server writes.
				id := msg.ID
				go func() {
					_ = p.send(map[string]any{"jsonrpc": "2.0", "id": id, "error": rpcError{Code: -32601, Message: "not available through nia-edge"}})
				}()
			}
			continue
		}
		p.mu.Lock()
		waiting := p.pending[string(msg.ID)]
		delete(p.pending, string(msg.ID))
		p.mu.Unlock()
		if waiting != nil {
			waiting <- response{result: msg.Result, err: msg.Error}
		}
	}
	failure := scanner.Err()
	if failure == nil {
		failure = errEnded
	}
	p.mu.Lock()
	p.failure = failure
	for id, waiting := range p.pending {
		close(waiting)
		delete(p.pending, id)
	}
	p.mu.Unlock()
	close(p.done)
}

func (p *process) send(message any) error {
	encoded, err := json.Marshal(message)
	if err != nil {
		return err
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	_, err = p.stream.Write(append(encoded, '\n'))
	return err
}

// call sends a request and waits for its answer.
func (p *process) call(ctx context.Context, method string, params any) (json.RawMessage, *rpcError, error) {
	p.mu.Lock()
	if p.failure != nil {
		p.mu.Unlock()
		return nil, nil, p.failure
	}
	p.next++
	number := p.next
	id := strconv.FormatInt(number, 10)
	waiting := make(chan response, 1)
	p.pending[id] = waiting
	p.mu.Unlock()
	message := map[string]any{"jsonrpc": "2.0", "id": number, "method": method}
	if params != nil {
		message["params"] = params
	}
	if err := p.send(message); err != nil {
		p.forget(id)
		return nil, nil, err
	}
	select {
	case answer, ok := <-waiting:
		if !ok {
			return nil, nil, errEnded
		}
		return answer.result, answer.err, nil
	case <-ctx.Done():
		p.forget(id)
		return nil, nil, ctx.Err()
	}
}

func (p *process) notify(method string) error {
	return p.send(map[string]any{"jsonrpc": "2.0", "method": method})
}

func (p *process) forget(id string) {
	p.mu.Lock()
	delete(p.pending, id)
	p.mu.Unlock()
}

func (p *process) busy() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pending) > 0
}

func (p *process) ended() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (p *process) close() {
	_ = p.stream.Close()
}
