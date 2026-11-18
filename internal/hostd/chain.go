package hostd

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// The journal is a hash chain: each entry carries its number and the SHA-256
// of the line before it, so an entry removed, changed or put back in another
// order breaks the chain from there on. Root on the machine can rewrite the
// whole file; Nia keeps the head it saw, and the machine shows that its chain
// still holds it (see Anchor).

// Head is the end of the chain: the number of the last entry and the SHA-256
// of its line. The empty journal has Seq 0 and no hash.
type Head struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash,omitempty"`
}

// HeadAction answers the head of the journal, and with an anchor the hash of
// the entry at that number: it runs nothing and is not journaled.
const HeadAction = "journal_head"

func lineHash(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}

// chain reads the journal and checks its chain. It returns every entry's
// line hash, in order, and the head. Lines written before the chain existed
// (no seq) are accepted at the start only.
func (s *Server) chain() ([]string, Head, error) {
	file, err := os.Open(s.JournalPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, Head{}, nil
	}
	if err != nil {
		return nil, Head{}, err
	}
	defer file.Close()
	var hashes []string
	head := Head{}
	chained := false
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := bytes.Clone(scanner.Bytes())
		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, Head{}, fmt.Errorf("hostd: journal line %d cannot be read: %w", len(hashes)+1, err)
		}
		seq := int64(len(hashes) + 1)
		switch {
		case entry.Seq == 0 && !chained:
			// Before the chain: counted, not linked.
		case entry.Seq != seq:
			return nil, Head{}, fmt.Errorf("hostd: journal line %d says it is entry %d: the chain is broken", seq, entry.Seq)
		case entry.Prev != head.Hash:
			return nil, Head{}, fmt.Errorf("hostd: journal entry %d does not follow entry %d: the chain is broken", seq, seq-1)
		default:
			chained = true
		}
		head = Head{Seq: seq, Hash: lineHash(line)}
		hashes = append(hashes, head.Hash)
	}
	if err := scanner.Err(); err != nil {
		return nil, Head{}, err
	}
	return hashes, head, nil
}

// VerifyJournal checks the chain and returns its head.
func (s *Server) VerifyJournal() (Head, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, head, err := s.chain()
	return head, err
}

// Anchor is what the machine shows Nia: its head, and the hash of the entry
// Nia last saw as the head, so Nia sees whether the chain still holds it.
type Anchor struct {
	Head
	// At is the number Nia asked about; AtHash the hash of that entry, empty
	// when the chain has no such entry.
	At     int64  `json:"at,omitempty"`
	AtHash string `json:"at_hash,omitempty"`
	// Broken says the chain does not verify here.
	Broken string `json:"broken,omitempty"`
}

func (s *Server) anchor(at int64) Anchor {
	hashes, head, err := s.chain()
	if err != nil {
		return Anchor{Broken: err.Error()}
	}
	a := Anchor{Head: head, At: at}
	if at > 0 && at <= int64(len(hashes)) {
		a.AtHash = hashes[at-1]
	}
	return a
}
