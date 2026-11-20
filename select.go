package pin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kololog "github.com/ciranda-dev/kolo-log"
	kolosync "github.com/ciranda-dev/kolo-sync"
)

const (
	// DefaultCopies is the number of pinning peers Select and AddMany choose when n is 0 or less.
	DefaultCopies = 2
	// MaxFallback is how many more peers AddMany tries, in Select's order, when chosen ones are unreachable.
	MaxFallback = 2
)

// Selection is the result of Select.
type Selection struct {
	Peers        []Peer // the chosen peers, highest weight first
	SharedGroups bool   // there were fewer groups than peers to choose, so some chosen peers share a group
}

// Select returns the n peers with the highest rendezvous weight for logID, from different groups when it can.
// A peer without a group counts as its own group. Peers with an invalid ID are skipped, and of repeated IDs one is kept.
func Select(peers []Peer, logID kololog.LogID, n int) Selection {
	if n <= 0 {
		n = DefaultCopies
	}
	order := rank(peers, logID)
	used := map[string]bool{}
	picked := make([]bool, len(order))
	var sel Selection
	for i, p := range order {
		if len(sel.Peers) == n {
			break
		}
		if g := groupOf(p); !used[g] {
			used[g] = true
			picked[i] = true
			sel.Peers = append(sel.Peers, p)
		}
	}
	for i, p := range order {
		if len(sel.Peers) == n {
			break
		}
		if !picked[i] {
			picked[i] = true
			sel.Peers = append(sel.Peers, p)
			sel.SharedGroups = true
		}
	}
	sel.Peers = sel.Peers[:0]
	for i, p := range order {
		if picked[i] {
			sel.Peers = append(sel.Peers, p)
		}
	}
	return sel
}

func groupOf(p Peer) string {
	if p.Group == "" {
		return "\x00" + string(p.ID)
	}
	return "\x01" + p.Group
}

// rank returns the valid peers, highest weight for logID first. Of peers with the same ID, it keeps the one with
// the smallest group, then address, so the result never depends on the order of peers.
func rank(peers []Peer, logID kololog.LogID) []Peer {
	type weighted struct {
		p Peer
		w [sha256.Size]byte
	}
	var ws []weighted
	for _, p := range peers {
		if len(p.ID) == ed25519.PublicKeySize {
			ws = append(ws, weighted{p, weight(p.ID, logID)})
		}
	}
	slices.SortFunc(ws, func(a, b weighted) int {
		if c := bytes.Compare(b.w[:], a.w[:]); c != 0 {
			return c
		}
		if c := bytes.Compare(a.p.ID, b.p.ID); c != 0 {
			return c
		}
		if c := strings.Compare(a.p.Group, b.p.Group); c != 0 {
			return c
		}
		return strings.Compare(a.p.Addr, b.p.Addr)
	})
	var out []Peer
	for _, w := range ws {
		if len(out) == 0 || !out[len(out)-1].ID.Equal(w.p.ID) {
			out = append(out, w.p)
		}
	}
	return out
}

// weight is the rendezvous weight of a peer for a log: SHA-256 of the peer ID and the log ID.
func weight(peer []byte, logID kololog.LogID) [sha256.Size]byte {
	return sha256.Sum256(append(slices.Clone(peer), logID[:]...))
}

// IssueMany issues c for each peer, all with the same issue time, in the order of peers.
func IssueMany(owner *koloid.Identity, peers []Peer, c Capability) ([][]byte, error) {
	if c.Issued.IsZero() {
		c.Issued = time.Now()
	}
	out := make([][]byte, 0, len(peers))
	for _, p := range peers {
		c.Peer = p.ID
		b, err := Issue(owner, c)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// Outcome is what happened when AddMany tried one peer.
type Outcome int

const (
	// Accepted means the peer pulled and verified the log.
	Accepted Outcome = iota + 1
	// Refused means the peer answered with an error, or no capability named it.
	Refused
	// Unreachable means the peer could not be reached or the connection broke.
	Unreachable
)

// String returns "accepted", "refused" or "unreachable".
func (o Outcome) String() string {
	switch o {
	case Accepted:
		return "accepted"
	case Refused:
		return "refused"
	case Unreachable:
		return "unreachable"
	}
	return "unknown"
}

// Result is one peer AddMany tried.
type Result struct {
	Peer    Peer
	Outcome Outcome
	Info    Info  // set when Accepted
	Err     error // set unless Accepted
}

// Report is the result of AddMany.
type Report struct {
	Results      []Result // every peer tried, in order
	Accepted     int      // how many peers accepted the log
	SharedGroups bool     // as in Selection
}

// AddMany adds log to the n peers Select chooses, using the capability that names each one. An unreachable peer
// is replaced by the next peer in Select's order that was not chosen, at most MaxFallback times. It returns
// ErrNoPeer if none accepted, and ctx.Err() if ctx ended first; the Report always lists the tries made.
func AddMany(ctx context.Context, id *koloid.Identity, peers []Peer, log kolosync.Source, capabilities [][]byte, n int) (Report, error) {
	if log == nil {
		return Report{}, ErrInvalidArgument
	}
	caps := map[string][]byte{}
	for _, b := range capabilities {
		if c, err := ParseCapability(b); err == nil {
			caps[string(c.Peer)] = b
		}
	}
	sel := Select(peers, log.ID(), n)
	rep := Report{SharedGroups: sel.SharedGroups}
	chosen := map[string]bool{}
	for _, p := range sel.Peers {
		chosen[string(p.ID)] = true
	}
	var spare []Peer
	for _, p := range rank(peers, log.ID()) {
		if !chosen[string(p.ID)] {
			spare = append(spare, p)
		}
	}
	try := func(p Peer) Outcome {
		r := Result{Peer: p}
		if b := caps[string(p.ID)]; b == nil {
			r.Outcome, r.Err = Refused, fmt.Errorf("%w: no capability for this peer", ErrUnauthorized)
		} else if r.Info, r.Err = Add(ctx, id, p, log, b); r.Err == nil {
			r.Outcome = Accepted
			rep.Accepted++
		} else if errors.Is(r.Err, ErrUnreachable) {
			r.Outcome = Unreachable
		} else {
			r.Outcome = Refused
		}
		rep.Results = append(rep.Results, r)
		return r.Outcome
	}
	fallback := min(MaxFallback, len(spare))
	for _, p := range sel.Peers {
		if ctx.Err() != nil {
			break
		}
		for try(p) == Unreachable && fallback > 0 && ctx.Err() == nil {
			p, spare = spare[0], spare[1:]
			fallback--
		}
	}
	if ctx.Err() != nil {
		return rep, ctx.Err()
	}
	if rep.Accepted == 0 {
		return rep, ErrNoPeer
	}
	return rep, nil
}
