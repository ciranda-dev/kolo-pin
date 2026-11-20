package pin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	kolodht "github.com/ciranda-dev/kolo-dht"
	kololog "github.com/ciranda-dev/kolo-log"
)

// heavier reports whether a has a higher rendezvous weight for logID than b.
func heavier(logID kololog.LogID, a, b ed25519.PublicKey) bool {
	wa, wb := weight(a, logID), weight(b, logID)
	return bytes.Compare(wa[:], wb[:]) > 0
}

func samePeers(a, b []Peer) bool {
	return slices.EqualFunc(a, b, func(x, y Peer) bool { return x.ID.Equal(y.ID) })
}

// randomPeers returns n peers with IDs from a fixed seed, so every run measures the same layout.
func randomPeers(r *rand.Rand, n int, groups ...string) []Peer {
	out := make([]Peer, n)
	for i := range out {
		id := make([]byte, 32)
		for j := range id {
			id[j] = byte(r.Uint32())
		}
		out[i] = Peer{ID: id, Addr: fmt.Sprintf("127.0.0.1:%d", 7000+i)}
		if len(groups) > 0 {
			out[i].Group = groups[i%len(groups)]
		}
	}
	return out
}

func randomLog(r *rand.Rand) kololog.LogID {
	var id kololog.LogID
	for j := range id {
		id[j] = byte(r.Uint32())
	}
	return id
}

func TestSelectDeterministic(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	peers := randomPeers(r, 12)
	logID := randomLog(r)
	sel := Select(peers, logID, 3)
	if len(sel.Peers) != 3 || sel.SharedGroups {
		t.Fatalf("Select = %d peers, shared %v", len(sel.Peers), sel.SharedGroups)
	}
	all := rank(peers, logID)
	if !samePeers(sel.Peers, all[:3]) {
		t.Fatal("Select without groups did not return the 3 heaviest peers")
	}
	for range 20 {
		shuffled := slices.Clone(peers)
		r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		if again := Select(append(shuffled, shuffled[0]), logID, 3); !samePeers(again.Peers, sel.Peers) {
			t.Fatal("Select depends on input order or repeats")
		}
	}
	if got := Select(peers, logID, 0); len(got.Peers) != DefaultCopies {
		t.Fatalf("Select with n 0 chose %d peers", len(got.Peers))
	}
	dup := Peer{ID: peers[0].ID, Group: "other", Addr: "127.0.0.1:1"}
	a, b := Select(append(slices.Clone(peers), dup), logID, 12), Select(append([]Peer{dup}, peers...), logID, 12)
	if !slices.EqualFunc(a.Peers, b.Peers, func(x, y Peer) bool { return x.ID.Equal(y.ID) && x.Group == y.Group && x.Addr == y.Addr }) {
		t.Fatal("a repeated ID with another group makes Select depend on input order")
	}
	bad := append(slices.Clone(peers), Peer{ID: []byte{1, 2}})
	if got := Select(bad, logID, 100); len(got.Peers) != len(peers) {
		t.Fatalf("Select kept an invalid ID: %d peers", len(got.Peers))
	}
}

func TestSelectGroups(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	for range 200 {
		peers := randomPeers(r, 9, "eu", "us", "asia")
		logID := randomLog(r)
		sel := Select(peers, logID, 3)
		groups := map[string]bool{}
		for _, p := range sel.Peers {
			groups[p.Group] = true
		}
		if len(groups) != 3 || sel.SharedGroups {
			t.Fatalf("3 peers from %d groups, shared %v", len(groups), sel.SharedGroups)
		}
		// Each chosen peer is the heaviest of its group.
		for _, p := range sel.Peers {
			for _, q := range peers {
				if q.Group == p.Group && heavier(logID, q.ID, p.ID) {
					t.Fatal("a heavier peer of the same group was skipped")
				}
			}
		}
		if sel = Select(peers, logID, 5); len(sel.Peers) != 5 || !sel.SharedGroups {
			t.Fatalf("5 peers from 3 groups: %d peers, shared %v", len(sel.Peers), sel.SharedGroups)
		}
	}
}

// moved returns the share of logs whose chosen set changes between two peer lists, and checks each changes by at most one peer.
func moved(t *testing.T, logs []kololog.LogID, before, after []Peer, n int, pick func([]Peer, kololog.LogID, int) []Peer) float64 {
	t.Helper()
	count := 0
	for _, id := range logs {
		a, b := pick(before, id, n), pick(after, id, n)
		diff := 0
		for _, p := range b {
			if !slices.ContainsFunc(a, func(q Peer) bool { return q.ID.Equal(p.ID) }) {
				diff++
			}
		}
		if diff > 1 {
			t.Fatalf("one peer added or removed changed %d of a log's peers", diff)
		}
		count += diff
	}
	return float64(count) / float64(len(logs))
}

// xorPick is the alternative measured against Select: the n peers closest to the log ID by XOR distance.
func xorPick(peers []Peer, id kololog.LogID, n int) []Peer {
	out := slices.Clone(peers)
	slices.SortFunc(out, func(a, b Peer) int {
		da, db := kolodht.Distance([32]byte(id), [32]byte(a.ID)), kolodht.Distance([32]byte(id), [32]byte(b.ID))
		return bytes.Compare(da[:], db[:])
	})
	return out[:min(n, len(out))]
}

func hrwPick(peers []Peer, id kololog.LogID, n int) []Peer { return Select(peers, id, n).Peers }

func load(logs []kololog.LogID, peers []Peer, n int, pick func([]Peer, kololog.LogID, int) []Peer) (maxShare float64) {
	per := map[string]int{}
	for _, id := range logs {
		for _, p := range pick(peers, id, n) {
			per[string(p.ID)]++
		}
	}
	m := 0
	for _, c := range per {
		m = max(m, c)
	}
	mean := float64(len(logs)*n) / float64(len(peers))
	return float64(m) / mean
}

// When one peer joins or leaves, a log moves only if that peer is among its n chosen ones: n/(N+1) of the
// logs on average for random IDs, for rendezvous and XOR alike. The test allows 1.5 times that over the rounds,
// and checks that rendezvous spreads the logs evenly where XOR does not.
func TestSelectMovesFewLogs(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	const peersN, n, logsN, rounds = 20, 2, 1000, 10
	logs := make([]kololog.LogID, logsN)
	for i := range logs {
		logs[i] = randomLog(r)
	}
	expect := float64(n) / float64(peersN+1)
	var xorAdd, hrwAdd, xorDel, hrwDel, xorLoad, hrwLoad float64
	for range rounds {
		peers := randomPeers(r, peersN+1)
		xorAdd += moved(t, logs, peers[:peersN], peers, n, xorPick) / rounds
		hrwAdd += moved(t, logs, peers[:peersN], peers, n, hrwPick) / rounds
		xorDel += moved(t, logs, peers, peers[1:], n, xorPick) / rounds
		hrwDel += moved(t, logs, peers, peers[1:], n, hrwPick) / rounds
		xorLoad = max(xorLoad, load(logs, peers, n, xorPick))
		hrwLoad = max(hrwLoad, load(logs, peers, n, hrwPick))
	}
	t.Logf("expected %.3f; moved on join: xor %.3f, hrw %.3f; on leave: xor %.3f, hrw %.3f", expect, xorAdd, hrwAdd, xorDel, hrwDel)
	t.Logf("busiest peer over the mean: xor %.2f, hrw %.2f", xorLoad, hrwLoad)
	if hrwAdd > 1.5*expect || hrwDel > 1.5*expect {
		t.Fatalf("Select moved %.3f and %.3f of the logs, bound %.3f", hrwAdd, hrwDel, 1.5*expect)
	}
	if hrwLoad > 1.6 || hrwLoad >= xorLoad {
		t.Fatalf("busiest peer at %.2f of the mean with Select, %.2f with XOR", hrwLoad, xorLoad)
	}
}

// AddMany falls back to the next closest peer when a chosen one is down, and reports each try.
func TestAddManyFallback(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	alice := newOwner(t)
	l := alice.log(t, "x", "y")
	var pins []*pinPeer
	var peers []Peer
	for range 3 {
		p := startPin(t, Options{})
		pins = append(pins, p)
		peers = append(peers, p.Peer)
	}
	order := rank(peers, l.ID())
	caps, err := IssueMany(alice.id, peers, Capability{Expires: timeIn(3600)})
	if err != nil || len(caps) != 3 {
		t.Fatalf("IssueMany = %d, %v", len(caps), err)
	}
	for _, p := range pins {
		if p.ID.Equal(order[0].ID) {
			p.stop(t)
		}
	}
	rep, err := AddMany(ctx, alice.id, peers, l, caps, 2)
	if err != nil || rep.Accepted != 2 || len(rep.Results) != 3 {
		t.Fatalf("AddMany = %+v, %v", rep, err)
	}
	// The first chosen peer is down, so the spare (third in order) replaces it before the second chosen one.
	want := []struct {
		rank    int
		outcome Outcome
	}{{0, Unreachable}, {2, Accepted}, {1, Accepted}}
	for i, res := range rep.Results {
		if !res.Peer.ID.Equal(order[want[i].rank].ID) || res.Outcome != want[i].outcome {
			t.Fatalf("try %d: peer %v, %v; want rank %d, %v", i, res.Peer.ID, res.Outcome, want[i].rank, want[i].outcome)
		}
	}
	if !errors.Is(rep.Results[0].Err, ErrUnreachable) || rep.Results[1].Info.Entries != 2 {
		t.Fatalf("results = %+v", rep.Results)
	}

	// No capability for any peer: every try is refused and AddMany fails.
	rep, err = AddMany(ctx, alice.id, peers[1:], l, nil, 2)
	if !errors.Is(err, ErrNoPeer) || rep.Accepted != 0 || rep.Results[0].Outcome != Refused {
		t.Fatalf("AddMany without capabilities = %+v, %v", rep, err)
	}
	done, cancel := context.WithCancel(ctx)
	cancel()
	if rep, err := AddMany(done, alice.id, peers, l, caps, 2); !errors.Is(err, context.Canceled) || rep.Accepted != 0 {
		t.Fatalf("AddMany with an ended context = %+v, %v; want context.Canceled", rep, err)
	}
	if _, err := AddMany(context.Background(), alice.id, peers, nil, caps, 2); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("AddMany(nil log) = %v", err)
	}
}
