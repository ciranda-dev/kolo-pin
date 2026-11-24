package pin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolosync "github.com/ciranda-dev/kolo-sync"
)

// capture sets the served hook for one pinning peer started after it, and returns its server.
func capture(t *testing.T) func() *server {
	t.Helper()
	ch := make(chan *server, 1)
	served = func(s *server) { ch <- s }
	t.Cleanup(func() { served = nil })
	var s *server
	return func() *server {
		if s == nil {
			s = <-ch
			served = nil
		}
		return s
	}
}

// addOffering sends ADD on a connection where the client serves l with the given access.
func addOffering(t *testing.T, ctx context.Context, p Peer, o *ownerNode, l kolosync.Source, capb []byte, a kolosync.Access) error {
	t.Helper()
	conn, err := kolosecure.Dial(ctx, p.Addr, o.id, p.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	srv := kolosync.NewServer(func(_, _ ed25519.PublicKey, _ kololog.LogID) kolosync.Access { return a })
	_ = srv.Offer(l)
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() { _ = srv.Serve(sctx, conn); close(done) }()
	defer func() { cancel(); conn.Close(); <-done }()
	b, err := call(ctx, conn, request{typ: tAdd, logID: l.ID(), data: capb})
	if err != nil {
		t.Fatal(err)
	}
	_, err = decodeAnswer(b, true)
	return err
}

func entryKeys(t *testing.T, l *kolostore.Log) [][]byte {
	t.Helper()
	var keys [][]byte
	for i := range l.Len() {
		e, err := l.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		if e.Key != nil {
			keys = append(keys, e.Key)
		}
	}
	return keys
}

// A client that offers entry keys is never asked for them, and the pinning peer stores none.
func TestOfferedKeysRefused(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	alice := newOwner(t)
	fresh := alice.log(t, "secret one", "secret two")
	pinned := alice.log(t, "kept")
	capb := alice.issue(t, p.Peer, Capability{})
	if err := addOffering(t, ctx, p.Peer, alice, fresh, capb, kolosync.Keys); err != nil {
		t.Fatalf("Add of a new log offered with keys = %v", err)
	}
	if _, err := Add(ctx, alice.id, p.Peer, pinned, capb); err != nil {
		t.Fatal(err)
	}
	if _, err := pinned.Append([]byte("secret three")); err != nil {
		t.Fatal(err)
	}
	if err := addOffering(t, ctx, p.Peer, alice, pinned, capb, kolosync.Keys); err != nil {
		t.Fatalf("refresh offered with keys = %v", err)
	}
	dump := p.dump(t)
	for i, k := range append(entryKeys(t, fresh), entryKeys(t, pinned)...) {
		if bytes.Contains(dump, k) {
			t.Errorf("entry key %d stored on the pinning peer", i)
		}
	}
}

// An ADD whose client never answers holds no lock the sweep needs: other owners' logs still expire.
func TestStalledAddDoesNotStallSweep(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	var later atomic.Int64
	clock = func() time.Time { return time.Now().Add(time.Duration(later.Load())) }
	t.Cleanup(func() { clock = time.Now })
	get := capture(t)
	p := startPin(t, Options{})
	srv := get()
	type victim struct {
		o  *ownerNode
		id kololog.LogID
	}
	var victims []victim
	for range 3 {
		v := newOwner(t)
		l := v.log(t, "v")
		if _, err := Add(ctx, v.id, p.Peer, l, v.issue(t, p.Peer, Capability{})); err != nil {
			t.Fatal(err)
		}
		_ = l.Close()
		victims = append(victims, victim{v, l.ID()})
	}
	mallory := newOwner(t)
	conn, err := kolosecure.Dial(ctx, p.Addr, mallory.id, p.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ss, err := conn.OpenUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mc := mallory.issue(t, p.Peer, Capability{Expires: time.Now().Add(3 * time.Hour)})
	_, _ = ss.Write(request{typ: tAdd, logID: kololog.LogID{1}, data: mc}.encode())
	_ = ss.Close()
	// The capability is installed before the peer asks the client for the log's header, where the ADD now waits.
	eventually(t, "the stalled ADD", func() bool {
		o := srv.lookup(mallory.id.PublicKey())
		if o == nil {
			return false
		}
		o.mu.Lock()
		defer o.mu.Unlock()
		return o.capb != nil
	})
	later.Store(int64(2 * time.Hour))
	deadline := time.Now().Add(5 * time.Second)
	for _, v := range victims {
		for {
			_, err := pullFrom(t, ctx, p.Peer, v.o.id.PublicKey(), v.id)
			if errors.Is(err, kolosync.ErrNotFound) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("a victim's log is still served after expiry during a stalled ADD: %v", err)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

// Refused ADDs on a full disk leave no owner in memory.
func TestRefusedOwnersNotKept(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	get := capture(t)
	p := startPin(t, Options{MaxBytes: 1})
	for range 10 {
		o := newOwner(t)
		if _, err := Add(ctx, o.id, p.Peer, o.log(t, "x"), o.issue(t, p.Peer, Capability{})); !errors.Is(err, ErrDiskFull) {
			t.Fatalf("Add on a full disk = %v", err)
		}
		_, _ = Add(ctx, o.id, p.Peer, o.log(t, "y"), o.issue(t, Peer{ID: generate(t).PublicKey()}, Capability{}))
	}
	s := get()
	s.mu.Lock()
	n := len(s.owners)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d owners in memory after refused ADDs", n)
	}
}

// A revoke note for an owner the peer has never seen is stored, also across a restart.
func TestRevokeBeforeFirstUse(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	get := capture(t)
	p := startPin(t, Options{})
	alice := newOwner(t)
	l := alice.log(t, "x")
	now := time.Now()
	old := alice.issue(t, p.Peer, Capability{Issued: now.Add(-time.Minute)})
	note, err := IssueRevocation(alice.id, p.ID, now.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := Revoke(ctx, generate(t), p.Peer, note); err != nil {
		t.Fatal(err)
	}
	s := get()
	s.mu.Lock()
	n := len(s.owners)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d owners in memory after a revoke note alone", n)
	}
	p.restart(t)
	if _, err := Add(ctx, alice.id, p.Peer, l, old); !errors.Is(err, ErrRevoked) {
		t.Fatalf("Add with a token revoked before first use = %v, want ErrRevoked", err)
	}
	if _, err := Add(ctx, alice.id, p.Peer, l, alice.issue(t, p.Peer, Capability{Issued: now})); err != nil {
		t.Fatalf("Add with a token issued after the note = %v", err)
	}
}

// A revoke note dated in the future is refused, so it cannot lock the owner out.
func TestRevokeFutureRefused(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	alice := newOwner(t)
	note, err := IssueRevocation(alice.id, p.ID, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := Revoke(ctx, generate(t), p.Peer, note); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoke note an hour ahead = %v, want ErrUnauthorized", err)
	}
	p.restart(t)
	if _, err := Add(ctx, alice.id, p.Peer, alice.log(t, "y"), alice.issue(t, p.Peer, Capability{})); err != nil {
		t.Fatalf("Add after the refused note = %v", err)
	}
}

// Open replicas stay within MaxOpenBytes: reading more closes the least recently used ones.
func TestOpenReplicasCapped(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	get := capture(t)
	p := startPin(t, Options{MaxOpenBytes: 2 * openCost(1)})
	alice := newOwner(t)
	c := alice.issue(t, p.Peer, Capability{})
	var logs []*kolostore.Log
	for i := range 5 {
		l := alice.log(t, fmt.Sprint("log ", i))
		if _, err := Add(ctx, alice.id, p.Peer, l, c); err != nil {
			t.Fatal(err)
		}
		logs = append(logs, l)
	}
	for _, l := range logs {
		rep, err := pullFrom(t, ctx, p.Peer, alice.id.PublicKey(), l.ID())
		if err != nil {
			t.Fatal(err)
		}
		mustEqualEntries(t, l, rep, 1)
	}
	s := get()
	s.openMu.Lock()
	n := len(s.open)
	s.openMu.Unlock()
	if n > 2 {
		t.Fatalf("%d replicas open, cap 2", n)
	}
}

// Many small logs stay open together under the byte budget, and one large log alone past it closes the idle others.
func TestOpenLogsByBytes(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	get := capture(t)
	p := startPin(t, Options{MaxOpenBytes: openCost(20)})
	s := get()
	alice := newOwner(t)
	c := alice.issue(t, p.Peer, Capability{})
	open := func() int {
		s.openMu.Lock()
		defer s.openMu.Unlock()
		return len(s.open)
	}
	for i := range 5 {
		if _, err := Add(ctx, alice.id, p.Peer, alice.log(t, fmt.Sprint("log ", i)), c); err != nil {
			t.Fatal(err)
		}
	}
	if n := open(); n != 5 {
		t.Fatalf("%d small logs open, want 5", n)
	}
	var values []string
	for i := range 40 {
		values = append(values, fmt.Sprint("entry ", i))
	}
	big := alice.log(t, values...)
	if _, err := Add(ctx, alice.id, p.Peer, big, c); err != nil {
		t.Fatal(err)
	}
	if n := open(); n != 1 {
		t.Fatalf("%d logs open after one past the budget, want only that one", n)
	}
}

// A log that grows past the budget by a pull closes the idle ones, though it was already open.
func TestGrowthClosesIdleLogs(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	get := capture(t)
	p := startPin(t, Options{MaxOpenBytes: openCost(20)})
	s := get()
	alice := newOwner(t)
	c := alice.issue(t, p.Peer, Capability{})
	small, grown := alice.log(t, "a"), alice.log(t, "b")
	for _, l := range []*kolostore.Log{small, grown} {
		if _, err := Add(ctx, alice.id, p.Peer, l, c); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 40 {
		if _, err := grown.Append(fmt.Appendf(nil, "entry %d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Add(ctx, alice.id, p.Peer, grown, c); err != nil {
		t.Fatal(err)
	}
	s.openMu.Lock()
	n := len(s.open)
	s.openMu.Unlock()
	if n != 1 {
		t.Fatalf("%d logs open after one grew past the budget, want 1", n)
	}
}

// The default budget holds far more than 64 small logs open at once.
func TestManySmallLogsOpen(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	get := capture(t)
	p := startPin(t, Options{})
	s := get()
	alice := newOwner(t)
	c := alice.issue(t, p.Peer, Capability{})
	for i := range 100 {
		if _, err := Add(ctx, alice.id, p.Peer, alice.log(t, fmt.Sprint("log ", i)), c); err != nil {
			t.Fatal(err)
		}
	}
	s.openMu.Lock()
	n := len(s.open)
	s.openMu.Unlock()
	if n != 100 {
		t.Fatalf("%d logs open, want 100", n)
	}
}

// The idle sweep and the open cap never close a replica while a pull fills it.
func TestRunningPullNotClosed(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	idleAfter = time.Nanosecond
	t.Cleanup(func() { idleAfter = time.Minute })
	p := startPin(t, Options{MaxOpenBytes: 1})
	alice := newOwner(t)
	var values []string
	for i := range 16 {
		values = append(values, fmt.Sprintf("%d%s", i, make([]byte, 512<<10)))
	}
	l := alice.log(t, values...)
	other := alice.log(t, "other")
	c := alice.issue(t, p.Peer, Capability{})
	if _, err := Add(ctx, alice.id, p.Peer, other, c); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = pullFrom(t, ctx, p.Peer, alice.id.PublicKey(), other.ID())
			}
		}
	}()
	in, err := Add(ctx, alice.id, p.Peer, l, c)
	close(stop)
	<-readerDone
	if err != nil || in.Entries != 16 {
		t.Fatalf("Add while the sweep and other reads run = %+v, %v", in, err)
	}
}

// A new log whose first pull fails is not kept, even empty.
func TestFailedNewLogDropped(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	alice := newOwner(t)
	// Served from a replica, with the owner's log closed: kolo-store deletes a replica only then.
	l := alice.log(t, "a", "b")
	h, err := l.Head()
	if err != nil {
		t.Fatal(err)
	}
	src, err := kololog.NewReplica(alice.id.PublicKey(), l.ID(), l.Header().Encode(), kololog.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	var entries []kololog.Entry
	for i := range l.Len() {
		e, err := l.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}
	if err := src.Update(h, kololog.ConsistencyProof{}, entries); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	bad := tampered{src, 0, func(e kololog.Entry) (kololog.Entry, error) { e.Ciphertext[3] ^= 1; return e, nil }}
	if _, err := Add(ctx, alice.id, p.Peer, bad, alice.issue(t, p.Peer, Capability{})); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Add of a forged new log = %v", err)
	}
	if in, err := Status(ctx, alice.id, p.Peer, l.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Status after the failed first pull = %+v, %v; want ErrNotFound", in, err)
	}
}

// Status answers not found as soon as the capability expires, before the sweep deletes anything.
func TestStatusAfterExpiryBeforeSweep(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	var later atomic.Int64
	clock = func() time.Time { return time.Now().Add(time.Duration(later.Load())) }
	sweepEvery = time.Hour
	t.Cleanup(func() { clock, sweepEvery = time.Now, 20*time.Millisecond })
	p := startPin(t, Options{})
	alice := newOwner(t)
	l := alice.log(t, "x")
	if _, err := Add(ctx, alice.id, p.Peer, l, alice.issue(t, p.Peer, Capability{})); err != nil {
		t.Fatal(err)
	}
	later.Store(int64(2 * time.Hour))
	if _, err := Status(ctx, alice.id, p.Peer, l.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Status after expiry = %v, want ErrNotFound", err)
	}
}
