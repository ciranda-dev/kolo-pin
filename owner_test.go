package pin

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	koloid "github.com/ciranda-dev/kolo-id"
	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolosync "github.com/ciranda-dev/kolo-sync"
)

// logWithID returns a new log of id whose log ID is logID, as any owner can make: log IDs are not secret.
func logWithID(t *testing.T, id *koloid.Identity, logID kololog.LogID, values ...string) *kololog.Log {
	t.Helper()
	l, err := kololog.New(id, kololog.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	head, err := l.Head()
	if err != nil {
		t.Fatal(err)
	}
	from := l.ID()
	resign := func(context string, enc []byte) []byte {
		signed := bytes.Clone(enc[:len(enc)-64])
		i := bytes.Index(signed, from[:])
		if i < 0 {
			t.Fatal("log ID not found in the encoding")
		}
		copy(signed[i:], logID[:])
		sig, err := id.Sign(context, signed)
		if err != nil {
			t.Fatal(err)
		}
		return append(signed, sig...)
	}
	r, err := kololog.Restore(id, resign(kololog.HeaderContext, l.Header().Encode()), resign(kololog.HeadContext, head.Encode()), kololog.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	if r.ID() != logID {
		t.Fatalf("restored log has ID %x", r.ID())
	}
	for _, v := range values {
		if _, err := r.Append([]byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

// asReplica copies l into a replica and closes l, so that deleting a pinned log with its ID is not refused
// because a writable log with that ID is open in this test process.
func asReplica(t *testing.T, l *kololog.Log) *kololog.Replica {
	t.Helper()
	r, err := kololog.NewReplica(l.Header().LogKey, l.ID(), l.Header().Encode(), kololog.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	h, err := l.Head()
	if err != nil {
		t.Fatal(err)
	}
	p, err := l.ConsistencyProof(0, h.Size)
	if err != nil {
		t.Fatal(err)
	}
	var entries []kololog.Entry
	for i := range h.Size {
		e, err := l.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, e)
	}
	if err := r.Update(h, p, entries); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return r
}

// A log is identified by its owner and its ID: another owner's log with the same ID is pinned, served, fetched
// and dropped on its own and never replaces the first.
func TestSameLogIDTwoOwners(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	alice, bob := newOwner(t), newOwner(t)
	first, err := kololog.New(alice.id, kololog.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"a", "b"} {
		if _, err := first.Append([]byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	al := asReplica(t, first)
	bl := asReplica(t, logWithID(t, bob.id, al.ID(), "x", "y", "z"))
	if _, err := Add(ctx, alice.id, p.Peer, al, alice.issue(t, p.Peer, Capability{})); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, bob.id, p.Peer, bl, bob.issue(t, p.Peer, Capability{})); err != nil {
		t.Fatal(err)
	}
	served := func(o *ownerNode, src kolosync.Source, n uint64) {
		t.Helper()
		rep, err := pullFrom(t, ctx, p.Peer, o.id.PublicKey(), src.ID())
		if err != nil {
			t.Fatal(err)
		}
		mustEqualEntries(t, src, rep, n)
		conn, err := kolosecure.Dial(ctx, p.Addr, generate(t), p.ID, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		h, err := kolosync.FetchHead(ctx, conn, o.id.PublicKey(), src.ID())
		if err != nil || h.Size() != n {
			t.Fatalf("FetchHead: size %d, %v; want %d", h.Size(), err, n)
		}
		got, err := kolosync.Fetch(ctx, conn, h, 0, n-1)
		if err != nil || uint64(len(got)) != n {
			t.Fatalf("Fetch: %d entries, %v", len(got), err)
		}
	}
	gone := func(o *ownerNode, id kololog.LogID) {
		t.Helper()
		if _, err := pullFrom(t, ctx, p.Peer, o.id.PublicKey(), id); !errors.Is(err, kolosync.ErrNotFound) {
			t.Fatalf("pull of a dropped log = %v, want kolosync.ErrNotFound", err)
		}
	}
	served(alice, al, 2)
	served(bob, bl, 3)

	// Started again, the peer offers each log under its own owner.
	p.restart(t)
	served(bob, bl, 3)
	served(alice, al, 2)

	if err := Remove(ctx, bob.id, p.Peer, bl.ID()); err != nil {
		t.Fatal(err)
	}
	gone(bob, bl.ID())
	served(alice, al, 2)
	if _, err := Add(ctx, bob.id, p.Peer, bl, bob.issue(t, p.Peer, Capability{})); err != nil {
		t.Fatal(err)
	}
	served(bob, bl, 3)
	note, err := IssueRevocation(alice.id, p.ID, timeIn(0))
	if err != nil {
		t.Fatal(err)
	}
	if err := Revoke(ctx, generate(t), p.Peer, note); err != nil {
		t.Fatal(err)
	}
	gone(alice, al.ID())
	served(bob, bl, 3)
}

type noOwner struct{ kolosync.Source }

func (noOwner) Header() kololog.LogHeader { return kololog.LogHeader{} }

func TestAddLogWithoutOwner(t *testing.T) {
	ctx := testCtx(t)
	alice := newOwner(t)
	l := alice.log(t, "a")
	peer := Peer{ID: generate(t).PublicKey(), Addr: "127.0.0.1:9"}
	if _, err := Add(ctx, alice.id, peer, noOwner{l}, alice.issue(t, peer, Capability{})); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Add of a log whose header has no owner key = %v, want ErrInvalidArgument", err)
	}
}

// Add serves its log with Ciphertext access only: a pinning peer that asks for the keys gets none.
func TestAddNeverSendsKeys(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	fake := generate(t)
	ln, err := kolosecure.Listen(ctx, "127.0.0.1:0", fake, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	alice := newOwner(t)
	l := alice.log(t, "a", "b")
	peer := Peer{ID: fake.PublicKey(), Addr: ln.Addr().String()}
	added := make(chan error, 1)
	go func() {
		_, err := Add(ctx, alice.id, peer, l, alice.issue(t, peer, Capability{}))
		added <- err
	}()
	conn, err := ln.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st := kolostore.New(kolostore.NewMemory())
	defer st.Close()
	header, err := kolosync.FetchHeader(ctx, conn, alice.id.PublicKey(), l.ID())
	if err != nil {
		t.Fatal(err)
	}
	rep, err := st.OpenReplica(alice.id.PublicKey(), l.ID(), header)
	if err != nil {
		t.Fatal(err)
	}
	if err := kolosync.Pull(ctx, conn, rep); err != nil {
		t.Fatal(err)
	}
	if rep.Len() != 2 {
		t.Fatalf("pulled %d entries, want 2", rep.Len())
	}
	for i := range rep.Len() {
		if info, err := rep.EntryInfo(i); err != nil || info.Keyed {
			t.Fatalf("entry %d pulled from Add: %+v, %v", i, info, err)
		}
	}
	_ = conn.Close()
	if err := <-added; !errors.Is(err, ErrUnreachable) {
		t.Fatalf("Add to a peer that never answers = %v, want ErrUnreachable", err)
	}
}

// A log removed while its Add is between reading its header and offering it is never offered: every pull of it,
// also after a restart, gets not found.
func TestRemoveDuringOffer(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	alice := newOwner(t)
	first, err := kololog.New(alice.id, kololog.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Append([]byte("a")); err != nil {
		t.Fatal(err)
	}
	l := asReplica(t, first)
	var p *pinPeer
	removed := make(chan error, 1)
	var once sync.Once
	gap = func(h *hosted) {
		h.mu.Lock()
		read := h.head.LogKey != nil
		h.mu.Unlock()
		if !read {
			t.Error("the header was not read before the owner's lock was taken")
		}
		once.Do(func() { removed <- Remove(ctx, alice.id, p.Peer, l.ID()) })
	}
	t.Cleanup(func() { gap = nil })
	p = startPin(t, Options{})
	if _, err := Add(ctx, alice.id, p.Peer, l, alice.issue(t, p.Peer, Capability{})); err != nil {
		t.Fatal(err)
	}
	p.restart(t)
	for range 2 {
		if _, err := pullFrom(t, ctx, p.Peer, alice.id.PublicKey(), l.ID()); !errors.Is(err, kolosync.ErrNotFound) {
			t.Fatalf("pull of a log removed during its first request = %v, want kolosync.ErrNotFound", err)
		}
	}
	if err := <-removed; err != nil {
		t.Fatal(err)
	}
}

// A hosted log is offered when its Add finishes and once; requests skip the header check and Offer.
func TestOfferedOnce(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	var srv *server
	served = func(s *server) { srv = s }
	var gaps atomic.Int32
	gap = func(*hosted) { gaps.Add(1) }
	t.Cleanup(func() { served, gap = nil, nil })
	p := startPin(t, Options{})
	alice := newOwner(t)
	l := alice.log(t, "a")
	if _, err := Add(ctx, alice.id, p.Peer, l, alice.issue(t, p.Peer, Capability{})); err != nil {
		t.Fatal(err)
	}
	o := srv.lookup(alice.id.PublicKey())
	offered := func() bool {
		o.mu.Lock()
		defer o.mu.Unlock()
		return o.logs[l.ID()].offered
	}
	if !offered() {
		t.Fatal("not offered when its Add finished")
	}
	if _, err := pullFrom(t, ctx, p.Peer, alice.id.PublicKey(), l.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := pullFrom(t, ctx, p.Peer, alice.id.PublicKey(), l.ID()); err != nil {
		t.Fatal(err)
	}
	if n := gaps.Load(); n != 1 {
		t.Fatalf("the log was offered %d times over an Add and two pulls, want 1", n)
	}
}
