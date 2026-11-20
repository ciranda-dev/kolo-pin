package pin

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kololog "github.com/ciranda-dev/kolo-log"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolosync "github.com/ciranda-dev/kolo-sync"
)

var errDiskFailed = errors.New("disk failed")

// failDeletes is a pinning peer's backend that fails its next fails log deletes, as a disk error would.
type failDeletes struct {
	kolostore.Backend
	fails  atomic.Int32
	srv    *server
	during func(*server) // called in each failing delete, while the owner's lock is held
}

func (f *failDeletes) NewBatch() kolostore.Batch {
	return &failBatch{Batch: f.Backend.NewBatch(), f: f}
}

// failBatch fails the commit of a log delete, the only batch with a DeleteRange.
type failBatch struct {
	kolostore.Batch
	f      *failDeletes
	ranged bool
}

func (b *failBatch) DeleteRange(start, end []byte) {
	b.ranged = true
	b.Batch.DeleteRange(start, end)
}

func (b *failBatch) Commit() error {
	if b.ranged && b.f.fails.Add(-1) >= 0 {
		if b.f.during != nil {
			b.f.during(b.f.srv)
		}
		return errDiskFailed
	}
	return b.Batch.Commit()
}

// arm makes the next Serve use f as its backend and records its server in f.srv; wait returns once it serves.
func (f *failDeletes) arm(t *testing.T) (wait func()) {
	t.Helper()
	ready := make(chan struct{})
	wrap = func(db kolostore.Backend) kolostore.Backend {
		f.Backend = db
		return f
	}
	served = func(s *server) {
		f.srv = s
		close(ready)
	}
	t.Cleanup(func() { wrap, served = nil, nil })
	return func() {
		<-ready
		wrap, served = nil, nil
	}
}

// manualSweep makes the pinning peers started after it sweep only when a test calls sweep. Its sweep interval,
// which is also the wait before a failed delete is tried again, is 10 minutes of the test's clock.
func manualSweep(t *testing.T) {
	sweepEvery = 10 * time.Minute
	t.Cleanup(func() { sweepEvery = 20 * time.Millisecond })
}

// failingPin starts a pinning peer whose next n log deletes fail and that sweeps only when a test calls sweep;
// after a restart its deletes work again.
func failingPin(t *testing.T, n int32, during func(*server)) (*pinPeer, *failDeletes) {
	return failingPinOpts(t, n, during, Options{})
}

func failingPinOpts(t *testing.T, n int32, during func(*server), opts Options) (*pinPeer, *failDeletes) {
	t.Helper()
	manualSweep(t)
	f := &failDeletes{during: during}
	f.fails.Store(n)
	wait := f.arm(t)
	p := startPin(t, opts)
	wait()
	return p, f
}

// logRecorder is a slog handler that keeps the messages it gets.
type logRecorder struct {
	mu   *sync.Mutex
	msgs *[]string
}

func newLogRecorder() (*slog.Logger, func(msg string) int) {
	r := logRecorder{mu: &sync.Mutex{}, msgs: &[]string{}}
	count := func(msg string) int {
		r.mu.Lock()
		defer r.mu.Unlock()
		n := 0
		for _, m := range *r.msgs {
			if m == msg {
				n++
			}
		}
		return n
	}
	return slog.New(r), count
}

func (r logRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (r logRecorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	*r.msgs = append(*r.msgs, rec.Message)
	return nil
}
func (r logRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r logRecorder) WithGroup(string) slog.Handler      { return r }

// held reports whether the pinning peer holds the log logID of owner, served or not.
func held(s *server, owner []byte, logID kololog.LogID) bool {
	o := s.lookup(owner)
	if o == nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.logs[logID] != nil
}

// failingHead serves a log whose every Head after the first fails: the pinning peer creates the log from its
// header, then its first pull fails, so it drops the new log.
type failingHead struct {
	kolosync.Source
	heads atomic.Int32
}

func (f *failingHead) Head() (kololog.Head, error) {
	if f.heads.Add(1) > 1 {
		return kololog.Head{}, kololog.ErrNoHead
	}
	return f.Source.Head()
}

// detachedLog returns a log of o as a replica, so that only the backend can make the pinning peer's delete fail.
func detachedLog(t *testing.T, o *ownerNode, values ...string) *kololog.Replica {
	t.Helper()
	l, err := kololog.New(o.id, kololog.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range values {
		if _, err := l.Append([]byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	return asReplica(t, l)
}

// A new log whose first pull fails is dropped. When the delete fails, here because the owner's log is open in the
// same process, the log stays held, empty, and the next Add of it pins it.
func TestFailedDropKeepsNewLog(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	alice := newOwner(t)
	l := alice.log(t, "a", "b")
	capb := alice.issue(t, p.Peer, Capability{})
	if _, err := Add(ctx, alice.id, p.Peer, &failingHead{Source: l}, capb); err == nil {
		t.Fatal("Add whose pull finds no head succeeded")
	}
	if in, err := Status(ctx, alice.id, p.Peer, l.ID()); err != nil || in.Entries != 0 {
		t.Fatalf("Status after the failed delete = %+v, %v; want the empty log held", in, err)
	}
	if in, err := Add(ctx, alice.id, p.Peer, l, capb); err != nil || in.Entries != 2 {
		t.Fatalf("Add after the failed delete = %+v, %v", in, err)
	}
	rep, err := pullFrom(t, ctx, p.Peer, alice.id.PublicKey(), l.ID())
	if err != nil {
		t.Fatal(err)
	}
	mustEqualEntries(t, l, rep, 2)
}

// A log whose delete failed once is deleted by the owner's Remove, and is not back after a restart.
func TestFailedDropThenRemove(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p, _ := failingPin(t, 1, nil)
	alice := newOwner(t)
	l := detachedLog(t, alice, "a", "b")
	key := alice.id.PublicKey()
	if _, err := Add(ctx, alice.id, p.Peer, &failingHead{Source: l}, alice.issue(t, p.Peer, Capability{})); err == nil {
		t.Fatal("Add whose pull finds no head succeeded")
	}
	if in, err := Status(ctx, alice.id, p.Peer, l.ID()); err != nil || in.Entries != 0 {
		t.Fatalf("Status after the failed delete = %+v, %v; want the empty log held", in, err)
	}
	if err := Remove(ctx, alice.id, p.Peer, l.ID()); err != nil {
		t.Fatalf("Remove after the failed delete = %v", err)
	}
	if _, err := Status(ctx, alice.id, p.Peer, l.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Status after Remove = %v, want ErrNotFound", err)
	}
	if _, err := pullFrom(t, ctx, p.Peer, key, l.ID()); !errors.Is(err, kolosync.ErrNotFound) {
		t.Fatalf("pull after Remove = %v, want kolosync.ErrNotFound", err)
	}
	p.restart(t)
	if _, err := Status(ctx, alice.id, p.Peer, l.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Status of the removed log after a restart = %v, want ErrNotFound", err)
	}
	if n := dataBytes(t, p, key); n != 0 {
		t.Fatalf("%d data bytes left after Remove", n)
	}
}

// When the owner's Remove fails too, it answers busy and the log stays held and served, also after a restart,
// until a Remove succeeds.
func TestFailedRemoveKeepsLog(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p, f := failingPin(t, 2, nil)
	alice := newOwner(t)
	l := detachedLog(t, alice, "a", "b")
	key := alice.id.PublicKey()
	capb := alice.issue(t, p.Peer, Capability{})
	if _, err := Add(ctx, alice.id, p.Peer, &failingHead{Source: l}, capb); err == nil {
		t.Fatal("Add whose pull finds no head succeeded")
	}
	if in, err := Add(ctx, alice.id, p.Peer, l, capb); err != nil || in.Entries != 2 {
		t.Fatalf("Add after the failed delete = %+v, %v", in, err)
	}
	if _, err := pullFrom(t, ctx, p.Peer, key, l.ID()); err != nil {
		t.Fatal(err)
	}
	if err := Remove(ctx, alice.id, p.Peer, l.ID()); !errors.Is(err, ErrBusy) {
		t.Fatalf("Remove whose delete fails = %v, want ErrBusy", err)
	}
	if n := f.fails.Load(); n > 0 {
		t.Fatalf("%d delete failures left unused", n)
	}
	if in, err := Status(ctx, alice.id, p.Peer, l.ID()); err != nil || in.Entries != 2 {
		t.Fatalf("Status after the failed Remove = %+v, %v", in, err)
	}
	rep, err := pullFrom(t, ctx, p.Peer, key, l.ID())
	if err != nil {
		t.Fatalf("pull after the failed Remove = %v", err)
	}
	mustEqualEntries(t, l, rep, 2)
	p.restart(t)
	if in, err := Status(ctx, alice.id, p.Peer, l.ID()); err != nil || in.Entries != 2 {
		t.Fatalf("Status after the failed Remove and a restart = %+v, %v", in, err)
	}
	if err := Remove(ctx, alice.id, p.Peer, l.ID()); err != nil {
		t.Fatal(err)
	}
	p.restart(t)
	if _, err := Status(ctx, alice.id, p.Peer, l.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Status of the removed log after a restart = %v, want ErrNotFound", err)
	}
}

// A log whose delete failed is held again after a restart, and the next Add pins it.
func TestFailedDropThenRestart(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p, _ := failingPin(t, 1, nil)
	alice := newOwner(t)
	l := detachedLog(t, alice, "a", "b")
	capb := alice.issue(t, p.Peer, Capability{})
	if _, err := Add(ctx, alice.id, p.Peer, &failingHead{Source: l}, capb); err == nil {
		t.Fatal("Add whose pull finds no head succeeded")
	}
	p.restart(t)
	if in, err := Add(ctx, alice.id, p.Peer, l, capb); err != nil || in.Entries != 2 {
		t.Fatalf("Add after the failed delete and a restart = %+v, %v", in, err)
	}
}

// An Add of the log sent while its delete is failing waits for the drop and then pins the log.
func TestAddDuringFailedDrop(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	alice := newOwner(t)
	l := detachedLog(t, alice, "a", "b")
	var p *pinPeer
	var capb []byte
	type result struct {
		in  Info
		err error
	}
	second := make(chan result, 1)
	p, _ = failingPin(t, 1, func(*server) {
		go func() {
			in, err := Add(ctx, alice.id, p.Peer, l, capb)
			second <- result{in, err}
		}()
	})
	capb = alice.issue(t, p.Peer, Capability{})
	if _, err := Add(ctx, alice.id, p.Peer, &failingHead{Source: l}, capb); err == nil {
		t.Fatal("Add whose pull finds no head succeeded")
	}
	if r := <-second; r.err != nil || r.in.Entries != 2 {
		t.Fatalf("Add sent during the failed delete = %+v, %v", r.in, r.err)
	}
}

// A log a narrower capability no longer covers whose delete failed is neither served nor reported, and a later
// capability that covers it again pins it.
func TestFailedDropOfUncoveredLog(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	var gaps atomic.Int32
	gap = func(*hosted) { gaps.Add(1) }
	t.Cleanup(func() { gap = nil })
	p, f := failingPin(t, 1, nil)
	alice := newOwner(t)
	l1, l2 := detachedLog(t, alice, "one"), detachedLog(t, alice, "two")
	key := alice.id.PublicKey()
	now := time.Now()
	all := alice.issue(t, p.Peer, Capability{Issued: now.Add(-2 * time.Minute)})
	for _, l := range []*kololog.Replica{l1, l2} {
		if _, err := Add(ctx, alice.id, p.Peer, l, all); err != nil {
			t.Fatal(err)
		}
	}
	narrow := alice.issue(t, p.Peer, Capability{Issued: now.Add(-time.Minute), Logs: []kololog.LogID{l1.ID()}})
	if _, err := Add(ctx, alice.id, p.Peer, l1, narrow); err != nil {
		t.Fatal(err)
	}
	if n := f.fails.Load(); n > 0 {
		t.Fatalf("%d delete failures left unused", n)
	}
	if _, err := Status(ctx, alice.id, p.Peer, l2.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Status of the uncovered log = %v, want ErrNotFound", err)
	}
	if _, err := pullFrom(t, ctx, p.Peer, key, l2.ID()); !errors.Is(err, kolosync.ErrNotFound) {
		t.Fatalf("pull of the uncovered log = %v, want kolosync.ErrNotFound", err)
	}
	if n := gaps.Load(); n != 0 {
		t.Fatalf("the uncovered log was opened for %d pulls, want 0", n)
	}
	again := alice.issue(t, p.Peer, Capability{Issued: now})
	if in, err := Add(ctx, alice.id, p.Peer, l2, again); err != nil || in.Entries != 1 {
		t.Fatalf("Add under a capability that covers the log again = %+v, %v", in, err)
	}
	rep, err := pullFrom(t, ctx, p.Peer, key, l2.ID())
	if err != nil {
		t.Fatal(err)
	}
	mustEqualEntries(t, l2, rep, 1)
}

// A log whose capability changes to one that does not cover it, with a failed delete, while a pull is between
// reading its header and offering it, is not offered.
func TestFailedDropDuringAuthorize(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	alice := newOwner(t)
	l1, l2 := detachedLog(t, alice, "one"), detachedLog(t, alice, "two")
	now := time.Now()
	var p *pinPeer
	narrowed := make(chan error, 1)
	var once sync.Once
	gap = func(*hosted) {
		once.Do(func() {
			narrow := alice.issue(t, p.Peer, Capability{Issued: now, Logs: []kololog.LogID{l1.ID()}})
			_, err := Add(ctx, alice.id, p.Peer, l1, narrow)
			narrowed <- err
		})
	}
	t.Cleanup(func() { gap = nil })
	var f *failDeletes
	p, f = failingPin(t, 1, nil)
	all := alice.issue(t, p.Peer, Capability{Issued: now.Add(-time.Minute)})
	for _, l := range []*kololog.Replica{l1, l2} {
		if _, err := Add(ctx, alice.id, p.Peer, l, all); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pullFrom(t, ctx, p.Peer, alice.id.PublicKey(), l2.ID()); !errors.Is(err, kolosync.ErrNotFound) {
		t.Fatalf("pull of a log uncovered during its first request = %v, want kolosync.ErrNotFound", err)
	}
	if err := <-narrowed; err != nil {
		t.Fatal(err)
	}
	if n := f.fails.Load(); n > 0 {
		t.Fatalf("%d delete failures left unused", n)
	}
}

// When a revoke note drops the owner's logs and a delete fails, the log is not served, a new capability pins it
// again, and a restart before that deletes it.
func TestFailedDropOnRevoke(t *testing.T) {
	for _, c := range []struct {
		name    string
		restart bool
	}{{"new capability", false}, {"restart", true}} {
		t.Run(c.name, func(t *testing.T) {
			checkGoroutines(t)
			ctx := testCtx(t)
			p, f := failingPin(t, 1, nil)
			alice := newOwner(t)
			l := detachedLog(t, alice, "a")
			key := alice.id.PublicKey()
			now := time.Now()
			if _, err := Add(ctx, alice.id, p.Peer, l, alice.issue(t, p.Peer, Capability{Issued: now.Add(-time.Minute)})); err != nil {
				t.Fatal(err)
			}
			note, err := IssueRevocation(alice.id, p.ID, now.Add(-30*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if err := Revoke(ctx, alice.id, p.Peer, note); err != nil {
				t.Fatal(err)
			}
			if _, err := Status(ctx, alice.id, p.Peer, l.ID()); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Status after the revoke = %v, want ErrNotFound", err)
			}
			if _, err := pullFrom(t, ctx, p.Peer, key, l.ID()); !errors.Is(err, kolosync.ErrNotFound) {
				t.Fatalf("pull after the revoke = %v, want kolosync.ErrNotFound", err)
			}
			if n := f.fails.Load(); n > 0 {
				t.Fatalf("%d delete failures left unused", n)
			}
			if c.restart {
				p.restart(t)
				if n := dataBytes(t, p, key); n != 0 {
					t.Fatalf("%d data bytes left after a restart", n)
				}
				return
			}
			if in, err := Add(ctx, alice.id, p.Peer, l, alice.issue(t, p.Peer, Capability{Issued: now})); err != nil || in.Entries != 1 {
				t.Fatalf("Add under a new capability = %+v, %v", in, err)
			}
			if _, err := pullFrom(t, ctx, p.Peer, key, l.ID()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Nothing can reopen a log while its delete runs: the replica's lock is held until the delete has failed.
func TestDeleteHoldsReplicaLock(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	alice := newOwner(t)
	l := detachedLog(t, alice, "a")
	var checked atomic.Bool
	p, _ := failingPin(t, 1, func(s *server) {
		// The goroutine that runs the delete holds the owner's lock.
		h := s.lookup(alice.id.PublicKey()).logs[l.ID()]
		if h.mu.TryLock() {
			h.mu.Unlock()
			t.Error("the replica's lock is not held during its delete")
		}
		checked.Store(true)
	})
	if _, err := Add(ctx, alice.id, p.Peer, &failingHead{Source: l}, alice.issue(t, p.Peer, Capability{})); err == nil {
		t.Fatal("Add whose pull finds no head succeeded")
	}
	if !checked.Load() {
		t.Fatal("the delete did not run")
	}
}

// A delete that fails when a log stops being covered, by a narrower capability, a revoke note or an expiry, is
// tried again by the next sweep, which frees the log's bytes and forgets an owner left with nothing.
func TestSweepRetriesFailedDrop(t *testing.T) {
	for _, c := range []string{"narrower", "revoked", "expired"} {
		t.Run(c, func(t *testing.T) {
			checkGoroutines(t)
			ctx := testCtx(t)
			var later atomic.Int64
			clock = func() time.Time { return time.Now().Add(time.Duration(later.Load())) }
			t.Cleanup(func() { clock = time.Now })
			p, f := failingPin(t, 1, nil)
			alice := newOwner(t)
			l1, l2 := detachedLog(t, alice, "one"), detachedLog(t, alice, "two")
			key := alice.id.PublicKey()
			now := time.Now()
			all := alice.issue(t, p.Peer, Capability{Issued: now.Add(-2 * time.Minute)})
			for _, l := range []*kololog.Replica{l1, l2} {
				if _, err := Add(ctx, alice.id, p.Peer, l, all); err != nil {
					t.Fatal(err)
				}
			}
			o := f.srv.lookup(key)
			switch c {
			case "narrower":
				narrow := alice.issue(t, p.Peer, Capability{Issued: now.Add(-time.Minute), Logs: []kololog.LogID{l1.ID()}})
				if _, err := Add(ctx, alice.id, p.Peer, l1, narrow); err != nil {
					t.Fatal(err)
				}
			case "revoked":
				note, err := IssueRevocation(alice.id, p.ID, now.Add(-time.Minute))
				if err != nil {
					t.Fatal(err)
				}
				if err := Revoke(ctx, alice.id, p.Peer, note); err != nil {
					t.Fatal(err)
				}
			case "expired":
				later.Store(int64(2 * time.Hour))
				f.srv.sweep()
			}
			if n := f.fails.Load(); n > 0 {
				t.Fatalf("%d delete failures left unused", n)
			}
			before, _ := o.sp.usage()
			o.mu.Lock()
			left := len(o.logs)
			o.mu.Unlock()
			want := 1
			if c == "narrower" {
				want = 2
			}
			if left != want {
				t.Fatalf("%d logs held after the failed delete", left)
			}
			if _, err := Status(ctx, alice.id, p.Peer, l2.ID()); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Status of the dropped log = %v, want ErrNotFound", err)
			}
			later.Add(int64(sweepEvery))
			f.srv.sweep()
			if after, _ := o.sp.usage(); after >= before {
				t.Fatalf("%d bytes used after the sweep, %d before", after, before)
			}
			if c == "narrower" {
				if held(f.srv, key, l2.ID()) || !held(f.srv, key, l1.ID()) {
					t.Fatal("the sweep did not delete only the uncovered log")
				}
				return
			}
			if f.srv.lookup(key) != nil {
				t.Fatal("an owner without a capability or a log is still in memory after the sweep")
			}
		})
	}
}

// A delete that fails at start, for a log the stored capability does not cover or for an owner no longer
// accepted, does not stop the peer: the log stays held but unserved, and the sweep deletes it.
func TestFailedDropAtStart(t *testing.T) {
	for _, c := range []string{"not covered", "owner not accepted"} {
		t.Run(c, func(t *testing.T) {
			checkGoroutines(t)
			ctx := testCtx(t)
			manualSweep(t)
			var later atomic.Int64
			clock = func() time.Time { return time.Now().Add(time.Duration(later.Load())) }
			t.Cleanup(func() { clock = time.Now })
			p := startPin(t, Options{})
			alice := newOwner(t)
			l1, l2 := detachedLog(t, alice, "one"), detachedLog(t, alice, "two")
			key := alice.id.PublicKey()
			now := time.Now()
			all := alice.issue(t, p.Peer, Capability{Issued: now.Add(-time.Minute)})
			for _, l := range []*kololog.Replica{l1, l2} {
				if _, err := Add(ctx, alice.id, p.Peer, l, all); err != nil {
					t.Fatal(err)
				}
			}
			f := &failDeletes{}
			wait := f.arm(t)
			if c == "not covered" {
				f.fails.Store(1)
				narrow := alice.issue(t, p.Peer, Capability{Issued: now, Logs: []kololog.LogID{l1.ID()}})
				p.raw(t, func(db kolostore.Backend) {
					if err := db.Put(ownerKey(pMeta, key), encodeMeta(now.Unix(), narrow, 0)); err != nil {
						t.Fatal(err)
					}
				})
			} else {
				f.fails.Store(2)
				p.opts.Owners = []ed25519.PublicKey{generate(t).PublicKey()}
				p.restart(t)
			}
			wait()
			if n := f.fails.Load(); n > 0 {
				t.Fatalf("%d delete failures left unused", n)
			}
			if !held(f.srv, key, l2.ID()) {
				t.Fatal("the log whose delete failed at start is not held")
			}
			if _, err := Status(ctx, alice.id, p.Peer, l2.ID()); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Status of the log whose delete failed at start = %v, want ErrNotFound", err)
			}
			if _, err := pullFrom(t, ctx, p.Peer, key, l2.ID()); !errors.Is(err, kolosync.ErrNotFound) {
				t.Fatalf("pull of the log whose delete failed at start = %v, want kolosync.ErrNotFound", err)
			}
			f.srv.sweep()
			if !held(f.srv, key, l2.ID()) {
				t.Fatal("the sweep tried again before the wait was over")
			}
			later.Add(int64(sweepEvery))
			f.srv.sweep()
			if held(f.srv, key, l2.ID()) {
				t.Fatal("the sweep did not delete the log")
			}
			if c == "not covered" {
				if in, err := Status(ctx, alice.id, p.Peer, l1.ID()); err != nil || in.Entries != 1 {
					t.Fatalf("Status of the covered log = %+v, %v", in, err)
				}
			} else if f.srv.lookup(key) != nil {
				t.Fatal("the owner no longer accepted is still in memory after the sweep")
			}
		})
	}
}

// blockingHead serves a log whose second Head waits for release and then fails, so a test can act while the
// pinning peer's first pull of a new log runs.
type blockingHead struct {
	kolosync.Source
	heads            atomic.Int32
	pulling, release chan struct{}
}

func (b *blockingHead) Head() (kololog.Head, error) {
	switch b.heads.Add(1) {
	case 1:
		return b.Source.Head()
	case 2:
		close(b.pulling)
		<-b.release
	}
	return kololog.Head{}, kololog.ErrNoHead
}

// An Add that finds a new log which another Add then drops answers busy, not not found, and the next Add pins it.
func TestAddRacingDrop(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	alice := newOwner(t)
	l := detachedLog(t, alice, "a", "b")
	found, dropped := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	acquiring = func(*hosted) {
		if calls.Add(1) == 2 {
			close(found)
			<-dropped
		}
	}
	t.Cleanup(func() { acquiring = nil })
	p := startPin(t, Options{})
	capb := alice.issue(t, p.Peer, Capability{})
	src := &blockingHead{Source: l, pulling: make(chan struct{}), release: make(chan struct{})}
	first, second := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := Add(ctx, alice.id, p.Peer, src, capb)
		first <- err
	}()
	<-src.pulling
	go func() {
		_, err := Add(ctx, alice.id, p.Peer, l, capb)
		second <- err
	}()
	<-found
	close(src.release)
	if err := <-first; err == nil {
		t.Fatal("Add whose pull finds no head succeeded")
	}
	close(dropped)
	if err := <-second; !errors.Is(err, ErrBusy) {
		t.Fatalf("Add of a log dropped after it was found = %v, want ErrBusy", err)
	}
	if in, err := Add(ctx, alice.id, p.Peer, l, capb); err != nil || in.Entries != 2 {
		t.Fatalf("the next Add = %+v, %v", in, err)
	}
}

// A delete that keeps failing is tried again after one sweep interval, then after twice as long each time up to
// 2^retryDoublings intervals, and it logs one warning when it first fails and one event when it finally works.
func TestFailedDropBacksOff(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	var later atomic.Int64
	clock = func() time.Time { return time.Now().Add(time.Duration(later.Load())) }
	t.Cleanup(func() { clock = time.Now })
	logger, count := newLogRecorder()
	const fails = 100
	p, f := failingPinOpts(t, fails, nil, Options{Logger: logger})
	attempts := func() int { return fails - int(f.fails.Load()) }
	alice := newOwner(t)
	l1, l2 := detachedLog(t, alice, "one"), detachedLog(t, alice, "two")
	key := alice.id.PublicKey()
	now := time.Now()
	all := alice.issue(t, p.Peer, Capability{Issued: now.Add(-2 * time.Minute), Expires: now.Add(1000 * time.Hour)})
	for _, l := range []*kololog.Replica{l1, l2} {
		if _, err := Add(ctx, alice.id, p.Peer, l, all); err != nil {
			t.Fatal(err)
		}
	}
	narrow := alice.issue(t, p.Peer, Capability{Issued: now.Add(-time.Minute), Expires: now.Add(1000 * time.Hour), Logs: []kololog.LogID{l1.ID()}})
	if _, err := Add(ctx, alice.id, p.Peer, l1, narrow); err != nil {
		t.Fatal(err)
	}
	if attempts() != 1 || !held(f.srv, key, l2.ID()) {
		t.Fatalf("%d delete attempts, held %v after the narrower capability", attempts(), held(f.srv, key, l2.ID()))
	}
	step := func(d time.Duration, want int) {
		t.Helper()
		later.Add(int64(d))
		f.srv.sweep()
		if got := attempts(); got != want {
			t.Fatalf("%d delete attempts, want %d", got, want)
		}
	}
	if sweepEvery<<retryDoublings != 64*sweepEvery {
		t.Fatalf("the longest wait is %d sweep intervals, the docs say 64", 1<<retryDoublings)
	}
	f.srv.sweep()
	if attempts() != 1 {
		t.Fatalf("the sweep tried again at once: %d attempts", attempts())
	}
	for n := 1; n <= retryDoublings+3; n++ {
		wait := sweepEvery << min(n-1, retryDoublings)
		step(wait-time.Second, n)
		step(time.Second, n+1)
	}
	if n := count("delete failed, log kept"); n != 1 {
		t.Fatalf("%d delete failed warnings, want 1", n)
	}
	if n := count("dropped") + count("dropped after retry"); n != 0 {
		t.Fatalf("%d dropped events while the log is still held", n)
	}
	f.fails.Store(0)
	later.Add(int64(sweepEvery << retryDoublings))
	f.srv.sweep()
	if held(f.srv, key, l2.ID()) {
		t.Fatal("the sweep did not delete the log once the disk worked")
	}
	if count("dropped after retry") != 1 || count("dropped") != 0 || count("delete failed, log kept") != 1 {
		t.Fatalf("events: dropped after retry %d, dropped %d, delete failed %d", count("dropped after retry"), count("dropped"), count("delete failed, log kept"))
	}
}

// A delete that works logs "dropped" once, and no warning.
func TestDropLogsOnce(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	logger, count := newLogRecorder()
	p := startPin(t, Options{Logger: logger})
	alice := newOwner(t)
	l1, l2 := detachedLog(t, alice, "one"), detachedLog(t, alice, "two")
	now := time.Now()
	for i, l := range []*kololog.Replica{l1, l2} {
		c := Capability{Issued: now.Add(-2 * time.Minute)}
		if i == 0 {
			c.Issued = now.Add(-3 * time.Minute)
		}
		if _, err := Add(ctx, alice.id, p.Peer, l, alice.issue(t, p.Peer, c)); err != nil {
			t.Fatal(err)
		}
	}
	narrow := alice.issue(t, p.Peer, Capability{Issued: now.Add(-time.Minute), Logs: []kololog.LogID{l1.ID()}})
	if _, err := Add(ctx, alice.id, p.Peer, l1, narrow); err != nil {
		t.Fatal(err)
	}
	if count("dropped") != 1 || count("delete failed, log kept") != 0 || count("dropped after retry") != 0 {
		t.Fatalf("events: dropped %d, delete failed %d, after retry %d", count("dropped"), count("delete failed, log kept"), count("dropped after retry"))
	}
}

// A log that is covered again starts over: its next failure warns again and waits one sweep interval.
func TestFailedDropStartsOverWhenCovered(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	var later atomic.Int64
	clock = func() time.Time { return time.Now().Add(time.Duration(later.Load())) }
	t.Cleanup(func() { clock = time.Now })
	logger, count := newLogRecorder()
	p, f := failingPinOpts(t, 2, nil, Options{Logger: logger})
	alice := newOwner(t)
	l1, l2 := detachedLog(t, alice, "one"), detachedLog(t, alice, "two")
	key := alice.id.PublicKey()
	now := time.Now()
	issue := func(ago time.Duration, logs ...kololog.LogID) []byte {
		return alice.issue(t, p.Peer, Capability{Issued: now.Add(-ago), Expires: now.Add(1000 * time.Hour), Logs: logs})
	}
	add := func(l *kololog.Replica, c []byte) {
		t.Helper()
		if _, err := Add(ctx, alice.id, p.Peer, l, c); err != nil {
			t.Fatal(err)
		}
	}
	all, narrow := issue(4*time.Minute), []kololog.LogID{l1.ID()}
	add(l1, all)
	add(l2, all)
	add(l1, issue(3*time.Minute, narrow...))
	if f.fails.Load() != 1 || !held(f.srv, key, l2.ID()) || count("delete failed, log kept") != 1 {
		t.Fatalf("after the first failure: %d failures left, held %v", f.fails.Load(), held(f.srv, key, l2.ID()))
	}
	add(l2, issue(2*time.Minute))
	add(l1, issue(time.Minute, narrow...))
	if f.fails.Load() != 0 || count("delete failed, log kept") != 2 {
		t.Fatalf("after the second failure: %d failures left, %d warnings", f.fails.Load(), count("delete failed, log kept"))
	}
	later.Add(int64(sweepEvery - time.Second))
	f.srv.sweep()
	if !held(f.srv, key, l2.ID()) {
		t.Fatal("the sweep tried again before one sweep interval")
	}
	later.Add(int64(time.Second))
	f.srv.sweep()
	if held(f.srv, key, l2.ID()) || count("dropped after retry") != 1 {
		t.Fatalf("held %v, %d dropped after retry events after one sweep interval", held(f.srv, key, l2.ID()), count("dropped after retry"))
	}
}
