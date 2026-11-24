package pin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"log/slog"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kololog "github.com/ciranda-dev/kolo-log"
	kolostore "github.com/ciranda-dev/kolo-store"
	"github.com/prometheus/client_golang/prometheus"
)

// metaRecords counts the owner records on the peer's disk.
func metaRecords(t *testing.T, p *pinPeer) (n int) {
	t.Helper()
	p.raw(t, func(db kolostore.Backend) {
		if err := db.Scan([]byte{pMeta}, []byte{pMeta + 1}, false, 0, func(_, _ []byte) bool { n++; return true }); err != nil {
			t.Fatal(err)
		}
	})
	return n
}

func revokeNote(t *testing.T, p *pinPeer, owner *ownerNode, through time.Time) []byte {
	t.Helper()
	note, err := IssueRevocation(owner.id, p.ID, through)
	if err != nil {
		t.Fatal(err)
	}
	return note
}

// An open peer keeps at most MaxOwners owner records, however many keys send revoke notes or capabilities; an owner
// already kept is never refused, and its one record does not grow with its notes.
func TestOwnerLimitBoundsFlood(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	const max = 5
	get := capture(t)
	p := startPin(t, Options{MaxOwners: max})
	s := get()
	now := time.Now()
	var kept []*ownerNode
	for i := range 4 * max {
		o := newOwner(t)
		err := Revoke(ctx, generate(t), p.Peer, revokeNote(t, p, o, now.Add(-time.Second)))
		switch {
		case i < max && err != nil:
			t.Fatalf("note %d = %v", i, err)
		case i < max:
			kept = append(kept, o)
		case !errors.Is(err, ErrOwnerLimit):
			t.Fatalf("note %d past the limit = %v, want ErrOwnerLimit", i, err)
		}
	}
	s.disk.mu.Lock()
	records := s.disk.records
	s.disk.mu.Unlock()
	if records != max {
		t.Fatalf("%d records counted, want %d", records, max)
	}
	if n := metaRecords(t, p); n != max {
		t.Fatalf("%d records on disk after the flood, want %d", n, max)
	}

	// A kept owner can raise its floor again and again; a new owner cannot add a log.
	ctx = testCtx(t)
	for i := range 10 {
		if err := Revoke(ctx, generate(t), p.Peer, revokeNote(t, p, kept[0], now.Add(time.Duration(i-5)*time.Second))); err != nil {
			t.Fatalf("note of a kept owner = %v", err)
		}
	}
	if n := metaRecords(t, p); n != max {
		t.Fatalf("%d records after repeated notes of one owner, want %d", n, max)
	}
	stranger := newOwner(t)
	l := stranger.log(t, "x")
	if _, err := Add(ctx, stranger.id, p.Peer, l, stranger.issue(t, p.Peer, Capability{})); !errors.Is(err, ErrOwnerLimit) {
		t.Fatalf("Add by a new owner = %v, want ErrOwnerLimit", err)
	}
	if used, ok := p.usage(t, stranger.id.PublicKey()); ok || used != 0 {
		t.Fatalf("the refused owner left %d bytes", used)
	}
	if n := metaRecords(t, p); n != max {
		t.Fatalf("%d records after a refused Add, want %d", n, max)
	}

	// A kept owner's Add and the limit both survive a restart.
	k := kept[1]
	kl := k.log(t, "y")
	if _, err := Add(ctx, k.id, p.Peer, kl, k.issue(t, p.Peer, Capability{Issued: now})); err != nil {
		t.Fatalf("Add by a kept owner = %v", err)
	}
	p.restart(t)
	if err := Revoke(ctx, generate(t), p.Peer, revokeNote(t, p, newOwner(t), now.Add(-time.Second))); !errors.Is(err, ErrOwnerLimit) {
		t.Fatalf("note of a new owner after a restart = %v, want ErrOwnerLimit", err)
	}
	if _, err := Status(ctx, k.id, p.Peer, kl.ID()); err != nil {
		t.Fatalf("Status of a kept owner = %v", err)
	}
}

// A peer that lists its owners keeps no owner limit, however low MaxOwners is.
func TestListedOwnersNoOwnerLimit(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	var owners []*ownerNode
	var keys []ed25519.PublicKey
	for range 3 {
		o := newOwner(t)
		owners = append(owners, o)
		keys = append(keys, o.id.PublicKey())
	}
	get := capture(t)
	p := startPin(t, Options{Owners: keys, MaxOwners: 1})
	if s := get(); s.disk.maxRecords != 0 {
		t.Fatalf("limit %d with Owners set, want none", s.disk.maxRecords)
	}
	for i, o := range owners {
		if _, err := Add(ctx, o.id, p.Peer, o.log(t, "x"), o.issue(t, p.Peer, Capability{})); err != nil {
			t.Fatalf("Add by listed owner %d = %v", i, err)
		}
	}
	if n := metaRecords(t, p); n != 3 {
		t.Fatalf("%d records, want 3", n)
	}
}

// Start-up reads the owner records a chunk at a time: the heap does not grow with their number.
func TestStartupMemoryFlat(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	alice := newOwner(t)
	l := alice.log(t, "a", "b")
	if _, err := Add(ctx, alice.id, p.Peer, l, alice.issue(t, p.Peer, Capability{})); err != nil {
		t.Fatal(err)
	}
	const records = 100_000
	var samples []uint64
	p.raw(t, func(db kolostore.Backend) {
		b := db.NewBatch()
		for i := range records {
			key := make([]byte, ed25519.PublicKeySize)
			binary.BigEndian.PutUint64(key, uint64(i)+1)
			b.Put(ownerKey(pMeta, key), encodeMeta(0, nil, 1))
		}
		if err := b.Commit(); err != nil {
			t.Fatal(err)
		}
		n := 0
		wrap = func(db kolostore.Backend) kolostore.Backend {
			return scanHook{db, func(k []byte) {
				if k[0] == pMeta {
					if n++; n%10_000 == 0 {
						runtime.GC()
						var m runtime.MemStats
						runtime.ReadMemStats(&m)
						samples = append(samples, m.HeapAlloc)
					}
				}
			}}
		}
	})
	wrap = nil
	if len(samples) < 10 {
		t.Fatalf("%d heap samples, want at least 10", len(samples))
	}
	lo, hi := slices.Min(samples), slices.Max(samples)
	if hi-lo > 4<<20 {
		t.Fatalf("heap grew from %d to %d bytes while start-up read %d records", lo, hi, records)
	}
	if st, err := Status(ctx, alice.id, p.Peer, l.ID()); err != nil || st.Entries != 2 {
		t.Fatalf("Status after the restart = %+v, %v", st, err)
	}
}

// scanHook calls seen with the key of every record a Scan reads.
type scanHook struct {
	kolostore.Backend
	seen func(key []byte)
}

func (h scanHook) Scan(start, end []byte, reverse bool, limit int, fn func(k, v []byte) bool) error {
	return h.Backend.Scan(start, end, reverse, limit, func(k, v []byte) bool {
		h.seen(k)
		return fn(k, v)
	})
}

// The default limit is DefaultMaxOwners and an owner's record is bounded by the capability's size.
func TestOwnerLimitDefault(t *testing.T) {
	checkGoroutines(t)
	get := capture(t)
	startPin(t, Options{})
	if s := get(); s.disk.maxRecords != DefaultMaxOwners {
		t.Fatalf("limit %d, want %d", s.disk.maxRecords, DefaultMaxOwners)
	}
	if got := ErrOwnerLimit.Error(); !strings.HasPrefix(got, "pin: ") {
		t.Fatal(got)
	}
	if codeOf(ErrOwnerLimit) != codeOwnerLimit || codeErrs[codeOwnerLimit] != ErrOwnerLimit {
		t.Fatal("ErrOwnerLimit has no answer code")
	}
}

// slog records kept for a test.
type recorder struct {
	min  slog.Level
	mu   sync.Mutex
	recs []slog.Record
}

func (r *recorder) Enabled(_ context.Context, l slog.Level) bool { return l >= r.min }
func (r *recorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	r.recs = append(r.recs, rec)
	r.mu.Unlock()
	return nil
}
func (r *recorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *recorder) WithGroup(string) slog.Handler      { return r }

func (r *recorder) warnings() (out []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rec := range r.recs {
		if rec.Level == slog.LevelWarn {
			out = append(out, rec.Message)
		}
	}
	return out
}

// Serve warns at start when it accepts every owner, and not when it has an owner list.
func TestOpenPeerWarns(t *testing.T) {
	checkGoroutines(t)
	var open recorder
	startPin(t, Options{Logger: slog.New(&open)})
	w := open.warnings()
	if len(w) != 1 || !strings.HasPrefix(w[0], "open peer: every owner key is accepted") {
		t.Fatalf("warnings of an open peer: %q", w)
	}
	var listed recorder
	startPin(t, Options{Logger: slog.New(&listed), Owners: []ed25519.PublicKey{newOwner(t).id.PublicKey()}})
	if w := listed.warnings(); len(w) != 0 {
		t.Fatalf("warnings of a peer with owners: %q", w)
	}
}

// slowScan is a backend whose Scan of a range inside block waits for release.
type slowScan struct {
	kolostore.Backend
	block   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (b *slowScan) Scan(start, end []byte, reverse bool, limit int, fn func(k, v []byte) bool) error {
	if b.block.Load() && len(start) > 0 && start[0] == pData {
		b.entered <- struct{}{}
		<-b.release
	}
	return b.Backend.Scan(start, end, reverse, limit, fn)
}

// An owner's long delete does not hold the disk lock: another owner's writes, a usage read, a quota change and a
// metadata write all finish while the scan of the delete is still running.
func TestLongDeleteDoesNotBlockOthers(t *testing.T) {
	db := &slowScan{Backend: kolostore.NewMemory(), entered: make(chan struct{}), release: make(chan struct{})}
	d := &disk{db: db, max: 1 << 30, markers: prometheus.NewCounter(prometheus.CounterOpts{Name: "m"})}
	defer d.db.Close()
	a, b := newOwner(t), newOwner(t)
	spA, err := newSpace(d, a.id.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	spB, err := newSpace(d, b.id.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := spA.Put([]byte("k1"), bytes.Repeat([]byte{1}, 100)); err != nil {
		t.Fatal(err)
	}
	db.block.Store(true)
	deleted := make(chan error, 1)
	go func() {
		batch := spA.NewBatch()
		batch.DeleteRange([]byte("k"), []byte("l"))
		deleted <- batch.Commit()
	}()
	<-db.entered // the delete is measuring its range, with d.mu not held

	others := make(chan error, 1)
	go func() {
		err := spB.Put([]byte("x"), []byte("y"))
		spB.setQuota(1000)
		spA.usage()
		if err == nil {
			err = d.putMeta(ownerKey(pMeta, b.id.PublicKey()), []byte{1, 2, 3})
		}
		others <- err
	}()
	select {
	case err := <-others:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("another owner's work waited for a long delete")
	}
	close(db.release)
	if err := <-deleted; err != nil {
		t.Fatal(err)
	}
	var stored uint64
	db.block.Store(false)
	if err := d.db.Scan(nil, nil, false, 0, func(k, v []byte) bool {
		if k[0] == pData || k[0] == pMeta {
			stored += uint64(len(k) + len(v))
		}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if usedA, _ := spA.usage(); usedA != 0 {
		t.Fatalf("owner A still counts %d bytes after its delete", usedA)
	}
	if d.used != stored {
		t.Fatalf("disk counts %d bytes, %d stored", d.used, stored)
	}
}

// flaky is a backend whose batches fail to commit now and then.
type flaky struct {
	kolostore.Backend
	n atomic.Int64
}

type flakyBatch struct {
	kolostore.Batch
	f *flaky
}

func (f *flaky) NewBatch() kolostore.Batch { return &flakyBatch{f.Backend.NewBatch(), f} }

func (b *flakyBatch) Commit() error {
	if b.f.n.Add(1)%4 == 0 {
		return errors.New("disk failed")
	}
	return b.Batch.Commit()
}

// Commits of many owners at once, some failing, keep the disk count equal to what is stored and under the limit.
func TestConcurrentCommitsKeepCounts(t *testing.T) {
	const max = 20_000
	d := &disk{db: &flaky{Backend: kolostore.NewMemory()}, max: max, markers: prometheus.NewCounter(prometheus.CounterOpts{Name: "m"})}
	defer d.db.Close()
	var wg sync.WaitGroup
	var over atomic.Bool
	var spaces []*space
	for range 8 {
		sp, err := newSpace(d, newOwner(t).id.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		spaces = append(spaces, sp)
		wg.Go(func() {
			for i := range 60 {
				k := []byte{byte(i % 20)}
				switch i % 3 {
				case 0, 1:
					_ = sp.Put(k, bytes.Repeat([]byte{byte(i)}, 30+i))
				default:
					_ = sp.Delete(k)
				}
				d.mu.Lock()
				if d.used > max {
					over.Store(true)
				}
				d.mu.Unlock()
			}
		})
	}
	wg.Wait()
	if over.Load() {
		t.Fatal("the disk count passed the limit")
	}
	var stored uint64
	if err := d.db.Scan([]byte{pData}, []byte{pData + 1}, false, 0, func(k, v []byte) bool {
		stored += uint64(len(k) + len(v))
		return true
	}); err != nil {
		t.Fatal(err)
	}
	var sum uint64
	for _, sp := range spaces {
		u, _ := sp.usage()
		sum += u
	}
	if d.used != stored || sum != stored {
		t.Fatalf("disk counts %d, owners %d, stored %d", d.used, sum, stored)
	}
}

// With AddTimeout, an Add that cannot finish in time is ErrBusy and the peer stays usable.
func TestAddTimeout(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	alice := newOwner(t)
	l := alice.log(t, "a", "b")
	p := startPin(t, Options{AddTimeout: time.Nanosecond})
	if _, err := Add(ctx, alice.id, p.Peer, l, alice.issue(t, p.Peer, Capability{})); !errors.Is(err, ErrBusy) {
		t.Fatalf("Add with a timeout already over = %v, want ErrBusy", err)
	}
	q := startPin(t, Options{AddTimeout: time.Minute})
	info, err := Add(ctx, alice.id, q.Peer, l, alice.issue(t, q.Peer, Capability{}))
	if err != nil || info.Entries != 2 {
		t.Fatalf("Add within the timeout = %+v, %v", info, err)
	}
	if _, err := Status(ctx, alice.id, p.Peer, kololog.LogID{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Status after the timeout = %v", err)
	}
}

// The peers' addresses are logged only at debug level; their keys are logged at info level.
func TestAddressesOnlyAtDebug(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	for _, c := range []struct {
		min  slog.Level
		addr bool
	}{{slog.LevelInfo, false}, {slog.LevelDebug, true}} {
		rec := &recorder{min: c.min}
		p := startPin(t, Options{Logger: slog.New(rec)})
		alice := newOwner(t)
		l := alice.log(t, "a")
		if _, err := Add(ctx, alice.id, p.Peer, l, alice.issue(t, p.Peer, Capability{})); err != nil {
			t.Fatal(err)
		}
		if _, err := Status(ctx, alice.id, p.Peer, l.ID()); err != nil {
			t.Fatal(err)
		}
		rec.mu.Lock()
		var pinned bool
		for _, r := range rec.recs {
			var addr, peer bool
			r.Attrs(func(a slog.Attr) bool {
				addr = addr || a.Key == "addr" && r.Message != "serving"
				peer = peer || a.Key == "peer"
				return true
			})
			if addr != (c.addr && peer) {
				t.Errorf("level %v: %q has an address: %v", c.min, r.Message, addr)
			}
			pinned = pinned || r.Message == "pinned" && peer
		}
		rec.mu.Unlock()
		if !pinned {
			t.Errorf("level %v: no pinned event with the peer key", c.min)
		}
	}
}
