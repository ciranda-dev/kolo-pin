package pin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolosync "github.com/ciranda-dev/kolo-sync"
)

func TestMain(m *testing.M) {
	dialTimeout = time.Second
	sweepEvery = 20 * time.Millisecond
	os.Exit(m.Run())
}

// checkGoroutines fails the test if goroutines started after it are still running after the cleanups.
func checkGoroutines(t *testing.T) {
	t.Helper()
	before := goroutines()
	t.Cleanup(func() {
		deadline := time.Now().Add(5 * time.Second)
		for {
			var leaked []string
			for id, stack := range goroutines() {
				if _, ok := before[id]; !ok {
					leaked = append(leaked, stack)
				}
			}
			if len(leaked) == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Errorf("%d goroutines leaked:\n%s", len(leaked), strings.Join(leaked, "\n\n"))
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

func goroutines() map[string]string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	out := make(map[string]string)
	for _, stack := range strings.Split(string(buf), "\n\n") {
		if id, _, ok := strings.Cut(strings.TrimPrefix(stack, "goroutine "), " "); ok {
			out[id] = stack
		}
	}
	return out
}

func testCtx(t testing.TB) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func generate(t testing.TB) *koloid.Identity {
	t.Helper()
	id, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// pinPeer is a pinning peer served on loopback from a temp directory.
type pinPeer struct {
	Peer
	dir    string
	opts   Options
	cancel context.CancelFunc
	done   chan error
	ln     *kolosecure.Listener
}

func startPin(t testing.TB, opts Options) *pinPeer {
	t.Helper()
	if opts.Dir == "" {
		opts.Dir = privateDir(t)
	}
	p := &pinPeer{opts: opts, dir: opts.Dir}
	p.start(t)
	t.Cleanup(func() { p.stop(t) })
	return p
}

func (p *pinPeer) start(t testing.TB) {
	t.Helper()
	opts := p.opts
	id, err := LoadIdentity(opts.Dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := kolosecure.Listen(ctx, "127.0.0.1:0", id, nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	p.Peer = Peer{ID: id.PublicKey(), Addr: ln.Addr().String()}
	p.cancel, p.done, p.ln = cancel, make(chan error, 1), ln
	go func() { p.done <- Serve(ctx, ln, opts) }()
	// Serve has loaded its store and registered its metrics once it answers.
	rctx, rcancel := context.WithTimeout(ctx, 20*time.Second)
	defer rcancel()
	if _, err := Status(rctx, generate(t), p.Peer, kololog.LogID{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pinning peer not answering: %v", err)
	}
}

func (p *pinPeer) restart(t testing.TB) {
	t.Helper()
	p.stop(t)
	p.start(t)
}

// raw stops the peer, calls fn on its whole backend, and starts it again.
func (p *pinPeer) raw(t testing.TB, fn func(kolostore.Backend)) {
	t.Helper()
	p.stop(t)
	db, err := kolostore.OpenPebble(filepath.Join(p.dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	fn(db)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	p.start(t)
}

// dump returns every key and value the peer stores, concatenated.
func (p *pinPeer) dump(t testing.TB) []byte {
	t.Helper()
	var out []byte
	p.raw(t, func(db kolostore.Backend) {
		if err := db.Scan(nil, nil, false, 0, func(k, v []byte) bool {
			out = append(append(out, k...), v...)
			return true
		}); err != nil {
			t.Fatal(err)
		}
	})
	return out
}

func dumpContains(t testing.TB, p *pinPeer, b []byte) bool {
	t.Helper()
	return bytes.Contains(p.dump(t), b)
}

// usage returns the stored byte count of owner and whether it exists.
func (p *pinPeer) usage(t testing.TB, owner ed25519.PublicKey) (uint64, bool) {
	t.Helper()
	var n uint64
	var ok bool
	p.raw(t, func(db kolostore.Backend) {
		v, err := db.Get(ownerKey(pUsage, owner))
		if err == nil {
			n, _ = binary.Uvarint(v)
			ok = true
		}
	})
	return n, ok
}

// stop ends Serve and closes the listener; a second call does nothing.
func (p *pinPeer) stop(t testing.TB) {
	t.Helper()
	if p.cancel == nil {
		return
	}
	p.cancel()
	p.cancel = nil
	select {
	case err := <-p.done:
		if err != nil && err != context.Canceled {
			t.Errorf("Serve: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Error("Serve did not return")
	}
	_ = p.ln.Close()
}

func newOwner(t testing.TB) *ownerNode {
	t.Helper()
	o := &ownerNode{id: generate(t), st: kolostore.New(kolostore.NewMemory())}
	t.Cleanup(func() { _ = o.st.Close() })
	return o
}

// ownerNode is a peer that writes logs in an in-memory store.
type ownerNode struct {
	id *koloid.Identity
	st *kolostore.Store
}

func (o *ownerNode) log(t testing.TB, values ...string) *kolostore.Log {
	t.Helper()
	l, err := o.st.Create(o.id)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range values {
		if _, err := l.Append([]byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	return l
}

func (o *ownerNode) issue(t testing.TB, peer Peer, c Capability) []byte {
	t.Helper()
	c.Peer = peer.ID
	if c.Expires.IsZero() {
		c.Expires = time.Now().Add(time.Hour)
	}
	b, err := Issue(o.id, c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// pullFrom pulls the log logID of owner from the pinning peer into a new in-memory replica, as a second device.
func pullFrom(t testing.TB, ctx context.Context, p Peer, owner ed25519.PublicKey, logID kololog.LogID) (*kolostore.Replica, error) {
	t.Helper()
	dev := generate(t)
	conn, err := kolosecure.Dial(ctx, p.Addr, dev, p.ID, nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	st := kolostore.New(kolostore.NewMemory())
	t.Cleanup(func() { _ = st.Close() })
	header, err := kolosync.FetchHeader(ctx, conn, owner, logID)
	if err != nil {
		return nil, err
	}
	rep, err := st.OpenReplica(owner, logID, header)
	if err != nil {
		return nil, err
	}
	return rep, kolosync.Pull(ctx, conn, rep)
}

func mustEqualEntries(t testing.TB, want kolosync.Source, got *kolostore.Replica, n uint64) {
	t.Helper()
	if got.Len() != n {
		t.Fatalf("replica has %d entries, want %d", got.Len(), n)
	}
	for i := range n {
		a, err1 := want.Record(i)
		b, err2 := got.Record(i)
		if err1 != nil || err2 != nil || string(a.Encode()) != string(b.Encode()) {
			t.Fatalf("record %d differs: %v %v", i, err1, err2)
		}
	}
}

// privateDir returns a new directory for a pinning peer's data, which must not be open to others.
func privateDir(t testing.TB) string {
	return filepath.Join(t.TempDir(), "pin")
}

func timeIn(seconds int) time.Time {
	return time.Now().Add(time.Duration(seconds) * time.Second)
}

// eventually waits for f to be true.
func eventually(t testing.TB, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// tick returns once the clock that stamps the last use of a log has moved on.
func tick() {
	for t := time.Now().UnixNano(); time.Now().UnixNano() == t; {
	}
}
