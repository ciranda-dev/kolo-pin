package pin

import (
	"errors"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolosync "github.com/ciranda-dev/kolo-sync"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// dataBytes returns how many bytes the store holds under the owner's data prefix.
func dataBytes(t *testing.T, p *pinPeer, owner []byte) int {
	t.Helper()
	n := 0
	p.raw(t, func(db kolostore.Backend) {
		pre := ownerKey(pData, owner)
		if err := db.Scan(pre, prefixEnd(pre), false, 0, func(k, v []byte) bool { n += len(k) + len(v); return true }); err != nil {
			t.Fatal(err)
		}
	})
	return n
}

// A crash between storing a narrower capability and deleting the logs it no longer covers, or after a capability
// was cleared but a delete failed, leaves logs on disk; the next start deletes them.
func TestLoadDropsUncoveredLogs(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	alice := newOwner(t)
	l1, l2 := alice.log(t, "one"), alice.log(t, "two")
	now := time.Now()
	all := alice.issue(t, p.Peer, Capability{Issued: now.Add(-time.Minute)})
	for _, l := range []*kolostore.Log{l1, l2} {
		if _, err := Add(ctx, alice.id, p.Peer, l, all); err != nil {
			t.Fatal(err)
		}
		_ = l.Close()
	}
	key := alice.id.PublicKey()
	narrow := alice.issue(t, p.Peer, Capability{Issued: now, Logs: []kololog.LogID{l1.ID()}})
	before := dataBytes(t, p, key)
	p.raw(t, func(db kolostore.Backend) {
		if err := db.Put(ownerKey(pMeta, key), encodeMeta(now.Unix(), narrow, 0)); err != nil {
			t.Fatal(err)
		}
	})
	if _, err := Status(ctx, alice.id, p.Peer, l2.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Status of the uncovered log after the restart = %v, want ErrNotFound", err)
	}
	if _, err := pullFrom(t, ctx, p.Peer, key, l2.ID()); !errors.Is(err, kolosync.ErrNotFound) {
		t.Fatalf("pull of the uncovered log = %v, want kolosync.ErrNotFound", err)
	}
	if in, err := Status(ctx, alice.id, p.Peer, l1.ID()); err != nil || in.Entries != 1 {
		t.Fatalf("Status of the covered log = %+v, %v", in, err)
	}
	if after := dataBytes(t, p, key); after >= before {
		t.Fatalf("%d data bytes after the restart, %d before", after, before)
	}

	p.raw(t, func(db kolostore.Backend) {
		if err := db.Put(ownerKey(pMeta, key), encodeMeta(now.Unix(), nil, 0)); err != nil {
			t.Fatal(err)
		}
	})
	if n := dataBytes(t, p, key); n != 0 {
		t.Fatalf("%d data bytes left for an owner without a capability", n)
	}
}

// blocking serves a log but holds the first Entry read until release is closed.
type blocking struct {
	kolosync.Source
	once             sync.Once
	reached, release chan struct{}
}

func (s *blocking) Entry(i uint64) (kololog.Entry, error) {
	s.once.Do(func() {
		close(s.reached)
		<-s.release
	})
	return s.Source.Entry(i)
}

func dialRaw(t *testing.T, p *pinPeer) *kolosecure.Conn {
	t.Helper()
	conn, err := kolosecure.Dial(testCtx(t), p.Addr, generate(t), p.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// badProof serves a log with a corrupted consistency proof.
type badProof struct{ kolosync.Source }

func (s badProof) ConsistencyProof(a, b uint64) (kololog.ConsistencyProof, error) {
	p, err := s.Source.ConsistencyProof(a, b)
	if len(p.Path) > 0 {
		p.Path[0][0] ^= 1
	}
	return p, err
}

func TestMetricsExact(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	reg := prometheus.NewRegistry()
	p := startPin(t, Options{Metrics: reg})
	hs := httptest.NewServer(promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	defer hs.Close()
	alice := newOwner(t)
	l := alice.log(t, "a", "bb", "ccc")
	c := alice.issue(t, p.Peer, Capability{})
	src := &blocking{Source: l, reached: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() { _, err := Add(ctx, alice.id, p.Peer, src, c); done <- err }()
	<-src.reached
	during, _ := scrape(t, hs.URL)
	if value(t, during, "kolo_pin_active_pulls") != 1 || value(t, during, "kolo_pin_active_sync_streams") != 1 {
		t.Fatalf("during a pull: active_pulls %v, active_sync_streams %v; want 1 and 1",
			value(t, during, "kolo_pin_active_pulls"), value(t, during, "kolo_pin_active_sync_streams"))
	}
	close(src.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var want float64
	for i := range l.Len() {
		r, err := l.Record(i)
		if err != nil {
			t.Fatal(err)
		}
		want += float64(r.Size) + float64(len(r.Encode()))
	}
	after, _ := scrape(t, hs.URL)
	if got := value(t, after, "kolo_pin_bytes_received_total"); got != want {
		t.Fatalf("bytes_received_total %v, want %v (ciphertexts and records)", got, want)
	}
	if value(t, after, "kolo_pin_active_pulls") != 0 {
		t.Fatal("active_pulls not back to 0")
	}

	for range 3 {
		if _, err := l.Append([]byte("more")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Add(ctx, alice.id, p.Peer, badProof{l}, c); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Add with a bad proof = %v, want ErrInvalid", err)
	}
	conn := dialRaw(t, p)
	if err := rawCall(t, conn, []byte{0xff}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("garbage request = %v", err)
	}
	conn.Close()
	now, _ := scrape(t, hs.URL)
	for reason, d := range map[string]float64{"bad_proof": 1, "bad_signature": 0, "other": 1} {
		if got := value(t, now, "kolo_pin_refused_total", "reason", reason) - value(t, after, "kolo_pin_refused_total", "reason", reason); got != d {
			t.Errorf("refused %s grew by %v, want %v", reason, got, d)
		}
	}

	// The entry counts are saved at a clean stop, so the gauge is right before any log is opened again.
	if _, err := Add(ctx, alice.id, p.Peer, l, c); err != nil {
		t.Fatal(err)
	}
	p.restart(t)
	restarted, _ := scrape(t, hs.URL)
	if got := value(t, restarted, "kolo_pin_entries"); got != 6 {
		t.Fatalf("entries after a restart %v, want 6", got)
	}
}

func TestReasonMapping(t *testing.T) {
	for err, want := range map[error]string{
		errReplayed: "replayed_token", errRevokedNote: "revoked", ErrRevoked: "revoked", ErrExpired: "expired_token",
		fmt.Errorf("%w: %w", ErrUnauthorized, errBadSignature): "bad_signature", ErrUnauthorized: "bad_token",
		ErrQuotaExceeded: "quota_exceeded", ErrDiskFull: "disk_full", ErrTooLarge: "oversized_entry",
		fmt.Errorf("%w: %w", ErrInvalid, kololog.ErrBadProof): "bad_proof", fmt.Errorf("%w: %w", ErrInvalid, kololog.ErrDiverged): "bad_proof",
		fmt.Errorf("%w: %w", ErrInvalid, kololog.ErrBadEntry): "bad_signature", ErrBusy: "other", ErrNotFound: "other", ErrProtocol: "other",
	} {
		if got := reason(err); got != want {
			t.Errorf("reason(%v) = %s, want %s", err, got, want)
		}
	}
}

// Past MaxOpenBytes, the least recently used replica is closed, not the most recent one.
func TestOpenReplicasLRU(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	get := capture(t)
	p := startPin(t, Options{MaxOpenBytes: 2 * openCost(1)})
	alice := newOwner(t)
	c := alice.issue(t, p.Peer, Capability{})
	var logs []*kolostore.Log
	for i := range 3 {
		l := alice.log(t, fmt.Sprint("log ", i))
		if _, err := Add(ctx, alice.id, p.Peer, l, c); err != nil {
			t.Fatal(err)
		}
		logs = append(logs, l)
		tick()
	}
	s := get()
	o := s.lookup(alice.id.PublicKey())
	open := func(i int) bool {
		o.mu.Lock()
		h := o.logs[logs[i].ID()]
		o.mu.Unlock()
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.rep != nil
	}
	if open(0) || !open(1) || !open(2) {
		t.Fatalf("open replicas after three Adds: %v %v %v; want 1 and 2", open(0), open(1), open(2))
	}
	// Use 1, then read 0: 2 is now the least recently used.
	for _, i := range []int{1, 0} {
		if _, err := pullFrom(t, ctx, p.Peer, alice.id.PublicKey(), logs[i].ID()); err != nil {
			t.Fatal(err)
		}
		tick()
	}
	if !open(0) || !open(1) || open(2) {
		t.Fatalf("open replicas: %v %v %v; want the two most recently used, 0 and 1", open(0), open(1), open(2))
	}
}
