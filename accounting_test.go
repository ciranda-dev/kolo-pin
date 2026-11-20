package pin

import (
	"crypto/ed25519"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolosync "github.com/ciranda-dev/kolo-sync"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// recount adds up the stored data and capability state, the bytes MaxBytes counts.
func recount(t *testing.T, p *pinPeer) float64 {
	t.Helper()
	var n int
	p.raw(t, func(db kolostore.Backend) {
		for _, pre := range []byte{pData, pMeta} {
			if err := db.Scan([]byte{pre}, []byte{pre + 1}, false, 0, func(k, v []byte) bool { n += len(k) + len(v); return true }); err != nil {
				t.Fatal(err)
			}
		}
	})
	return float64(n)
}

func entriesKeyStored(t *testing.T, p *pinPeer, owner []byte, id kololog.LogID) bool {
	t.Helper()
	found := false
	p.raw(t, func(db kolostore.Backend) {
		_, err := db.Get(entriesKey(owner, id))
		found = err == nil
	})
	return found
}

// kolo_pin_bytes_used equals a recount of the store while running, after a clean restart and after a crash leftover.
func TestBytesUsedMatchesRecount(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	reg := prometheus.NewRegistry()
	p := startPin(t, Options{Metrics: reg})
	hs := httptest.NewServer(promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	defer hs.Close()
	used := func() float64 {
		fams, _ := scrape(t, hs.URL)
		return value(t, fams, "kolo_pin_bytes_used")
	}
	alice, bob := newOwner(t), newOwner(t)
	al := alice.log(t, "a", "b", "c")
	ac := alice.issue(t, p.Peer, Capability{})
	for _, l := range []*kolostore.Log{al, alice.log(t, "d")} {
		if _, err := Add(ctx, alice.id, p.Peer, l, ac); err != nil {
			t.Fatal(err)
		}
	}
	bl := bob.log(t, "e")
	if _, err := Add(ctx, bob.id, p.Peer, bl, bob.issue(t, p.Peer, Capability{})); err != nil {
		t.Fatal(err)
	}
	if err := al.Delete(1); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, alice.id, p.Peer, al, ac); err != nil {
		t.Fatal(err)
	}
	if err := al.Delete(0, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, alice.id, p.Peer, al, ac); err != nil {
		t.Fatal(err)
	}
	_ = bl.Close()
	if err := Remove(ctx, bob.id, p.Peer, bl.ID()); err != nil {
		t.Fatal(err)
	}
	running := used()
	if r := recount(t, p); running != r {
		t.Fatalf("bytes_used %v while running, recount %v", running, r)
	}
	if after := used(); after != running {
		t.Fatalf("bytes_used %v after a clean restart, %v before", after, running)
	}
	// A crash between a replica delete and its entry count delete leaves the count behind.
	p.raw(t, func(db kolostore.Backend) {
		if err := db.Put(entriesKey(bob.id.PublicKey(), bl.ID()), []byte{7}); err != nil {
			t.Fatal(err)
		}
	})
	if u, r := used(), recount(t, p); u != r || u != running {
		t.Fatalf("bytes_used %v after the leftover, recount %v, before %v", u, r, running)
	}
	if entriesKeyStored(t, p, bob.id.PublicKey(), bl.ID()) {
		t.Fatal("the leftover entry count of a dropped log was kept")
	}
}

// An owner taken off the Owners list loses its capability and logs at the next start; its revoke notes still count.
func TestOwnerRemovedFromAllowlist(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	alice, bob := newOwner(t), newOwner(t)
	p := startPin(t, Options{Owners: []ed25519.PublicKey{alice.id.PublicKey(), bob.id.PublicKey()}})
	now := time.Now()
	al, bl := alice.log(t, "a"), bob.log(t, "b")
	ac := alice.issue(t, p.Peer, Capability{Issued: now.Add(-time.Minute)})
	if _, err := Add(ctx, alice.id, p.Peer, al, ac); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, bob.id, p.Peer, bl, bob.issue(t, p.Peer, Capability{})); err != nil {
		t.Fatal(err)
	}
	_ = al.Close()
	p.opts.Owners = []ed25519.PublicKey{bob.id.PublicKey()}
	p.restart(t)
	if _, err := pullFrom(t, ctx, p.Peer, alice.id.PublicKey(), al.ID()); !errors.Is(err, kolosync.ErrNotFound) {
		t.Fatalf("pull of a removed owner's log = %v, want kolosync.ErrNotFound", err)
	}
	if n := dataBytes(t, p, alice.id.PublicKey()); n != 0 {
		t.Fatalf("%d data bytes left for the removed owner", n)
	}
	if _, err := Status(ctx, bob.id, p.Peer, bl.ID()); err != nil {
		t.Fatalf("Status of a listed owner = %v", err)
	}
	note, err := IssueRevocation(alice.id, p.ID, now.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := Revoke(ctx, generate(t), p.Peer, note); err != nil {
		t.Fatalf("revoke note of a removed owner = %v", err)
	}
	stranger := newOwner(t)
	other, _ := IssueRevocation(stranger.id, p.ID, now)
	if err := Revoke(ctx, generate(t), p.Peer, other); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoke note of an owner never seen = %v, want ErrUnauthorized", err)
	}
	p.opts.Owners = nil
	p.restart(t)
	l2, err := alice.st.Open(alice.id, al.ID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, alice.id, p.Peer, l2, ac); !errors.Is(err, ErrRevoked) {
		t.Fatalf("Add with the revoked token once listed again = %v, want ErrRevoked", err)
	}
}

// Owners whose logs the start-up cleanup deletes are not kept in memory, and their entry counts go too.
func TestLoadForgetsEmptyOwners(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	alice := newOwner(t)
	l := alice.log(t, "a")
	if _, err := Add(ctx, alice.id, p.Peer, l, alice.issue(t, p.Peer, Capability{Issued: time.Now().Add(-time.Minute)})); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	p.stop(t) // a clean stop saves the entry count
	get := capture(t)
	p.raw(t, func(db kolostore.Backend) {
		if err := db.Put(ownerKey(pMeta, alice.id.PublicKey()), encodeMeta(time.Now().Unix(), nil, 0)); err != nil {
			t.Fatal(err)
		}
	})
	s := get()
	s.mu.Lock()
	n := len(s.owners)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d owners in memory after the cleanup", n)
	}
	if entriesKeyStored(t, p, alice.id.PublicKey(), l.ID()) {
		t.Fatal("the entry count of a deleted log was kept")
	}
}

// A corrupt entry count key stops Serve with ErrCorrupt instead of a panic.
func TestCorruptEntriesKey(t *testing.T) {
	checkGoroutines(t)
	p := startPin(t, Options{})
	p.stop(t)
	db, err := kolostore.OpenPebble(filepath.Join(p.dir, "store"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Put([]byte{pEntries, 1, 2, 3}, []byte{1}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	id, err := LoadIdentity(p.dir)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := kolosecure.Listen(testCtx(t), "127.0.0.1:0", id, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := Serve(testCtx(t), ln, Options{Dir: p.dir}); !errors.Is(err, kolostore.ErrCorrupt) {
		t.Fatalf("Serve on a corrupt entry count key = %v, want ErrCorrupt", err)
	}
}
