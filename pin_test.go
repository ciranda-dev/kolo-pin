package pin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	kolokv "github.com/ciranda-dev/kolo-kv"
	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolosync "github.com/ciranda-dev/kolo-sync"
)

// Two owners pin through one pinning peer, go offline, and a third peer pulls both logs from it.
func TestTwoOwnersOnePinningPeer(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	alice, bob := newOwner(t), newOwner(t)
	al := alice.log(t, "a0", "a1", "a2")
	bl := bob.log(t, "b0", "b1")

	ac := alice.issue(t, p.Peer, Capability{})
	in, err := Add(ctx, alice.id, p.Peer, al, ac)
	if err != nil || in.Entries != 3 || in.Used == 0 {
		t.Fatalf("alice Add = %+v, %v", in, err)
	}
	if in, err = Add(ctx, bob.id, p.Peer, bl, bob.issue(t, p.Peer, Capability{Logs: []kololog.LogID{bl.ID()}})); err != nil || in.Entries != 2 {
		t.Fatalf("bob Add = %+v, %v", in, err)
	}
	if _, err := al.Append([]byte("a3")); err != nil {
		t.Fatal(err)
	}
	if in, err = Add(ctx, alice.id, p.Peer, al, ac); err != nil || in.Entries != 4 {
		t.Fatalf("alice refresh = %+v, %v", in, err)
	}
	aliceRecords, bobRecords := snapshot(t, al), snapshot(t, bl)
	_ = alice.st.Close()
	_ = bob.st.Close()

	for _, c := range []struct {
		owner   ed25519.PublicKey
		id      kololog.LogID
		records []string
	}{{alice.id.PublicKey(), al.ID(), aliceRecords}, {bob.id.PublicKey(), bl.ID(), bobRecords}} {
		rep, err := pullFrom(t, ctx, p.Peer, c.owner, c.id)
		if err != nil {
			t.Fatal(err)
		}
		if got := snapshot(t, rep); fmt.Sprint(got) != fmt.Sprint(c.records) {
			t.Fatalf("pulled records differ")
		}
		if _, err := rep.Get(0); !errors.Is(err, kololog.ErrKeyUnavailable) {
			t.Fatalf("Get on a copy from the pinning peer = %v, want ErrKeyUnavailable", err)
		}
	}
}

// A log with derived entry keys is pinned as ciphertext only, and a device with the secret reads the copy it pulls.
func TestDerivedKeysLogPinsCiphertextOnly(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	alice := newOwner(t)
	var secret kololog.EntrySecret
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	l, err := alice.st.Create(alice.id, kololog.WithDerivedKeys(&secret, 1))
	if err != nil {
		t.Fatal(err)
	}
	values := []string{"d0", "d1", "d2"}
	for _, v := range values {
		if _, err := l.Append([]byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	if in, err := Add(ctx, alice.id, p.Peer, l, alice.issue(t, p.Peer, Capability{})); err != nil || in.Entries != 3 {
		t.Fatalf("Add = %+v, %v", in, err)
	}
	rep, err := pullFrom(t, ctx, p.Peer, alice.id.PublicKey(), l.ID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rep.Get(0); !errors.Is(err, kololog.ErrKeyUnavailable) {
		t.Fatalf("Get on a copy from the pinning peer = %v, want ErrKeyUnavailable", err)
	}
	d, err := kololog.NewKeyDeriver(&secret, alice.id.PublicKey(), rep.Header())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	keys := make([]kololog.EntryKey, len(values))
	for i := range keys {
		if keys[i], err = d.Key(uint64(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := rep.AddKeys(0, keys); err != nil {
		t.Fatal(err)
	}
	for i, v := range values {
		if got, err := rep.Get(uint64(i)); err != nil || string(got) != v {
			t.Fatalf("entry %d = %q, %v; want %q", i, got, err, v)
		}
	}
	dump := p.dump(t)
	if bytes.Contains(dump, secret[:]) {
		t.Fatal("the pinning peer stores the entry secret")
	}
	for i, k := range keys {
		if bytes.Contains(dump, k) {
			t.Fatalf("the pinning peer stores the key of entry %d", i)
		}
		clear(k)
	}
}

// snapshot returns the encoded records of src.
func snapshot(t *testing.T, src kolosync.Source) []string {
	t.Helper()
	h, err := src.Head()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i := range h.Size {
		r, err := src.Record(i)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(r.Encode()))
	}
	return out
}

// A kolo-kv reader on another device fills from the pinning peer while the writer is offline, then gets the keys.
func TestKVReaderThroughPinningPeer(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	laptop := newOwner(t)
	l := laptop.log(t)
	db, err := kolokv.Open(l)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if err := db.Put(ctx, fmt.Appendf(nil, "k%d", i), fmt.Appendf(nil, "v%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Add(ctx, laptop.id, p.Peer, l, laptop.issue(t, p.Peer, Capability{})); err != nil {
		t.Fatal(err)
	}

	phone := kolostore.New(kolostore.NewMemory())
	defer phone.Close()
	dev := generate(t)
	conn, err := kolosecure.Dial(ctx, p.Addr, dev, p.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	header, err := kolosync.FetchHeader(ctx, conn, laptop.id.PublicKey(), l.ID())
	if err != nil {
		t.Fatal(err)
	}
	rep, err := phone.OpenReplica(laptop.id.PublicKey(), l.ID(), header)
	if err != nil {
		t.Fatal(err)
	}
	if err := kolosync.Pull(ctx, conn, rep); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if rep.Len() != l.Len() {
		t.Fatalf("phone has %d entries, want %d", rep.Len(), l.Len())
	}

	// The laptop comes back and gives only the keys.
	srv := kolosync.NewServer(func(peer, _ ed25519.PublicKey, _ kololog.LogID) kolosync.Access {
		if peer.Equal(dev.PublicKey()) {
			return kolosync.Keys
		}
		return kolosync.NoAccess
	})
	_ = srv.Offer(l)
	ln, err := kolosecure.Listen(ctx, "127.0.0.1:0", laptop.id, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	served := make(chan struct{})
	go func() {
		defer close(served)
		if c, err := ln.Accept(ctx); err == nil {
			_ = srv.Serve(ctx, c)
		}
	}()
	c2, err := kolosecure.Dial(ctx, ln.Addr().String(), dev, laptop.id.PublicKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := kolosync.Pull(ctx, c2, rep); err != nil {
		t.Fatal(err)
	}
	c2.Close()
	<-served
	reader, err := kolokv.OpenReader(rep)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if v, err := reader.Get([]byte("k3")); err != nil || string(v) != "v3" {
		t.Fatalf("Get(k3) = %q, %v", v, err)
	}
	_ = db.Close()
}

func TestStatusAndRemove(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	alice, mallory := newOwner(t), newOwner(t)
	l := alice.log(t, "x", "y")
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	if _, err := Add(ctx, alice.id, p.Peer, l, alice.issue(t, p.Peer, Capability{Quota: 1 << 20, Expires: exp})); err != nil {
		t.Fatal(err)
	}
	in, err := Status(ctx, alice.id, p.Peer, l.ID())
	if err != nil || in.Entries != 2 || in.Quota != 1<<20 || !in.Expires.Equal(exp) || in.Used == 0 {
		t.Fatalf("Status = %+v, %v", in, err)
	}
	if _, err := Status(ctx, mallory.id, p.Peer, l.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Status by another key = %v, want ErrNotFound", err)
	}
	if err := Remove(ctx, mallory.id, p.Peer, l.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Remove by another key = %v, want ErrNotFound", err)
	}
	_ = l.Close() // kolo-store refuses to delete a replica while its owner's log is open in the same process
	if err := Remove(ctx, alice.id, p.Peer, l.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := Status(ctx, alice.id, p.Peer, l.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Status after Remove = %v, want ErrNotFound", err)
	}
	if _, err := pullFrom(t, ctx, p.Peer, alice.id.PublicKey(), l.ID()); !errors.Is(err, kolosync.ErrNotFound) {
		t.Fatalf("pull after Remove = %v, want kolosync.ErrNotFound", err)
	}
}

func TestRefusedCapabilities(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	other := startPin(t, Options{})
	alice, bob := newOwner(t), newOwner(t)
	l := alice.log(t, "x")
	now := time.Now()
	forged := alice.issue(t, p.Peer, Capability{})
	forged[len(forged)-1] ^= 1
	var unrelated kololog.LogID
	unrelated[0] = 1
	for _, c := range []struct {
		name string
		cap  []byte
		want error
	}{
		{"other pinning peer", alice.issue(t, other.Peer, Capability{}), ErrUnauthorized},
		{"other owner", bob.issue(t, p.Peer, Capability{}), ErrUnauthorized},
		{"other log", alice.issue(t, p.Peer, Capability{Logs: []kololog.LogID{unrelated}}), ErrUnauthorized},
		{"bad signature", forged, ErrUnauthorized},
		{"truncated", alice.issue(t, p.Peer, Capability{})[:40], ErrUnauthorized},
		{"future", alice.issue(t, p.Peer, Capability{Issued: now.Add(time.Hour), Expires: now.Add(2 * time.Hour)}), ErrUnauthorized},
		{"expired", alice.issue(t, p.Peer, Capability{Issued: now.Add(-2 * time.Hour), Expires: now.Add(-time.Hour)}), ErrExpired},
	} {
		if _, err := Add(ctx, alice.id, p.Peer, l, c.cap); !errors.Is(err, c.want) {
			t.Errorf("%s: Add = %v, want %v", c.name, err, c.want)
		}
	}
	if _, err := pullFrom(t, ctx, p.Peer, alice.id.PublicKey(), l.ID()); !errors.Is(err, kolosync.ErrNotFound) {
		t.Fatalf("pull after refusals = %v, want kolosync.ErrNotFound", err)
	}
}

func TestOwnersAllowList(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	alice, bob := newOwner(t), newOwner(t)
	p := startPin(t, Options{Owners: []ed25519.PublicKey{alice.id.PublicKey()}})
	if _, err := Add(ctx, alice.id, p.Peer, alice.log(t, "a"), alice.issue(t, p.Peer, Capability{})); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, bob.id, p.Peer, bob.log(t, "b"), bob.issue(t, p.Peer, Capability{})); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Add by an owner not listed = %v, want ErrUnauthorized", err)
	}
}

// An old capability replayed after a newer one, or after a revoke note, is refused.
func TestReplayAndRevoke(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	alice := newOwner(t)
	l := alice.log(t, "x")
	now := time.Now()
	old := alice.issue(t, p.Peer, Capability{Issued: now.Add(-time.Minute), Expires: now.Add(time.Hour)})
	newer := alice.issue(t, p.Peer, Capability{Issued: now, Expires: now.Add(time.Hour), Quota: 1 << 20})
	if _, err := Add(ctx, alice.id, p.Peer, l, newer); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, alice.id, p.Peer, l, newer); err != nil {
		t.Fatalf("the same capability again = %v", err)
	}
	if _, err := Add(ctx, alice.id, p.Peer, l, old); !errors.Is(err, ErrRevoked) {
		t.Fatalf("replayed old capability = %v, want ErrRevoked", err)
	}
	sameSecond := alice.issue(t, p.Peer, Capability{Issued: now, Expires: now.Add(time.Hour), Quota: 2 << 20})
	if _, err := Add(ctx, alice.id, p.Peer, l, sameSecond); !errors.Is(err, ErrRevoked) {
		t.Fatalf("another capability with the same issue time = %v, want ErrRevoked", err)
	}

	_ = l.Close()
	note, err := IssueRevocation(alice.id, p.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := Revoke(ctx, generate(t), p.Peer, note); err != nil {
		t.Fatal(err)
	}
	if _, err := Status(ctx, alice.id, p.Peer, l.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Status after revoke = %v, want ErrNotFound", err)
	}
	l2, err := alice.st.Open(alice.id, l.ID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, alice.id, p.Peer, l2, newer); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked capability = %v, want ErrRevoked", err)
	}
	other, err := IssueRevocation(alice.id, generate(t).PublicKey(), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := Revoke(ctx, generate(t), p.Peer, other); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoke note for another peer = %v, want ErrUnauthorized", err)
	}
	fresh := alice.issue(t, p.Peer, Capability{Issued: now.Add(time.Second), Expires: now.Add(time.Hour)})
	if _, err := Add(ctx, alice.id, p.Peer, l2, fresh); err != nil {
		t.Fatalf("capability issued after the revoke note = %v", err)
	}
}

// The owner quota and the disk limit refuse writes with their own errors, which reach the client.
func TestQuotaAndDiskFull(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	big := string(make([]byte, 64<<10))
	t.Run("owner", func(t *testing.T) {
		p := startPin(t, Options{})
		alice := newOwner(t)
		l := alice.log(t, big)
		c := alice.issue(t, p.Peer, Capability{Quota: 100 << 10})
		if _, err := Add(ctx, alice.id, p.Peer, l, c); err != nil {
			t.Fatal(err)
		}
		if _, err := l.Append([]byte(big)); err != nil {
			t.Fatal(err)
		}
		_, err := Add(ctx, alice.id, p.Peer, l, c)
		if !errors.Is(err, ErrQuotaExceeded) || errors.Is(err, ErrDiskFull) {
			t.Fatalf("Add over the owner quota = %v, want ErrQuotaExceeded", err)
		}
		in, err := Status(ctx, alice.id, p.Peer, l.ID())
		if err != nil || in.Entries != 1 || in.Used > 100<<10 {
			t.Fatalf("Status after the refused write = %+v, %v; want the first entry kept", in, err)
		}
	})
	t.Run("disk", func(t *testing.T) {
		p := startPin(t, Options{MaxBytes: 100 << 10})
		alice := newOwner(t)
		l := alice.log(t, big)
		c := alice.issue(t, p.Peer, Capability{})
		if _, err := Add(ctx, alice.id, p.Peer, l, c); err != nil {
			t.Fatal(err)
		}
		if _, err := l.Append([]byte(big)); err != nil {
			t.Fatal(err)
		}
		_, err := Add(ctx, alice.id, p.Peer, l, c)
		if !errors.Is(err, ErrDiskFull) || errors.Is(err, ErrQuotaExceeded) {
			t.Fatalf("Add over the disk limit = %v, want ErrDiskFull", err)
		}
		bob := newOwner(t)
		if _, err := Add(ctx, bob.id, p.Peer, bob.log(t, big), bob.issue(t, p.Peer, Capability{})); !errors.Is(err, ErrDiskFull) {
			t.Fatalf("another owner on a full disk = %v, want ErrDiskFull", err)
		}
		if in, err := Status(ctx, alice.id, p.Peer, l.ID()); err != nil || in.Entries != 1 {
			t.Fatalf("Status after the refused write = %+v, %v; want the first entry kept", in, err)
		}
	})
}

// A delete marker from the owner drops the ciphertext on the pinning peer at the next Add.
func TestDeleteMarkerDropsCiphertext(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	dir := privateDir(t)
	p := startPin(t, Options{Dir: dir})
	alice := newOwner(t)
	l := alice.log(t, "keep", "secret to delete", "keep too")
	c := alice.issue(t, p.Peer, Capability{})
	if _, err := Add(ctx, alice.id, p.Peer, l, c); err != nil {
		t.Fatal(err)
	}
	e, err := l.Entry(1)
	if err != nil {
		t.Fatal(err)
	}
	ct := e.Ciphertext
	if !dumpContains(t, p, ct) {
		t.Fatal("ciphertext not found before the delete")
	}
	before, _ := Status(ctx, alice.id, p.Peer, l.ID())
	p.restart(t)
	if err := l.Delete(1); err != nil {
		t.Fatal(err)
	}
	after, err := Add(ctx, alice.id, p.Peer, l, c)
	if err != nil {
		t.Fatal(err)
	}
	if after.Used >= before.Used {
		t.Fatalf("used %d bytes after the delete, %d before", after.Used, before.Used)
	}
	rep, err := pullFrom(t, ctx, p.Peer, alice.id.PublicKey(), l.ID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rep.Get(1); !errors.Is(err, kololog.ErrDeleted) {
		t.Fatalf("Get of the deleted entry from the pinning peer's copy = %v, want ErrDeleted", err)
	}
	if dumpContains(t, p, ct) {
		t.Fatal("the pinning peer still stores the deleted ciphertext")
	}
}

// Logs are dropped once the capability expires, and the state survives a restart.
func TestExpiryDropsLogs(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	var later atomic.Int64
	clock = func() time.Time { return time.Now().Add(time.Duration(later.Load())) }
	t.Cleanup(func() { clock = time.Now })
	p := startPin(t, Options{})
	alice := newOwner(t)
	l := alice.log(t, "x")
	if _, err := Add(ctx, alice.id, p.Peer, l, alice.issue(t, p.Peer, Capability{})); err != nil {
		t.Fatal(err)
	}
	p.restart(t)
	if in, err := Status(ctx, alice.id, p.Peer, l.ID()); err != nil || in.Entries != 1 {
		t.Fatalf("Status after restart = %+v, %v", in, err)
	}
	_ = l.Close()
	later.Store(int64(2 * time.Hour))
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := pullFrom(t, ctx, p.Peer, alice.id.PublicKey(), l.ID())
		if errors.Is(err, kolosync.ErrNotFound) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("log still served after expiry: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if used, _ := p.usage(t, alice.id.PublicKey()); used != 0 {
		t.Fatalf("%d bytes left after expiry", used)
	}
}

// A capability for fewer logs replaces the old one and drops the logs it no longer covers.
func TestNarrowerCapabilityDropsLogs(t *testing.T) {
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
	}
	_ = l2.Close()
	if _, err := Add(ctx, alice.id, p.Peer, l1, alice.issue(t, p.Peer, Capability{Issued: now, Logs: []kololog.LogID{l1.ID()}})); err != nil {
		t.Fatal(err)
	}
	if _, err := Status(ctx, alice.id, p.Peer, l2.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Status of the uncovered log = %v, want ErrNotFound", err)
	}
}

func TestIdentityPersists(t *testing.T) {
	dir := privateDir(t)
	a, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadIdentity(dir)
	if err != nil || !a.PublicKey().Equal(b.PublicKey()) {
		t.Fatalf("second LoadIdentity = %v, %v; want the same key", b, err)
	}
	if fmt.Sprint(a) == fmt.Sprintf("%x", a.PublicKey()) {
		t.Fatal("identity printed as raw key bytes")
	}
}

func TestServeArguments(t *testing.T) {
	if err := Serve(testCtx(t), nil, Options{Dir: t.TempDir()}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Serve(nil) = %v", err)
	}
	if _, err := Add(testCtx(t), nil, Peer{}, nil, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Add with no arguments = %v", err)
	}
	if err := Remove(testCtx(t), generate(t), Peer{ID: make([]byte, 3)}, kololog.LogID{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Remove with a short key = %v", err)
	}
	if err := Remove(testCtx(t), generate(t), Peer{ID: generate(t).PublicKey(), Addr: "[::1]:7450"}, kololog.LogID{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Remove to an IPv6 address = %v, want ErrInvalidArgument", err)
	}
}

func TestAddRefusesNonOwner(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	alice, mallory := newOwner(t), newOwner(t)
	l := alice.log(t, "a0", "a1")
	capb := alice.issue(t, p.Peer, Capability{})
	if _, err := Add(ctx, mallory.id, p.Peer, l, capb); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Add by a key that is not the owner = %v, want ErrUnauthorized", err)
	}
	if _, err := Status(ctx, alice.id, p.Peer, l.ID()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Status after the refused add = %v, want ErrNotFound", err)
	}
	if used, _ := p.usage(t, alice.id.PublicKey()); used != 0 {
		t.Fatalf("%d bytes stored for a refused add", used)
	}
	if in, err := Add(ctx, alice.id, p.Peer, l, capb); err != nil || in.Entries != 2 {
		t.Fatalf("Add by the owner = %+v, %v", in, err)
	}
}

func TestAddNonOwnerLearnsNothingOfCapabilityState(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	alice, mallory := newOwner(t), newOwner(t)
	l := alice.log(t, "x")
	now := time.Now()
	expired := alice.issue(t, p.Peer, Capability{Issued: now.Add(-2 * time.Hour), Expires: now.Add(-time.Hour)})
	old := alice.issue(t, p.Peer, Capability{Issued: now.Add(-time.Minute)})
	newer := alice.issue(t, p.Peer, Capability{Issued: now})
	if _, err := Add(ctx, alice.id, p.Peer, l, newer); err != nil {
		t.Fatal(err)
	}
	note, err := IssueRevocation(alice.id, p.ID, now.Add(-30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := Revoke(ctx, alice.id, p.Peer, note); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name  string
		capb  []byte
		owner error
	}{
		{"expired", expired, ErrExpired},
		{"revoked", old, ErrRevoked},
	} {
		if _, err := Add(ctx, mallory.id, p.Peer, l, c.capb); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("%s: Add by a key that is not the owner = %v, want ErrUnauthorized", c.name, err)
		}
		if _, err := Add(ctx, alice.id, p.Peer, l, c.capb); !errors.Is(err, c.owner) {
			t.Fatalf("%s: Add by the owner = %v, want %v", c.name, err, c.owner)
		}
	}
}

func TestAddReplayFromThirdKeyRefused(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	alice, mallory := newOwner(t), newOwner(t)
	l := alice.log(t, "x")
	capb := alice.issue(t, p.Peer, Capability{})
	if err := addOffering(t, ctx, p.Peer, alice, l, capb, kolosync.Ciphertext); err != nil {
		t.Fatalf("Add by the owner = %v", err)
	}
	if err := addOffering(t, ctx, p.Peer, mallory, l, capb, kolosync.Ciphertext); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("replay of the same request from another key = %v, want ErrUnauthorized", err)
	}
}
