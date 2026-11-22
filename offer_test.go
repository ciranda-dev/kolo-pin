package pin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolosync "github.com/ciranda-dev/kolo-sync"
)

// follow starts a Follower with an empty replica of l and connects it to the pinning peer, with no header fetch first.
func follow(t *testing.T, ctx context.Context, p Peer, owner *ownerNode, l *kolostore.Log) *kolosync.Follower {
	t.Helper()
	st := kolostore.New(kolostore.NewMemory())
	t.Cleanup(func() { _ = st.Close() })
	rep, err := st.OpenReplica(owner.id.PublicKey(), l.ID(), l.Header().Encode())
	if err != nil {
		t.Fatal(err)
	}
	f, err := kolosync.NewFollower(&kolosync.FollowOptions{Ciphertext: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Add(rep); err != nil {
		t.Fatal(err)
	}
	conn, err := kolosecure.Dial(ctx, p.Addr, generate(t), p.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	fctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { _ = f.Follow(fctx, conn); close(done) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = f.Close()
		_ = conn.Close()
	})
	eventually(t, "the follower to pull the log", func() bool {
		s, err := f.Status(owner.id.PublicKey(), l.ID())
		return err == nil && s.Len == l.Len()
	})
	return f
}

// A Follower that names a hosted log in its first watch gets it, with no request for the log before.
func TestFollowerPullsLogOfferedByAdd(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	alice := newOwner(t)
	l := alice.log(t, "a0", "a1", "a2")
	if _, err := Add(ctx, alice.id, p.Peer, l, alice.issue(t, p.Peer, Capability{})); err != nil {
		t.Fatal(err)
	}
	follow(t, ctx, p.Peer, alice, l)
}

// The same after a restart, when the pinning peer loads the log from its store.
func TestFollowerPullsLogOfferedAtStart(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	alice := newOwner(t)
	l := alice.log(t, "a0", "a1", "a2")
	if _, err := Add(ctx, alice.id, p.Peer, l, alice.issue(t, p.Peer, Capability{})); err != nil {
		t.Fatal(err)
	}
	p.restart(t)
	follow(t, ctx, p.Peer, alice, l)
}

// A log the pinning peer removed is no longer offered: a Follower does not get it.
func TestFollowerDoesNotGetRemovedLog(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	alice := newOwner(t)
	l := alice.log(t, "a0")
	if _, err := Add(ctx, alice.id, p.Peer, l, alice.issue(t, p.Peer, Capability{})); err != nil {
		t.Fatal(err)
	}
	_ = l.Close() // kolo-store refuses to delete a replica while its owner's log is open in the same process
	if err := Remove(ctx, alice.id, p.Peer, l.ID()); err != nil {
		t.Fatal(err)
	}
	conn, err := kolosecure.Dial(ctx, p.Addr, generate(t), p.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := kolosync.FetchHeader(ctx, conn, alice.id.PublicKey(), l.ID()); !errors.Is(err, kolosync.ErrNotFound) {
		t.Fatalf("FetchHeader of a removed log = %v, want kolosync.ErrNotFound", err)
	}
}

// Serve uses Options.Identity, so a listener made with it is the pinning peer, and writes no identity.key.
func TestServeUsesGivenIdentity(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	id := generate(t)
	dir := privateDir(t)
	sctx, cancel := context.WithCancel(ctx)
	ln, err := kolosecure.Listen(sctx, "127.0.0.1:0", id, nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Serve(sctx, ln, Options{Dir: dir, Identity: id}) }()
	defer func() {
		cancel()
		<-done
		_ = ln.Close()
	}()
	peer := Peer{ID: id.PublicKey(), Addr: ln.Addr().String()}
	alice := newOwner(t)
	l := alice.log(t, "a0")
	if _, err := Add(ctx, alice.id, peer, l, alice.issue(t, peer, Capability{})); err != nil {
		t.Fatalf("Add under the given identity = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "identity.key")); !os.IsNotExist(err) {
		t.Fatalf("identity.key after Serve with an Identity: %v", err)
	}
}

// Without an Identity, Serve takes LoadIdentity(Dir), which writes identity.key.
func TestServeWithoutIdentityWritesKey(t *testing.T) {
	p := startPin(t, Options{})
	if _, err := os.Stat(filepath.Join(p.dir, "identity.key")); err != nil {
		t.Fatalf("identity.key: %v", err)
	}
}
