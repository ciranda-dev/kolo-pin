package pin

import (
	"fmt"
	"testing"
)

// BenchmarkAdd measures one Add that brings a pinned log up by 10 entries of 1 KiB.
func BenchmarkAdd(b *testing.B) {
	ctx := testCtx(b)
	p := startPin(b, Options{})
	alice := newOwner(b)
	l := alice.log(b)
	c := alice.issue(b, p.Peer, Capability{})
	value := make([]byte, 1<<10)
	for b.Loop() {
		for range 10 {
			if _, err := l.Append(value); err != nil {
				b.Fatal(err)
			}
		}
		if _, err := Add(ctx, alice.id, p.Peer, l, c); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSyncPull measures a second device pulling a 100-entry log of 1 KiB entries from the pinning peer.
func BenchmarkSyncPull(b *testing.B) {
	ctx := testCtx(b)
	p := startPin(b, Options{})
	alice := newOwner(b)
	var values []string
	for i := range 100 {
		values = append(values, fmt.Sprintf("%d%s", i, make([]byte, 1<<10)))
	}
	l := alice.log(b, values...)
	if _, err := Add(ctx, alice.id, p.Peer, l, alice.issue(b, p.Peer, Capability{})); err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if _, err := pullFrom(b, ctx, p.Peer, alice.id.PublicKey(), l.ID()); err != nil {
			b.Fatal(err)
		}
	}
}
