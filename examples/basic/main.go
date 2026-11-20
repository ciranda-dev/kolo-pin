// Command basic runs a pinning peer on loopback with its data in the directory given as argument: alice pins
// a log and goes offline, then her phone pulls the log's ciphertext from the pinning peer.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	"github.com/ciranda-dev/kolo-pin"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolosync "github.com/ciranda-dev/kolo-sync"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: basic DIR")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The pinning peer: its key and store live in DIR.
	pid, err := pin.LoadIdentity(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	ln, err := kolosecure.Listen(ctx, "127.0.0.1:0", pid, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	sctx, stop := context.WithCancel(ctx)
	served := make(chan error, 1)
	go func() { served <- pin.Serve(sctx, ln, pin.Options{Dir: os.Args[1]}) }()
	peer := pin.Peer{ID: pid.PublicKey(), Addr: ln.Addr().String()}

	// Alice writes a log and lets the pinning peer keep it for 30 days, up to 100 MB.
	alice, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}
	as := kolostore.New(kolostore.NewMemory())
	l, err := as.Create(alice)
	if err != nil {
		log.Fatal(err)
	}
	for _, v := range []string{"hello", "from", "alice"} {
		if _, err := l.Append([]byte(v)); err != nil {
			log.Fatal(err)
		}
	}
	capability, err := pin.Issue(alice, pin.Capability{Peer: peer.ID, Expires: time.Now().Add(30 * 24 * time.Hour), Quota: 100_000_000})
	if err != nil {
		log.Fatal(err)
	}
	info, err := pin.Add(ctx, alice, peer, l, capability)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("pinned %d entries, %d bytes used\n", info.Entries, info.Used)
	logID := l.ID()
	as.Close() // alice goes offline

	// Her phone pulls the ciphertext from the pinning peer and verifies it against her key.
	phone, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}
	conn, err := kolosecure.Dial(ctx, peer.Addr, phone, peer.ID, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	ps := kolostore.New(kolostore.NewMemory())
	defer ps.Close()
	header, err := kolosync.FetchHeader(ctx, conn, alice.PublicKey(), logID)
	if err != nil {
		log.Fatal(err)
	}
	rep, err := ps.OpenReplica(alice.PublicKey(), logID, header)
	if err != nil {
		log.Fatal(err)
	}
	if err := kolosync.Pull(ctx, conn, rep); err != nil {
		log.Fatal(err)
	}
	_, err = rep.Get(0)
	fmt.Printf("phone holds %d verified entries; reading one without its key: %v\n", rep.Len(), err)

	stop()
	if err := <-served; err != context.Canceled {
		log.Fatal(err)
	}
}
