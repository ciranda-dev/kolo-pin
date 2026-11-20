// Command choose runs three pinning peers on loopback, with their data under the directory given as argument,
// and pins one log to the two that Select chooses for it, from different groups.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	"github.com/ciranda-dev/kolo-pin"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: choose DIR")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Three pinning peers; in an application this list comes from configuration.
	var peers []pin.Peer
	for i, group := range []string{"provider-a", "provider-a", "provider-b"} {
		dir := filepath.Join(os.Args[1], fmt.Sprint("pin", i))
		id, err := pin.LoadIdentity(dir)
		if err != nil {
			log.Fatal(err)
		}
		ln, err := kolosecure.Listen(ctx, "127.0.0.1:0", id, nil)
		if err != nil {
			log.Fatal(err)
		}
		defer ln.Close()
		go pin.Serve(ctx, ln, pin.Options{Dir: dir})
		peers = append(peers, pin.Peer{ID: id.PublicKey(), Addr: ln.Addr().String(), Group: group})
	}

	alice, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}
	st := kolostore.New(kolostore.NewMemory())
	defer st.Close()
	l, err := st.Create(alice)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := l.Append([]byte("chat history")); err != nil {
		log.Fatal(err)
	}

	sel := pin.Select(peers, l.ID(), 2)
	fmt.Printf("chosen: %s and %s, shared group: %v\n", sel.Peers[0].Group, sel.Peers[1].Group, sel.SharedGroups)
	caps, err := pin.IssueMany(alice, sel.Peers, pin.Capability{Expires: time.Now().Add(30 * 24 * time.Hour)})
	if err != nil {
		log.Fatal(err)
	}
	report, err := pin.AddMany(ctx, alice, peers, l, caps, 2)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("accepted by %d peers\n", report.Accepted)
	for _, r := range report.Results {
		fmt.Printf("  %s: %v, %d entries\n", r.Peer.Group, r.Outcome, r.Info.Entries)
	}
}
