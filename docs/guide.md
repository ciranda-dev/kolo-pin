# Guide

The library API of kolo-pin: choosing pinning peers, the server and client calls, capabilities, the rules a pinning peer follows, errors and design. Bounds are in [limits.md](limits.md); the wire format is in [protocol.md](protocol.md); the binary is in [operations.md](operations.md).

## Choose pinning peers

An application usually keeps each log on two or more pinning peers, run by
different people or in different places. Give each peer a `Group`, such as
its provider or region. `Select(peers, logID, n)` picks n peers for a log
by rendezvous hashing: every (peer, log) pair gets the weight
SHA-256(peer ID ‖ log ID), and the heaviest peers win. The result does not
depend on the order of the list, and when one peer joins or leaves, only
the logs for which that peer is among the chosen ones move (about n/(N+1)
of them for N peers). Chosen peers come from different groups when there
are enough groups; otherwise the next heaviest fill in and
`SharedGroups` is true.

A capability names one pinning peer, so `IssueMany` signs one per peer.
`AddMany(ctx, id, peers, log, capabilities, n)` adds the log to the n
chosen peers, replaces an unreachable one with the next peer in the same
order (at most `MaxFallback`, 2, times), and returns a `Report` with each
try (`Accepted`, `Refused`, `Unreachable`) and how many accepted. It
returns `ErrNoPeer` if none did, and `ctx.Err()` if the context ended
before it finished, with the tries made so far in the report. n of 0 or
less means `DefaultCopies`, 2. There is no retry in the background: call it again.

`go run ./examples/choose "$(mktemp -d)"` runs three pinning peers in two
groups and pins a log to two of them:

```go
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
```

## API

Server:

- `LoadIdentity(dir)` loads the pinning peer's key from `dir/identity.key`,
  creating it on first use.
- `Serve(ctx, node, opts)` runs a pinning peer on `node`, a
  `*kolosecure.Listener` made with that key, until `ctx` is done, then
  closes the connections it accepted and its store and returns `ctx.Err()`.
  `Options`: `Dir` (data directory, required), `MaxBytes` (default
  `DefaultMaxBytes`, 100 GB), `Owners` (accepted owner keys; empty accepts
  any and logs a warning at start), `MaxOwners` (owner records kept, default
  `DefaultMaxOwners`), `AddTimeout` (the most time one `Add` pulls, default
  none), `Logger` (nil discards) and `Metrics` (a `prometheus.Registerer`
  that gets the `kolo_pin_*` metrics while `Serve` runs, or nil). Every
  connection is served by kolo-sync, so any peer pulls a hosted log, or
  gets a range of its entries with `kolosync.Fetch`, as ciphertext, by its
  owner key and log ID. A hosted log is identified by both: another
  owner's log with the same ID is held, served and dropped on its own and
  never replaces it.

Client; `id` is the kolo-id identity the connection is made with, and
`peer` a `Peer` (its key, IPv4 `host:port` and optional `Group`):

- `Add(ctx, id, peer, log, capability) (Info, error)` serves `log` (a
  kolo-store or kolo-log log or replica) to the pinning peer without entry
  keys and returns once it has pulled and verified it. Call it again to
  send new entries and delete markers. `id` must be the capability's
  owner: the pinning peer serves an add only on a connection whose key is the owner's. A device that owns a log
  adds it itself; a sibling device cannot add for another key. A path based on device certificates may come later.
- `Status(ctx, id, peer, logID) (Info, error)` and
  `Remove(ctx, id, peer, logID)`: `id` must be the log's owner.
  `Info` has `Entries`, `Used` (bytes of all the owner's logs on the peer),
  `Quota` and `Expires`.
- `Revoke(ctx, id, peer, note)` delivers a revoke note.

Capabilities:

- `Issue(owner, c)` signs a `Capability`: `Peer` (the one pinning peer),
  `Logs` (empty for all of the owner's logs, at most `MaxLogs`, 256),
  `Issued` (zero means now), `Expires` (required) and `Quota` (bytes, 0 for
  none). Times are whole seconds.
- `ParseCapability(b)` decodes one and checks the owner's signature.
  `Capability.Covers(logID)` tells whether it covers a log.
- `IssueRevocation(owner, peer, through)` signs a revoke note for every
  capability issued for `peer` at or before `through`;
  `ParseRevocation(b)` decodes one.

The pinning peer's rules:

- It accepts a capability that names it, covers the log, names an owner it
  accepts, is not issued more than 60 s in its future and has not expired.
  The log's signed header must name the capability's owner.
- Per owner it keeps the newest capability. An older one, or another one
  with the same issue time, is `ErrRevoked`; the same one again is fine. A
  newer one replaces it at once: logs it no longer covers are deleted, and
  its quota applies from then on. At start, logs the stored capability
  does not cover are deleted too, so a crash in between leaves none.
- If a delete fails (a disk error, or the owner's log open in the same
  process), the log stays on disk. A log the capability in use still
  covers stays served and reported, so the next `Add` pins it. A log it
  does not cover is neither offered nor reported (`Status` answers not
  found); the sweep deletes it again, after one sweep interval (a minute)
  and then after twice as long each time, up to 64 minutes, as does the
  next start, which keeps going when the delete fails. Until it is
  deleted, the log's bytes still count against the owner's quota and
  `MaxBytes`, and in `Used`, so an `Add` can answer `ErrQuotaExceeded` or
  `ErrDiskFull` for space the owner cannot see.
- When the capability expires (checked every minute) or a revoke note
  covers it, every log of that owner is deleted. `Status` answers not
  found from the moment of expiry. A revoke note is stored even for an
  owner the peer has never seen, so a token revoked before its first use
  is refused; a note dated more than 60 s in the peer's future is refused
  (`ErrUnauthorized`), so it cannot lock the owner out. Each owner has one
  record, which a later note or capability only replaces, and the peer keeps
  at most `MaxOwners` of them: past that, a note or capability of a new owner
  is `ErrOwnerLimit`, and owners already kept are never refused.
- The pinning peer never asks for entry keys (`kolosync.PullCiphertext`),
  so it stores none even when a client offers them, and it serves its logs
  with `Ciphertext` access only, so no pull or `Fetch` from it carries a
  key. A log with derived entry keys (kolo-log `WithDerivedKeys`) is pinned
  the same way: the peer never holds its entry secret, and a device that
  does derives the keys of the copy it pulls.
- A write that would take the owner past its quota is `ErrQuotaExceeded`;
  one that would take the peer past `MaxBytes` is `ErrDiskFull`. Both are
  refused before anything is stored, and nothing is evicted to make room.
  Bytes are counted as stored keys and values (each owner's logs and
  capability state), not disk blocks; the peer's own small counters are
  not counted. Deletes always pass.

## Errors

Errors work with `errors.Is`; none carries bytes a peer sent.

- `ErrUnauthorized`: the requester is not the capability's owner (checked first, before
  expiry or revocation), the capability is for another peer or owner, does not
  cover the log, has a bad signature or an issue time in the future, the
  owner is not accepted, or the log is not the owner's.
- `ErrExpired`, `ErrRevoked`, `ErrQuotaExceeded`, `ErrDiskFull`.
- `ErrOwnerLimit`: the peer keeps the most owner records it accepts and this
  owner is not one of them; its operator can raise `MaxOwners` or list the
  owners.
- `ErrNotFound`: the peer does not hold the log for this owner.
- `ErrInvalid`: the log did not verify; the peer kept what verified before.
- `ErrTooLarge`, `ErrProtocol`, `ErrBusy` (try again later). `Remove`
  answers `ErrBusy` when the delete fails: the log stays as it was (served
  while covered, held but not served otherwise), so call it again. `Add` answers it for a log that another request
  dropped meanwhile.
- `ErrUnreachable`: the connection failed or broke before the answer.
- `ErrInvalidArgument`, `ErrInvalidCapability` (local parsing), `ErrNoPeer`.

## Design

- A pinning peer is a kolo-store replica with kolo-sync's `Ciphertext`
  access. Everything it stores went through `Replica.Update` or
  `Replica.ApplyDelete`, which check every signature, hash and consistency
  proof first, so it never stores a forged entry.
- On a connection, kolo-sync uses the bidirectional streams, unchanged, and
  pin requests use unidirectional ones: one stream per request, one per
  answer. `Add` makes the pinning peer pull from the client on the same
  connection; it never accepts pushed data.
- Each owner's replicas sit under their own key prefix in one Pebble store.
  A small wrapper counts the bytes of every write and stores the owner's
  count in the same batch, so limits hold across crashes. Its lock guards
  only the counts: a commit reserves its growth, writes with no lock held
  but its owner's, and settles the counts, so one owner removing a large log
  never blocks another owner's writes.
- No owner lock is held while the pinning peer waits for a client, so a
  client that never answers stalls only its own request.
- Requests on one connection are answered one at a time, each read within
  60 s and at most `MaxRequestSize` bytes. There is no other rate limit
  than the owner quota, `MaxBytes`, and the connection, stream, size and
  time limits of kolo-transport and kolo-sync.

What the pinning peer can see: which owner keys and log IDs it hosts,
their entry counts and sizes, the signed records, when each log grows, is
deleted from or is pulled, and for every request the requester's key, IP
address and timing. It also sees every field of each capability: issue
time, expiry, quota, and every log ID listed, including logs never pinned
there. It cannot read entries. Anyone who knows an owner key and log ID can pull its
ciphertext and records from it and learn the same metadata.

Deletion is best effort. The pinning peer applies an owner's new delete
markers at the next `Add`, as kolo-sync hands them over, and drops their
ciphertexts in the same write. A peer that does
not follow the protocol keeps what it has, and old disk blocks can hold
deleted bytes (see kolo-store).
