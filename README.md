# kolo-pin

A peer that stores encrypted data for others without being able to read it.

[![status: experimental](https://img.shields.io/badge/status-experimental-orange)](#status)
[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![go: 1.26+](https://img.shields.io/badge/go-1.26%2B-00ADD8)](go.mod)

## What it is

kolo-pin stores encrypted data for others under signed, expiring capabilities, verifies what it keeps as a [Certificate Transparency monitor (RFC 9162)](https://www.rfc-editor.org/info/rfc9162) would, and spreads data over pinning peers by [rendezvous hashing](https://doi.org/10.1109/90.663936). A pinning peer keeps other people's [kolo-log](https://github.com/ciranda-dev/kolo-log) logs available while their owners are offline: chat history, or what one of your devices wrote, for your other devices. It is a [kolo-sync](https://github.com/ciranda-dev/kolo-sync) replica without entry keys: it verifies and stores signed records, ciphertexts and delete markers, and serves them to any kolo-sync client, by pull or `Fetch`, but it never has the keys to read them.

Owners allow it with a signed, expiring capability that only the owner's key can present; there are no accounts. The library is pure Go and builds with `CGO_ENABLED=0`. The `kolo-pin` binary runs one on a small server.

## Install

```sh
go get github.com/ciranda-dev/kolo-pin
go install github.com/ciranda-dev/kolo-pin/cmd/kolo-pin@latest
```

## Quick start

This program runs a pinning peer on loopback with its data in the directory given as argument, such as `go run ./examples/basic "$(mktemp -d)/pin"`. Alice pins a log and goes offline, then her phone pulls the ciphertext from the pinning peer.

```go
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
```

```text
pinned 3 entries, 2305 bytes used
phone holds 3 verified entries; reading one without its key: kololog: entry key not available
```

The phone gets the keys from alice's own devices, later, with `kolosync.Keys` access; only keys then travel, since the ciphertext is already there. The program is in [examples/basic](examples/basic).

## Run the binary

```sh
kolo-pin run -data /var/lib/kolo-pin -listen 0.0.0.0:7450 -max-bytes 100GB
kolo-pin id -data /var/lib/kolo-pin
```

`id` prints the pinning peer's public key in hex, which owners put in their capabilities. The key is created in the data directory on first use (`identity.key`, the seed unencrypted, mode 0600) and kept across restarts; the data directory must be private (mode 0700). Flags also come from `KOLO_PIN_*` environment variables, and a flag wins. `/healthz` and a Prometheus `/metrics` listen on loopback by default. Open UDP port 7450 in the firewall. Details and the flag table are in [docs/operations.md](docs/operations.md).

## API

| Symbol | What it does |
|---|---|
| `LoadIdentity(dir)` | Load or create the pinning peer's key in `dir/identity.key` |
| `Serve(ctx, node, opts)` | Run a pinning peer on a kolo-secure listener; `Options` sets `Dir`, `MaxBytes`, `Owners`, `MaxOwners`, `MaxOpenBytes`, `AddTimeout`, `Logger` and `Metrics` |
| `Issue`, `IssueMany`, `ParseCapability` | Sign a capability for one pinning peer, or one per peer, and decode one |
| `Add(ctx, id, peer, log, capability)` | Have the pinning peer pull and verify a log; call it again to send new entries and delete markers |
| `Status`, `Remove` | Read or delete a hosted log; `id` must be the log's owner; `Remove` answers `ErrBusy` when the delete fails and the log stays as it was (served while covered) |
| `IssueRevocation`, `ParseRevocation`, `Revoke` | Revoke the capabilities issued for a peer up to a time |
| `Select(peers, logID, n)` | Choose n peers for a log by rendezvous hashing, from different groups when possible |
| `AddMany` | `Add` to the n chosen peers, replacing an unreachable one with the next |

Errors are sentinels for `errors.Is`: `ErrUnauthorized`, `ErrExpired`, `ErrRevoked`, `ErrQuotaExceeded`, `ErrDiskFull`, `ErrOwnerLimit`, `ErrNotFound`, `ErrInvalid`, `ErrTooLarge`, `ErrProtocol`, `ErrBusy`, `ErrUnreachable`, `ErrInvalidArgument`, `ErrInvalidCapability` and `ErrNoPeer`.

## What a pinning peer sees

It sees which owner keys and log IDs it hosts, their entry counts and sizes, the signed records, when each log grows, is deleted from or is pulled, and for every request the requester's key, IP address and timing. It also sees every field of each capability, including every log ID listed. It cannot read entries. Anyone who knows an owner key and log ID can pull its ciphertext and records from it and learn the same metadata. Deletion is best effort: a peer that does not follow the protocol keeps what it has.

## More

- [Guide](docs/guide.md): choosing pinning peers, every call, the peer's rules, errors and design notes.
- [Operations](docs/operations.md): flags, logs and metrics of the binary.
- [Limits](docs/limits.md): storage, capability, request and memory bounds.
- [Protocol](docs/protocol.md): capability, revoke note and request formats, and the standards followed.
- [Security policy](SECURITY.md).

## Status

Experimental. The API may change before v1.0.0.

## License

Licensed under either of the [Apache License, Version 2.0](LICENSE) or the [MIT license](LICENSE-MIT), at your option.
