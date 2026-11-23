# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Options.Identity`: the pinning peer's identity for callers that already have one. `Serve` refuses a listener that uses
  another identity with `ErrInvalidArgument`, before it serves. It needs the unreleased kolo-secure that adds `Listener.PublicKey`. Nil keeps `LoadIdentity(Dir)`, the only path that writes `identity.key`.

- `Options.MaxOpenBytes` and the `-max-open-bytes` flag (`KOLO_PIN_MAX_OPEN_BYTES`): the memory the open logs may take, 256 MiB by
  default (`DefaultMaxOpenBytes`), counted as 128 bytes per log and 256 per entry, the measured cost rounded up. It replaces the
  fixed count of 64 open logs, so about 1,000 logs of 1,000 entries stay open instead of 64, and a large log closes idle ones by
  bytes. The serving event shows `max-open-bytes`.

- `Options.PeerBytesPerSecond` and `Options.PeerBurstBytes`, with the `-peer-bytes-per-second` and `-peer-burst-bytes` flags
  (`KOLO_PIN_PEER_BYTES_PER_SECOND`, `KOLO_PIN_PEER_BURST_BYTES`): the byte budget of each peer key pulling from the peer,
  passed to kolo-sync's `NewServerWith`. Zero keeps kolo-sync's defaults, 32 MiB/s and 256 MiB; a pull past the budget is
  `kolosync.ErrBusy`, and a negative value or a burst below 8 MiB is `ErrInvalidArgument`. It needs the unreleased kolo-sync
  that adds `ServerOptions.PeerBytesPerSecond`.

### Fixed

- A hosted log is offered to the kolo-sync server after the peer starts and when an `Add` finishes, not only when a request
  names it. A `kolosync.Follower` that named a log in its first watch learned nothing of it and stayed at no head and no peers.
  This holds with kolo-sync v0.1.1 or later, whose server answers a watch from the offered logs; the release requires it.
- After a start, the peer serves at once and offers the stored logs in the background, one at a time. Opening a log reads
  and verifies all of it, about 20 to 25 µs per small entry measured (docs/limits.md), so offering them before serving
  would have delayed the start by minutes on a large store.

### Changed

- **Breaking:** a pinning peer answers busy (`kolosync.ErrBusy`) to a peer key that pulls more than 256 MiB faster than 32 MiB a
  second, over all its connections, where it served it without end: it passes kolo-sync's per-peer byte budget, on by default.
  Raise `PeerBytesPerSecond` and `PeerBurstBytes` (`-peer-bytes-per-second`, `-peer-burst-bytes`) for owners that pull more,
  or set both to 1 TiB to turn it off.
- **Breaking:** the 64 open logs limit is gone. The memory of the open logs is now bounded by `MaxOpenBytes`, not by a count, so
  a peer with much memory and many small logs keeps more open than before; set `MaxOpenBytes` to bound it for your host.
- **Breaking:** the `-max-conns` default is 2016 instead of 100, the most kolo-transport's default memory check accepts (its
  `MaxMemory` divided by the receive window of a connection, less 32 dialed connections), and `-max-conns` and
  `-max-conns-per-ip` no longer stop at 10000: a value the transport's memory check refuses fails at start with its message.
- **Breaking:** `MaxOwners` (`-max-owners`) applies only to an open peer, one with no `Owners` list. A peer that lists its owners
  keeps no owner limit and ignores `MaxOwners`; `kolo_pin_owner_records_max` is 0 then.
- Start-up reads the owner records and the entry counts a chunk at a time, so its memory does not grow with the number of
  records. Owners with a capability in use or a stored log are still loaded.

- **Breaking:** a pinning peer serves an add only when the key the connection proved is the capability's owner. A requester
  with another key, even with a valid capability, now gets `ErrUnauthorized`, before the capability's expiry or
  revocation is checked. Add with the owner's identity.

## [0.1.0] - 2026-11-20

### Added

- First release of kolo-pin.
