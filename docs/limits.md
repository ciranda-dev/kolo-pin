# Limits

Every bound in kolo-pin, with its value and what it protects. The flags that set some of them are in [operations.md](operations.md); the calls are in [guide.md](guide.md).

## Storage

| Limit | Value | Notes |
|---|---|---|
| `MaxBytes` (`-max-bytes`) | 100 GB (`DefaultMaxBytes`) | Most bytes stored for all owners together. A write past it is `ErrDiskFull`. |
| `MaxOwners` (`-max-owners`) | 100,000 (`DefaultMaxOwners`) | Most owner records kept, one per owner key that ever had a capability or revoke note accepted; a record stays after expiry, since it is what refuses a revoked capability. A new owner past it is `ErrOwnerLimit`; owners already kept are never refused. |
| `Capability.Quota` | set by the owner, 0 for none | Most bytes stored for one owner. A write past it is `ErrQuotaExceeded`. |
| Largest entry value | 4,128,764 bytes (4 MiB - 64 KiB - 4) | One byte more is `ErrTooLarge`. kolo-sync's messages are 4 MiB (`MaxMessageSize`) and must also hold the record and framing, and kolo-log pads an entry of this size to a multiple of 64 KiB, so the largest padded entry that fits is 4 MiB - 64 KiB, of which 4 bytes are its length. Large files must be split into entries. |

- Both storage limits are checked before anything is stored, and nothing is evicted to make room. Deletes always pass.
- Bytes are counted as stored keys and values (each owner's logs and capability state), not disk blocks; the peer's own small counters are not counted.
- With an open `-owners`, anyone can fill the disk up to `-max-bytes` with new keys, and each owner key with a capability in use also takes a small record in memory. The peer logs a warning at start when it is open. List your owners to keep the peer for them.

### Owner records

An owner key has one record: its capability in use (at most `MaxCapabilitySize`, 8353 bytes) and two times. A later capability or revoke note of the same key replaces the record and never adds one, so one key cannot grow it. A revoke note from a key the peer holds nothing for stores a record of about 50 bytes (an `m` key of 33 bytes and 11 bytes of value) that stays after the note, because it is what refuses the owner's older capabilities; nothing deletes it. On an open peer anyone can sign such a note with a throwaway key, so without a bound the records fill the disk and make every start slower, since the start reads them all.

`MaxOwners` bounds that. The default is derived from the record layout, not copied from another system: 100,000 records are about 5 MB of revoke-only records or at most 0.8 GB of capabilities, and an average of 1 MB per owner for a peer that fills the default 100 GB. At start the peer reads every record into memory for a moment (roughly 150 bytes each, estimated from the Go types and not measured, so about 15 MB for 100,000) and does one lookup for each. A peer that already holds more records than `MaxOwners` (a lowered limit) keeps them all and accepts no new owner. When an attacker fills the limit on an open peer, new owners are refused until the operator raises it or lists the owners with `-owners`; the owners already kept, and their revocations, are not affected. `kolo_pin_owner_records` and `kolo_pin_owner_records_max` show the count, and a refusal counts as `owner_limit` in `kolo_pin_refused_total`.

## Capabilities and requests

| Limit | Value | Notes |
|---|---|---|
| `MaxLogs` | 256 | Logs named in one capability; empty means all of the owner's logs. |
| `MaxCapabilitySize` | 8353 bytes | Encoded capability. |
| `MaxRequestSize` | 8389 bytes | One request on a unidirectional stream. |
| Clock skew | 60 s | A capability issued, or a revoke note dated, more than this in the peer's future is refused. |
| Request read time | 60 s | Requests on one connection are answered one at a time, each read within this time. |
| `AddTimeout` (`-add-timeout`) | none | Most time one `Add` may spend, pulling included; past it the `Add` is `ErrBusy` and the entries stored so far are kept. Without it a pull runs while the owner keeps sending, bounded by the connection's idle timeout and the owner's quota. |
| Expiry check | every minute | A capability that has expired, or that a revoke note covers, deletes every log of that owner, and the same sweep tries again the deletes that failed. |
| Delete retry | 1 to 64 minutes | A log whose delete failed is tried again by the sweep after one sweep interval, then after twice as long each time, up to 64 intervals. It only limits how often a delete that keeps failing logs and scans the log's keys. |
| `MaxFallback` | 2 | Replacement peers `AddMany` tries for an unreachable one. |
| `DefaultCopies` | 2 | Peers `AddMany` uses when n is 0 or less. |

There is no rate limit other than the owner quota, `MaxBytes`, `MaxOwners`, and the connection, stream, size and time limits of kolo-transport and kolo-sync.

One lock guards the disk's byte counts, and it is held only for arithmetic: a write checks its growth against the limits and reserves it, writes with no lock held but its owner's, and then settles the counts. A long delete, such as removing a large log, holds only its owner's commit lock, so it blocks that owner's other writes and no other owner's writes, `Status` calls or quota changes.

## Memory

An open kolo-store log keeps its tree hashes and a compact copy of each record in memory, about 250 bytes per entry, and reads ciphertexts from disk. The pinning peer opens a log when a request needs it, closes it after a minute unused, and keeps at most 64 open, closing the least recently used ones (never one being pulled into).

The cap bounds how many logs are open, not their size, so memory is bounded by the disk, not by RAM. A log of the smallest entries takes about 592 bytes on disk and 247 bytes of memory per entry, so 64 open logs that fill `MaxBytes` with tiny entries take about 0.4 times `MaxBytes` in memory (about 40 GB for a full 100 GB peer), and any peer that knows their owner keys and log IDs can make the pinning peer open them. Set `-max-bytes` (and owner quotas) for the RAM you have. Opening a log reads and verifies all of it, so reading many idle logs also costs the peer CPU and disk reads.

## Network

- Addresses are IPv4; IPv6 is refused.
- Connections come from kolo-transport's limits, set by `-max-conns` (default 100, up to 10,000, handshaking or open) and `-max-conns-per-ip` (default 4, at most `-max-conns`). Owners behind one NAT share one address: raise `-max-conns-per-ip` for them. A kolo-transport connection also has 16 incoming streams and a 30 s idle timeout, which have no flag.
- The metrics and health endpoints listen on loopback by default (`127.0.0.1:7452` and `127.0.0.1:7451`).
