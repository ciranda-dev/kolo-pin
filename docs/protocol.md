# Protocol

The wire formats of kolo-pin and the standards it follows. The calls that use them are in [guide.md](guide.md); bounds are in [limits.md](limits.md).

## Formats

A capability, in [kolo-codec](https://github.com/ciranda-dev/kolo-codec)
form, at most `MaxCapabilitySize` (8353) bytes:

    uvarint(0) ‖ owner key (32) ‖ pinning peer key (32) ‖ uvarint(issued)
    ‖ uvarint(expires) ‖ uvarint(quota) ‖ uvarint(n ≤ 256) ‖ n × log ID (32)
    ‖ signature (64)

The signature is Ed25519ctx by the owner over everything before it, with
context `kolo-pin/capability/v0`. Times are Unix seconds up to 2^53-1,
expires > issued, log IDs strictly ascending, no trailing bytes.

A revoke note, context `kolo-pin/revoke/v0`:

    uvarint(0) ‖ owner key (32) ‖ pinning peer key (32) ‖ uvarint(through) ‖ signature (64)

Test vectors for both are in `testdata/capability-v0.txt`.

Requests, one per unidirectional stream, at most `MaxRequestSize` (8389)
bytes, and answers, one per unidirectional stream from the pinning peer:

    uvarint(0) ‖ uvarint(type) ‖ fields
    1 ADD     log ID (32) ‖ bytes(capability)
    2 REMOVE  log ID (32)
    3 STATUS  log ID (32)
    4 REVOKE  bytes(revoke note)

    uvarint(0) ‖ uvarint(code) ‖ for ADD and STATUS with code 0:
    uvarint(entries) ‖ uvarint(used) ‖ uvarint(quota) ‖ uvarint(expires)

Codes: 0 ok, 1 not found, 2 unauthorized, 3 expired, 4 revoked, 5 quota
exceeded, 6 disk full, 7 invalid, 8 too large, 9 busy, 10 protocol, 11 owner
limit.
`bytes(x)` is a uvarint length and `x`. Non-minimal varints, other
versions and trailing bytes are protocol errors. The pinning peer stores
each owner's state as `uvarint(floor) ‖ bytes(capability) ‖
uvarint(revoked)`, where capabilities issued before `floor` are refused and
those before `revoked` were revoked by a note. There is no JSON form.

## References

- [RFC 9162, Certificate Transparency Version 2.0](https://www.rfc-editor.org/info/rfc9162) (Experimental, December 2021).
  Takes: the log verification the pinning peer relies on, through kolo-log and kolo-sync.
- [RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA)](https://www.rfc-editor.org/info/rfc8032) (Informational, January 2017).
  Takes: Ed25519ctx, for the capability and revoke note signatures.
- The capability model is the usual signed, expiring grant: an issuer, one
  audience (the pinning peer), the resources it covers, an expiry in seconds
  up to 2^53-1, 60 s clock skew, a separately signed revocation, and
  monotonic replay protection. There are no delegation chains, identifiers
  of other schemes or policy language, and the encoding is kolo-codec.
- The requests are add, status and remove, and a refresh is an add again.
  An add is synchronous, with no queue, no request IDs and no bearer tokens.
- [RFC 4918, HTTP Extensions for WebDAV](https://www.rfc-editor.org/info/rfc4918) (Proposed Standard, June 2007) 507 and
  [RFC 9110, HTTP Semantics](https://www.rfc-editor.org/info/rfc9110) (Internet Standard, June 2022) 413.
  Takes: storage limits refused before the write, with distinct answers.
  Not implemented: HTTP itself.
- Thaler and Ravishankar, [Using name-based mappings to increase hit rates](https://doi.org/10.1109/90.663936),
  IEEE/ACM Transactions on Networking, 1998.
  Takes: rendezvous hashing for `Select`, with SHA-256 weights.
- NIST [FIPS 180-4](https://doi.org/10.6028/NIST.FIPS.180-4) (2015).
  Takes: SHA-256, for the weights of `Select`.
