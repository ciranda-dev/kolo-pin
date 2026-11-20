package pin

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"slices"
	"time"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	koloid "github.com/ciranda-dev/kolo-id"
	kololog "github.com/ciranda-dev/kolo-log"
)

const (
	// CapabilityContext is the Ed25519ctx context of a capability signature.
	CapabilityContext = "kolo-pin/capability/v0"
	// RevokeContext is the Ed25519ctx context of a revoke note signature.
	RevokeContext = "kolo-pin/revoke/v0"
	// MaxLogs is the most log IDs one capability lists.
	MaxLogs = 256
	// MaxCapabilitySize is the size of a capability that lists MaxLogs logs.
	MaxCapabilitySize = 1 + 2*32 + 3*10 + 2 + MaxLogs*32 + ed25519.SignatureSize
	// maxTime is the largest issue or expiry time, in Unix seconds: a value every JSON number can carry exactly.
	maxTime = 1<<53 - 1
)

var errBadSignature = fmt.Errorf("%w: bad signature", ErrInvalidCapability)

// Capability lets one pinning peer keep and serve an owner's logs until it expires; the owner signs it.
type Capability struct {
	Owner   ed25519.PublicKey // the log owner who signs it; Issue sets it
	Peer    ed25519.PublicKey // the one pinning peer it is for
	Logs    []kololog.LogID   // the logs it covers; empty means every log of Owner
	Issued  time.Time         // newer capabilities replace older ones; zero means now in Issue
	Expires time.Time         // after this the pinning peer drops the logs
	Quota   uint64            // the most bytes Owner's logs may take on Peer; 0 means only the peer's own limit
}

// Covers reports whether c covers the log logID.
func (c Capability) Covers(logID kololog.LogID) bool {
	return len(c.Logs) == 0 || slices.Contains(c.Logs, logID)
}

// Issue signs c with the owner's identity and returns the encoded capability, in whole seconds.
func Issue(owner *koloid.Identity, c Capability) ([]byte, error) {
	if owner == nil {
		return nil, ErrInvalidArgument
	}
	c.Owner = owner.PublicKey()
	if c.Issued.IsZero() {
		c.Issued = time.Now()
	}
	if err := c.check(); err != nil {
		return nil, err
	}
	logs := slices.Clone(c.Logs)
	slices.SortFunc(logs, func(a, b kololog.LogID) int { return bytes.Compare(a[:], b[:]) })
	c.Logs = slices.Compact(logs)
	msg := c.signed()
	sig, err := owner.Sign(CapabilityContext, msg)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidArgument, err)
	}
	return append(msg, sig...), nil
}

func (c Capability) check() error {
	switch {
	case len(c.Owner) != ed25519.PublicKeySize || len(c.Peer) != ed25519.PublicKeySize:
		return fmt.Errorf("%w: keys must be %d bytes", ErrInvalidArgument, ed25519.PublicKeySize)
	case c.Owner.Equal(c.Peer):
		return fmt.Errorf("%w: owner and peer are the same key", ErrInvalidArgument)
	case len(c.Logs) > MaxLogs:
		return fmt.Errorf("%w: more than %d logs", ErrInvalidArgument, MaxLogs)
	case c.Issued.Unix() < 0 || c.Expires.Unix() > maxTime || c.Expires.Unix() <= c.Issued.Unix():
		return fmt.Errorf("%w: expiry must be after the issue time, both after 1970", ErrInvalidArgument)
	}
	return nil
}

func (c Capability) signed() []byte {
	var e kolocodec.Encoder
	e.PutUvarint(0)
	e.PutFixed(c.Owner)
	e.PutFixed(c.Peer)
	e.PutUvarint(uint64(c.Issued.Unix()))
	e.PutUvarint(uint64(c.Expires.Unix()))
	e.PutUvarint(c.Quota)
	e.PutUvarint(uint64(len(c.Logs)))
	for _, id := range c.Logs {
		e.PutFixed(id[:])
	}
	return e.Bytes()
}

// ParseCapability decodes a capability and checks its owner's signature; it never panics on untrusted input.
// It does not check the time: the pinning peer does, against its own clock.
func ParseCapability(b []byte) (Capability, error) {
	var c Capability
	if len(b) < ed25519.SignatureSize || len(b) > MaxCapabilitySize {
		return c, fmt.Errorf("%w: %d bytes", ErrInvalidCapability, len(b))
	}
	msg, sig := b[:len(b)-ed25519.SignatureSize], b[len(b)-ed25519.SignatureSize:]
	d := kolocodec.NewDecoder(msg)
	if v, err := d.Uvarint(); err != nil || v != 0 {
		return c, fmt.Errorf("%w: unknown version", ErrInvalidCapability)
	}
	owner, err1 := d.Fixed(ed25519.PublicKeySize)
	peer, err2 := d.Fixed(ed25519.PublicKeySize)
	issued, err3 := d.UvarintMax(maxTime)
	expires, err4 := d.UvarintMax(maxTime)
	quota, err5 := d.Uvarint()
	n, err6 := d.UvarintMax(MaxLogs)
	if err := firstErr(err1, err2, err3, err4, err5, err6); err != nil {
		return c, fmt.Errorf("%w: %w", ErrInvalidCapability, err)
	}
	if uint64(d.Len()) != n*kololog.LogIDSize {
		return c, fmt.Errorf("%w: wrong length for %d logs", ErrInvalidCapability, n)
	}
	c = Capability{Owner: owner, Peer: peer, Issued: time.Unix(int64(issued), 0), Expires: time.Unix(int64(expires), 0), Quota: quota}
	for i := uint64(0); i < n; i++ {
		var id kololog.LogID
		raw, _ := d.Fixed(kololog.LogIDSize)
		copy(id[:], raw)
		if len(c.Logs) > 0 && bytes.Compare(c.Logs[len(c.Logs)-1][:], id[:]) >= 0 {
			return Capability{}, fmt.Errorf("%w: log IDs not in strict order", ErrInvalidCapability)
		}
		c.Logs = append(c.Logs, id)
	}
	if c.Owner.Equal(c.Peer) || expires <= issued {
		return Capability{}, fmt.Errorf("%w: bad fields", ErrInvalidCapability)
	}
	if !koloid.Verify(c.Owner, CapabilityContext, msg, sig) {
		return Capability{}, errBadSignature
	}
	return c, nil
}

// Revocation revokes every capability an owner issued for one pinning peer at or before Through.
type Revocation struct {
	Owner   ed25519.PublicKey
	Peer    ed25519.PublicKey
	Through time.Time
}

// IssueRevocation signs a revoke note: peer drops owner's logs if its capability was issued at or before through.
func IssueRevocation(owner *koloid.Identity, peer ed25519.PublicKey, through time.Time) ([]byte, error) {
	if owner == nil || len(peer) != ed25519.PublicKeySize || owner.PublicKey().Equal(peer) ||
		through.Unix() < 0 || through.Unix() > maxTime {
		return nil, ErrInvalidArgument
	}
	r := Revocation{Owner: owner.PublicKey(), Peer: peer, Through: through}
	msg := r.signed()
	sig, err := owner.Sign(RevokeContext, msg)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidArgument, err)
	}
	return append(msg, sig...), nil
}

func (r Revocation) signed() []byte {
	var e kolocodec.Encoder
	e.PutUvarint(0)
	e.PutFixed(r.Owner)
	e.PutFixed(r.Peer)
	e.PutUvarint(uint64(r.Through.Unix()))
	return e.Bytes()
}

// ParseRevocation decodes a revoke note and checks its owner's signature; it never panics on untrusted input.
func ParseRevocation(b []byte) (Revocation, error) {
	var r Revocation
	if len(b) < ed25519.SignatureSize || len(b) > 1+2*32+10+ed25519.SignatureSize {
		return r, fmt.Errorf("%w: %d bytes", ErrInvalidCapability, len(b))
	}
	msg, sig := b[:len(b)-ed25519.SignatureSize], b[len(b)-ed25519.SignatureSize:]
	d := kolocodec.NewDecoder(msg)
	v, err0 := d.Uvarint()
	owner, err1 := d.Fixed(ed25519.PublicKeySize)
	peer, err2 := d.Fixed(ed25519.PublicKeySize)
	through, err3 := d.UvarintMax(maxTime)
	if err := firstErr(err0, err1, err2, err3, d.Done()); err != nil || v != 0 {
		return r, fmt.Errorf("%w: malformed revoke note", ErrInvalidCapability)
	}
	r = Revocation{Owner: owner, Peer: peer, Through: time.Unix(int64(through), 0)}
	if !koloid.Verify(r.Owner, RevokeContext, msg, sig) {
		return Revocation{}, errBadSignature
	}
	return r, nil
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
