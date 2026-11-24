package pin

import "errors"

var (
	// ErrInvalidArgument means a nil identity, log or listener, a key of the wrong size (also in a log's header), or a missing option.
	ErrInvalidArgument = errors.New("pin: invalid argument")
	// ErrInvalidCapability means a capability or revoke note that is malformed or whose signature does not verify.
	ErrInvalidCapability = errors.New("pin: invalid capability")
	// ErrUnauthorized means the pinning peer refused the capability: a requester that is not its owner, another
	// peer or owner, a log it does not cover, an owner the peer does not accept, a bad signature, or an issue time in the future.
	ErrUnauthorized = errors.New("pin: not authorized")
	// ErrExpired means the capability has expired.
	ErrExpired = errors.New("pin: capability expired")
	// ErrRevoked means the capability was revoked, or replaced by a newer one from the same owner.
	ErrRevoked = errors.New("pin: capability revoked or replaced")
	// ErrQuotaExceeded means the write would take the owner past the quota in its capability.
	ErrQuotaExceeded = errors.New("pin: owner quota exceeded")
	// ErrDiskFull means the write would take the pinning peer past its total byte limit.
	ErrDiskFull = errors.New("pin: pinning peer disk full")
	// ErrOwnerLimit means the pinning peer already keeps the most owner records it accepts and the owner is not one of them.
	ErrOwnerLimit = errors.New("pin: owner limit reached")
	// ErrNotFound means the pinning peer does not hold the log for this owner.
	ErrNotFound = errors.New("pin: log not found")
	// ErrInvalid means the log the pinning peer pulled does not verify; nothing past the last valid entry was kept.
	ErrInvalid = errors.New("pin: log data does not verify")
	// ErrTooLarge means a message or log entry over kolo-sync's MaxMessageSize, or a request over MaxRequestSize.
	ErrTooLarge = errors.New("pin: too large")
	// ErrBusy means the pinning peer could not finish now, for example a sync that timed out; try again later.
	ErrBusy = errors.New("pin: pinning peer busy")
	// ErrProtocol means a malformed, truncated or unexpected message, or another protocol version.
	ErrProtocol = errors.New("pin: protocol error")
	// ErrUnreachable means the pinning peer could not be reached, or the connection broke before it answered.
	ErrUnreachable = errors.New("pin: pinning peer unreachable")
	// ErrNoPeer means AddMany found no pinning peer that accepted the log.
	ErrNoPeer = errors.New("pin: no pinning peer accepted the log")
)
