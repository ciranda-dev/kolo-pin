package pin

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolosync "github.com/ciranda-dev/kolo-sync"
)

// Peer is a pinning peer: its kolo-id key, its IPv4 address and an optional group label.
type Peer struct {
	ID    ed25519.PublicKey
	Addr  string // host:port, IPv4
	Group string // where it is hosted, such as a provider or region; used by Select
}

// Info is what a pinning peer holds of one log and its owner.
type Info struct {
	Entries uint64    // entries of the log it holds
	Used    uint64    // bytes the owner's logs take on it
	Quota   uint64    // the owner's quota from the capability in use; 0 means none
	Expires time.Time // when that capability expires and the logs are dropped
}

// dialTimeout bounds connecting to one pinning peer.
var dialTimeout = 10 * time.Second

// Add asks the pinning peer to keep log under capability, and serves it the log's ciphertext until it has
// pulled and verified it. Call it again after new entries or deletes. id only opens the connection.
func Add(ctx context.Context, id *koloid.Identity, peer Peer, log kolosync.Source, capability []byte) (Info, error) {
	if log == nil || len(capability) == 0 || len(capability) > MaxCapabilitySize {
		return Info{}, ErrInvalidArgument
	}
	// The server offers this one log and runs only on the connection to the pinning peer.
	srv := kolosync.NewServer(func(_, _ ed25519.PublicKey, _ kololog.LogID) kolosync.Access { return kolosync.Ciphertext })
	if err := srv.Offer(log); err != nil {
		return Info{}, fmt.Errorf("%w: %w", ErrInvalidArgument, err)
	}
	conn, err := dial(ctx, id, peer)
	if err != nil {
		return Info{}, err
	}
	sctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Go(func() { _ = srv.Serve(sctx, conn) })
	defer func() {
		cancel()
		_ = conn.Close()
		wg.Wait()
	}()
	b, err := call(ctx, conn, request{typ: tAdd, logID: log.ID(), data: capability})
	if err != nil {
		return Info{}, err
	}
	return decodeAnswer(b, true)
}

// Remove asks the pinning peer to delete the log logID; id must be the log's owner.
func Remove(ctx context.Context, id *koloid.Identity, peer Peer, logID kololog.LogID) error {
	b, err := once(ctx, id, peer, request{typ: tRemove, logID: logID})
	if err != nil {
		return err
	}
	_, err = decodeAnswer(b, false)
	return err
}

// Status returns what the pinning peer holds of the log logID; id must be the log's owner.
func Status(ctx context.Context, id *koloid.Identity, peer Peer, logID kololog.LogID) (Info, error) {
	b, err := once(ctx, id, peer, request{typ: tStatus, logID: logID})
	if err != nil {
		return Info{}, err
	}
	return decodeAnswer(b, true)
}

// Revoke gives the pinning peer a revoke note from IssueRevocation; anyone may deliver it.
func Revoke(ctx context.Context, id *koloid.Identity, peer Peer, note []byte) error {
	if len(note) == 0 || len(note) > MaxCapabilitySize {
		return ErrInvalidArgument
	}
	b, err := once(ctx, id, peer, request{typ: tRevoke, data: note})
	if err != nil {
		return err
	}
	_, err = decodeAnswer(b, false)
	return err
}

func dial(ctx context.Context, id *koloid.Identity, peer Peer) (*kolosecure.Conn, error) {
	if id == nil || len(peer.ID) != ed25519.PublicKeySize {
		return nil, ErrInvalidArgument
	}
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	conn, err := kolosecure.Dial(dctx, peer.Addr, id, peer.ID, nil)
	switch {
	case errors.Is(err, kolosecure.ErrInvalidArgument):
		return nil, fmt.Errorf("%w: %w", ErrInvalidArgument, err)
	case err != nil && ctx.Err() != nil:
		return nil, ctx.Err()
	case err != nil:
		return nil, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	return conn, nil
}

func once(ctx context.Context, id *koloid.Identity, peer Peer, r request) ([]byte, error) {
	conn, err := dial(ctx, id, peer)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return call(ctx, conn, r)
}

// call sends one request on a unidirectional stream and reads the answer from the next one the peer opens.
func call(ctx context.Context, conn *kolosecure.Conn, r request) ([]byte, error) {
	ss, err := conn.OpenUniStream(ctx)
	if err != nil {
		return nil, unreachable(ctx, err)
	}
	_ = ss.SetWriteDeadline(time.Now().Add(Timeout))
	_, err = ss.Write(r.encode())
	_ = ss.Close()
	if err != nil {
		return nil, unreachable(ctx, err)
	}
	rs, err := conn.AcceptUniStream(ctx)
	if err != nil {
		return nil, unreachable(ctx, err)
	}
	stop := context.AfterFunc(ctx, func() { _ = rs.CancelRead(0) })
	defer stop()
	_ = rs.SetReadDeadline(time.Now().Add(Timeout))
	b, err := readAll(rs, maxAnswerSize)
	if errors.Is(err, ErrTooLarge) {
		return nil, ErrProtocol
	}
	if err != nil {
		return nil, unreachable(ctx, err)
	}
	return b, nil
}

func unreachable(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, ErrUnreachable) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrUnreachable, err)
}
