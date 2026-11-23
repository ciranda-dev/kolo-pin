package pin

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	koloid "github.com/ciranda-dev/kolo-id"
	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolosync "github.com/ciranda-dev/kolo-sync"
	"github.com/prometheus/client_golang/prometheus"
)

// DefaultMaxBytes is the default Options.MaxBytes: 100 GB.
const DefaultMaxBytes = 100_000_000_000

// DefaultMaxOwners is the default Options.MaxOwners: a revoke-only record is about 50 bytes and a capability at most
// 8353, so 100,000 records take at most 0.8 GB.
const DefaultMaxOwners = 100_000

// DefaultMaxOpenBytes is the default Options.MaxOpenBytes: 256 MiB, a quarter of kolo-transport's default MaxMemory.
const DefaultMaxOpenBytes = 256 << 20

// An open log is counted as openLogBytes plus openEntryBytes per entry, the measured heap rounded up (docs/limits.md).
const (
	openLogBytes   = 128
	openEntryBytes = 256
)

// loadChunk is how many records start-up reads from the store at a time.
const loadChunk = 1024

// retryDoublings is how many times the wait before retrying a failed log delete doubles from one sweep interval (1, 2,
// 4 ... 64 minutes at the one-minute sweep). It only bounds how often a failing delete logs and scans.
const retryDoublings = 6

// clockSkew is how far in the future a capability's issue time or a revoke note's time may be, in seconds.
const clockSkew = 60

// Test hooks, read once when Serve starts.
var (
	clock      = time.Now
	sweepEvery = time.Minute
	idleAfter  = time.Minute
	served     func(*server)
	gap        func(*hosted) // called in authorize between reading a log's header and offering it
	acquiring  func(*hosted) // called in add between finding or creating a log and acquiring it
	wrap       func(kolostore.Backend) kolostore.Backend
)

var (
	errReplayed    = fmt.Errorf("%w: older than the capability in use", ErrRevoked)
	errRevokedNote = fmt.Errorf("%w: by a revoke note", ErrRevoked)
	errOwnerGone   = errors.New("pin: owner state was just dropped")
)

// Options configures Serve.
type Options struct {
	// Dir is the data directory, holding identity.key and the store. It must be private; it is created with mode 0700.
	Dir string
	// Identity is the pinning peer's identity; Serve refuses a listener that uses another with ErrInvalidArgument. Nil loads it with
	// LoadIdentity(Dir), which writes identity.key on first use; a given Identity writes no key file.
	Identity *koloid.Identity
	// MaxBytes is the most bytes the peer stores for all owners together. Default DefaultMaxBytes.
	MaxBytes uint64
	// Owners lists the owner keys the peer accepts capabilities and revoke notes from. Empty accepts any owner, and
	// Serve then logs a warning: anyone can fill MaxBytes and MaxOwners.
	Owners []ed25519.PublicKey
	// MaxOwners is the most owner records an open peer (empty Owners) keeps: one per owner key with a capability in
	// use, a held log or a revoke note, which stays after expiry so a revoked capability is never accepted again. A
	// request that would add one past it is ErrOwnerLimit; owners already kept are not affected. Default
	// DefaultMaxOwners. It is ignored when Owners is set, since no other key can add a record.
	MaxOwners uint64
	// MaxOpenBytes is the memory the open logs may take together, counted as 128 bytes per log and 256 per entry. The
	// least recently used idle logs are closed past it, never one being pulled into. Default DefaultMaxOpenBytes.
	MaxOpenBytes uint64
	// AddTimeout bounds the time one Add may spend pulling a log, entries already stored are kept. Zero means no
	// limit but the connection's idle timeout and the owner's quota.
	AddTimeout time.Duration
	// Logger receives the peer's events; nil discards them.
	Logger *slog.Logger
	// Metrics, if set, gets the peer's kolo_pin_* metrics while Serve runs. Their labels never hold keys, IDs or addresses.
	Metrics prometheus.Registerer
}

// LoadIdentity returns the pinning peer's identity in dir, creating it (mode 0600) on first use.
func LoadIdentity(dir string) (*koloid.Identity, error) {
	if dir == "" {
		return nil, ErrInvalidArgument
	}
	path := filepath.Join(dir, "identity.key")
	id, err := koloid.Load(path)
	if !errors.Is(err, fs.ErrNotExist) {
		return id, err
	}
	if id, err = koloid.Generate(); err != nil {
		return nil, err
	}
	err = id.SaveNew(path)
	if errors.Is(err, fs.ErrExist) {
		return koloid.Load(path)
	}
	if err != nil && !errors.Is(err, koloid.ErrSavedNotSynced) {
		return nil, err
	}
	return id, nil
}

type server struct {
	key       ed25519.PublicKey
	dir       string
	disk      *disk
	sync      *kolosync.Server
	allow     map[string]bool
	log       *slog.Logger
	now       func() time.Time
	idle      time.Duration
	maxOpen   uint64 // bytes
	m         *metrics
	gap       func(*hosted)
	acquiring func(*hosted)
	retry     time.Duration // the wait before the first new try of a failed log delete: one sweep interval

	addTimeout time.Duration

	mu     sync.Mutex
	owners map[string]*owner // owners with a capability in use or a hosted log; the others live on disk only

	openMu sync.Mutex
	open   map[*hosted]struct{}
}

// Serve runs a pinning peer on node, which must listen with opts.Identity, or with LoadIdentity(opts.Dir) when that is nil,
// until ctx is done.
// It closes the connections it accepted and its store before it returns ctx.Err() or the listener's error.
func Serve(ctx context.Context, node *kolosecure.Listener, opts Options) error {
	if node == nil || opts.Dir == "" {
		return ErrInvalidArgument
	}
	id := opts.Identity
	if id == nil {
		var err error
		if id, err = LoadIdentity(opts.Dir); err != nil {
			return err
		}
	}
	if !bytes.Equal(node.PublicKey(), id.PublicKey()) {
		return fmt.Errorf("%w: the listener does not use the pinning peer's identity", ErrInvalidArgument)
	}
	db, err := kolostore.OpenPebble(filepath.Join(opts.Dir, "store"))
	if err != nil {
		return err
	}
	if wrap != nil {
		db = wrap(db)
	}
	s := &server{
		key:       id.PublicKey(),
		dir:       opts.Dir,
		allow:     map[string]bool{},
		log:       opts.Logger,
		now:       clock,
		idle:      idleAfter,
		maxOpen:   opts.MaxOpenBytes,
		m:         newMetrics(),
		gap:       gap,
		acquiring: acquiring,
		retry:     sweepEvery,
		owners:    map[string]*owner{},
		open:      map[*hosted]struct{}{},
	}
	s.disk = &disk{db: db, max: opts.MaxBytes, maxRecords: opts.MaxOwners, markers: s.m.markers}
	if s.disk.max == 0 {
		s.disk.max = DefaultMaxBytes
	}
	switch {
	case len(opts.Owners) > 0:
		s.disk.maxRecords = 0
	case s.disk.maxRecords == 0:
		s.disk.maxRecords = DefaultMaxOwners
	}
	if s.maxOpen == 0 {
		s.maxOpen = DefaultMaxOpenBytes
	}
	s.addTimeout = opts.AddTimeout
	if s.log == nil {
		s.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	for _, k := range opts.Owners {
		s.allow[string(k)] = true
	}
	s.sync = kolosync.NewServer(s.authorize)
	if err := s.load(); err != nil {
		s.close()
		return err
	}
	if opts.Metrics != nil {
		cs := s.collectors()
		for i, c := range cs {
			if err := opts.Metrics.Register(c); err != nil {
				for _, d := range cs[:i] {
					opts.Metrics.Unregister(d)
				}
				s.close()
				return fmt.Errorf("pin: metrics: %w", err)
			}
		}
		defer func() {
			for _, c := range cs {
				opts.Metrics.Unregister(c)
			}
		}()
	}
	if served != nil {
		served(s)
	}
	s.log.Info("serving", "key", hex.EncodeToString(s.key), "addr", node.Addr().String(),
		"owners", len(s.owners), "used", s.disk.used, "max-bytes", s.disk.max, "owner-records", s.disk.records,
		"max-owners", s.disk.maxRecords, "max-open-bytes", s.maxOpen)
	if len(s.allow) == 0 {
		s.log.Warn("open peer: every owner key is accepted, so anyone can fill max-bytes and max-owners; set owners to restrict it",
			"max-bytes", s.disk.max, "max-owners", s.disk.maxRecords)
	}

	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	every := sweepEvery
	wg.Go(func() { s.sweepLoop(ctx, every) })
	wg.Go(func() { s.offerLoaded(ctx) })
	for {
		conn, err := node.Accept(ctx)
		if err != nil {
			cancel()
			wg.Wait()
			s.close()
			if parent.Err() != nil {
				return parent.Err()
			}
			return err
		}
		wg.Go(func() { s.handle(ctx, conn) })
	}
}

// close saves every log's entry count in one batch, for the metrics after a restart, then closes the store.
func (s *server) close() {
	b := s.disk.db.NewBatch()
	s.mu.Lock()
	for _, o := range s.owners {
		o.mu.Lock()
		for id, h := range o.logs {
			b.Put(entriesKey(o.key, id), binary.AppendUvarint(nil, h.entries.Load()))
		}
		o.mu.Unlock()
	}
	if err := b.Commit(); err != nil {
		s.log.Warn("state write failed", "err", err.Error())
	}
	for _, o := range s.owners {
		_ = o.store.Close()
	}
	s.mu.Unlock()
	_ = s.disk.db.Close()
}

// scan calls fn for every key under prefix, reading loadChunk keys at a time so the memory it uses does not grow with
// their number; fn may write to the store.
func (s *server) scan(prefix []byte, fn func(k, v []byte) error) error {
	type kv struct{ k, v []byte }
	start, end := prefix, prefixEnd(prefix)
	for {
		var chunk []kv
		err := s.disk.db.Scan(start, end, false, loadChunk, func(k, v []byte) bool {
			chunk = append(chunk, kv{k, v})
			return true
		})
		if err != nil {
			return err
		}
		for _, r := range chunk {
			if err := fn(r.k, r.v); err != nil {
				return err
			}
		}
		if len(chunk) < loadChunk {
			return nil
		}
		start = append(chunk[len(chunk)-1].k, 0)
	}
}

// load counts the stored bytes and loads every owner with a capability or a stored log, one record at a time.
func (s *server) load() error {
	err := errors.Join(
		s.scan([]byte{pMeta}, func(k, v []byte) error {
			s.disk.used += uint64(len(k) + len(v))
			s.disk.records++
			return nil
		}),
		s.scan([]byte{pUsage}, func(_, v []byte) error {
			n, _ := binary.Uvarint(v)
			s.disk.used += n
			return nil
		}),
	)
	if err != nil {
		return err
	}
	err = s.scan([]byte{pMeta}, func(k, v []byte) error {
		if len(k) != 1+ed25519.PublicKeySize {
			return fmt.Errorf("pin: %w: owner key", kolostore.ErrCorrupt)
		}
		return s.loadOwner(k[1:], v)
	})
	if err != nil {
		return err
	}
	// Entry counts of logs no longer held, left by a crash or by the deletes above.
	return s.scan([]byte{pEntries}, func(k, _ []byte) error {
		if len(k) != 1+ed25519.PublicKeySize+kololog.LogIDSize {
			return fmt.Errorf("pin: %w: entry count key", kolostore.ErrCorrupt)
		}
		var logID kololog.LogID
		copy(logID[:], k[1+ed25519.PublicKeySize:])
		if o := s.lookup(k[1 : 1+ed25519.PublicKeySize]); o == nil || o.logs[logID] == nil {
			return s.disk.db.Delete(k)
		}
		return nil
	})
}

// loadOwner loads the owner key with its stored state meta, if it has a capability or a stored log.
func (s *server) loadOwner(key, meta []byte) error {
	_, capb, _, err := decodeMeta(meta)
	if err != nil {
		return err
	}
	if len(capb) == 0 {
		held := false
		if err := s.disk.db.Scan(ownerKey(pData, key), prefixEnd(ownerKey(pData, key)), false, 1, func(_, _ []byte) bool {
			held = true
			return false
		}); err != nil {
			return err
		}
		if !held {
			return nil
		}
	}
	o, err := s.owner(key)
	if err != nil {
		return err
	}
	if len(s.allow) > 0 && !s.allow[string(key)] && o.capb != nil {
		// The operator took the owner off the list: its capability goes, so its logs go below.
		o.cap, o.capb = Capability{}, nil
		o.sp.setQuota(0)
		if err := o.saveMeta(); err != nil {
			return err
		}
		s.log.Info("dropped", "owner", hex.EncodeToString(key), "reason", "owner not accepted")
	}
	entries := map[kololog.LogID]uint64{}
	err = s.scan(ownerKey(pEntries, key), func(k, v []byte) error {
		if len(k) != 1+ed25519.PublicKeySize+kololog.LogIDSize {
			return fmt.Errorf("pin: %w: entry count key", kolostore.ErrCorrupt)
		}
		var id kololog.LogID
		copy(id[:], k[1+ed25519.PublicKeySize:])
		entries[id], _ = binary.Uvarint(v)
		return nil
	})
	if err != nil {
		return err
	}
	ids, err := o.store.List()
	if err != nil {
		return err
	}
	for _, id := range ids {
		// A crash can leave a log the capability in use no longer covers, or one whose delete failed.
		if o.capb == nil || !o.cap.Covers(id) {
			err := o.store.Delete(id)
			if err == nil {
				s.log.Info("dropped", "owner", hex.EncodeToString(key), "log", hex.EncodeToString(id[:]), "reason", "not covered")
				continue
			}
			// Held but not served, as after a failed delete while serving, until the sweep deletes it.
			h := &hosted{o: o, id: id}
			h.failed(s, err)
			h.entries.Store(entries[id])
			o.logs[id] = h
			continue
		}
		h := &hosted{o: o, id: id}
		h.entries.Store(entries[id])
		o.logs[id] = h
	}
	if o.capb == nil && len(o.logs) == 0 {
		s.forget(o)
	}
	return nil
}

func encodeMeta(floor int64, capb []byte, revoked int64) []byte {
	var e kolocodec.Encoder
	e.PutUvarint(uint64(floor))
	e.PutBytes(capb)
	e.PutUvarint(uint64(revoked))
	return e.Bytes()
}

func decodeMeta(b []byte) (floor int64, capb []byte, revoked int64, err error) {
	d := kolocodec.NewDecoder(b)
	f, err1 := d.UvarintMax(maxTime + 1)
	capb, err2 := d.Bytes(MaxCapabilitySize)
	r, err3 := d.UvarintMax(maxTime + 1)
	if firstErr(err1, err2, err3, d.Done()) != nil {
		return 0, nil, 0, fmt.Errorf("pin: %w: owner state", kolostore.ErrCorrupt)
	}
	return int64(f), capb, int64(r), nil
}

// readMeta returns the stored state of the owner key, zero if there is none.
func (s *server) readMeta(key []byte) (floor int64, capb []byte, revoked int64, err error) {
	v, err := s.disk.db.Get(ownerKey(pMeta, key))
	if errors.Is(err, kolostore.ErrNotFound) {
		return 0, nil, 0, nil
	}
	if err != nil {
		return 0, nil, 0, err
	}
	return decodeMeta(v)
}

func (o *owner) saveMeta() error {
	return o.s.disk.putMeta(ownerKey(pMeta, o.key), encodeMeta(o.floor, o.capb, o.revoked))
}

// known reports whether the peer holds or once held state for the owner key, so its revoke notes still count
// after the operator takes it off the Owners list.
func (s *server) known(key []byte) bool {
	if s.lookup(key) != nil {
		return true
	}
	_, err := s.disk.db.Get(ownerKey(pMeta, key))
	return err == nil
}

func entriesKey(owner []byte, logID kololog.LogID) []byte {
	return append(ownerKey(pEntries, owner), logID[:]...)
}

// owner returns the in-memory state of the owner key, loading it from disk or creating it.
// A caller that fails to install a capability calls forget.
func (s *server) owner(key []byte) (*owner, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if o := s.owners[string(key)]; o != nil {
		return o, nil
	}
	floor, capb, revoked, err := s.readMeta(key)
	if err != nil {
		return nil, err
	}
	sp, err := newSpace(s.disk, key)
	if err != nil {
		return nil, err
	}
	o := &owner{s: s, key: bytes.Clone(key), sp: sp, store: kolostore.New(sp), logs: map[kololog.LogID]*hosted{},
		floor: floor, revoked: revoked}
	if len(capb) > 0 {
		c, err := ParseCapability(capb)
		if err != nil || !c.Owner.Equal(o.key) {
			return nil, fmt.Errorf("pin: %w: stored capability", kolostore.ErrCorrupt)
		}
		o.cap, o.capb = c, capb
		sp.setQuota(c.Quota)
	}
	s.owners[string(key)] = o
	return o, nil
}

// forget drops o from memory if it has no capability and no log; its floor stays on disk.
func (s *server) forget(o *owner) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.gone || o.capb != nil || len(o.logs) > 0 {
		return
	}
	o.gone = true
	delete(s.owners, string(o.key))
	_ = o.store.Close()
}

func (s *server) lookup(key []byte) *owner {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.owners[string(key)]
}

func (s *server) snapshot() []*owner {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*owner, 0, len(s.owners))
	for _, o := range s.owners {
		out = append(out, o)
	}
	return out
}

func (s *server) sweepLoop(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweep()
		}
	}
}

// sweep drops the logs of expired capabilities, deletes again the uncovered logs whose delete failed and whose
// wait is over, and closes logs nobody used for s.idle.
func (s *server) sweep() {
	now := s.now()
	for _, o := range s.snapshot() {
		o.mu.Lock()
		expired := o.capb != nil && !now.Before(o.cap.Expires)
		if expired {
			s.dropOwner(o, "expired")
		}
		retried := false
		for _, h := range o.logs {
			if !expired && !o.covered(h) && !now.Before(h.retryAt) {
				s.dropLog(o, h, "not covered")
				retried = true
				continue
			}
			h.idle(time.Now().Add(-s.idle))
		}
		o.mu.Unlock()
		if expired || retried {
			s.forget(o)
		}
	}
}

// handle serves one connection: kolo-sync pulls on its bidirectional streams, pin requests on its unidirectional ones.
func (s *server) handle(ctx context.Context, conn *kolosecure.Conn) {
	s.m.conns.Inc()
	defer s.m.conns.Dec()
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		_ = s.sync.Serve(ctx, conn)
		cancel()
		close(done)
	}()
	s.control(ctx, conn)
	cancel()
	_ = conn.Close()
	<-done
}

// control answers the peer's requests one at a time, each on its own pair of unidirectional streams.
func (s *server) control(ctx context.Context, conn *kolosecure.Conn) {
	peer := conn.RemotePublicKey()
	for {
		rs, err := conn.AcceptUniStream(ctx)
		if err != nil {
			return
		}
		_ = rs.SetReadDeadline(time.Now().Add(Timeout))
		b, err := readAll(rs, MaxRequestSize)
		_ = rs.CancelRead(0)
		var a answer
		var req request
		switch {
		case errors.Is(err, ErrTooLarge):
			a.code = codeTooLarge
			s.m.refused.WithLabelValues("other").Inc()
		case err != nil:
			return
		default:
			if req, err = decodeRequest(b); err != nil {
				a.code = codeProtocol
				s.m.refused.WithLabelValues("other").Inc()
			} else {
				a = s.do(ctx, conn, peer, req)
			}
		}
		ss, err := conn.OpenUniStream(ctx)
		if err != nil {
			return
		}
		_ = ss.SetWriteDeadline(time.Now().Add(Timeout))
		_, err = ss.Write(a.encode())
		_ = ss.Close()
		if err != nil {
			return
		}
	}
}

func (s *server) do(ctx context.Context, conn *kolosecure.Conn, peer ed25519.PublicKey, req request) answer {
	op := metricOps[req.typ-1]
	start := time.Now()
	attrs := []any{"op", op, "peer", hex.EncodeToString(peer)}
	if s.log.Enabled(ctx, slog.LevelDebug) {
		attrs = append(attrs, "addr", conn.RemoteAddr().String())
	}
	if req.typ != tRevoke {
		attrs = append(attrs, "log", hex.EncodeToString(req.logID[:]))
	}
	var in Info
	var err error
	switch req.typ {
	case tAdd:
		in, err = s.add(ctx, conn, req.logID, req.data)
	case tRemove:
		err = s.remove(peer, req.logID)
	case tStatus:
		in, err = s.status(peer, req.logID)
	case tRevoke:
		err = s.revoke(req.data)
	}
	s.m.requests.WithLabelValues(op).Inc()
	s.m.reqSeconds.WithLabelValues(op).Observe(time.Since(start).Seconds())
	if err != nil {
		s.m.refused.WithLabelValues(reason(err)).Inc()
		s.log.Info("refused", append(attrs, "err", err.Error())...)
		return answer{code: codeOf(err)}
	}
	if req.typ == tAdd {
		s.log.Info("pinned", append(attrs, "entries", in.Entries, "used", in.Used)...)
	} else if req.typ != tStatus {
		s.log.Info("done", attrs...)
	}
	if req.typ == tAdd || req.typ == tStatus {
		return answer{info: &in}
	}
	return answer{}
}

// add checks the capability, then pulls the log from the peer on conn, which serves it. No owner lock is held
// while the peer is asked for anything, so a peer that never answers stalls only its own request.
func (s *server) add(ctx context.Context, conn *kolosecure.Conn, logID kololog.LogID, capb []byte) (Info, error) {
	if s.addTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.addTimeout)
		defer cancel()
	}
	c, err := ParseCapability(capb)
	if err != nil {
		return Info{}, fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	now := s.now()
	switch {
	case !conn.RemotePublicKey().Equal(c.Owner):
		return Info{}, fmt.Errorf("%w: requester is not the capability owner", ErrUnauthorized)
	case !c.Peer.Equal(s.key):
		return Info{}, fmt.Errorf("%w: capability for another pinning peer", ErrUnauthorized)
	case !c.Covers(logID):
		return Info{}, fmt.Errorf("%w: capability does not cover the log", ErrUnauthorized)
	case len(s.allow) > 0 && !s.allow[string(c.Owner)]:
		return Info{}, fmt.Errorf("%w: owner not accepted here", ErrUnauthorized)
	case c.Issued.Unix() > now.Unix()+clockSkew:
		return Info{}, fmt.Errorf("%w: capability issued in the future", ErrUnauthorized)
	case !now.Before(c.Expires):
		return Info{}, ErrExpired
	}
	var o *owner
	var h *hosted
	for {
		if o, err = s.owner(c.Owner); err != nil {
			return Info{}, err
		}
		o.mu.Lock()
		err = s.accept(o, c, capb)
		h = o.logs[logID]
		o.mu.Unlock()
		if !errors.Is(err, errOwnerGone) {
			break
		}
	}
	if err != nil {
		s.forget(o)
		return Info{}, err
	}
	created := false
	if h == nil {
		if h, created, err = s.create(ctx, conn, o, logID); err != nil {
			return Info{}, err
		}
	}
	if s.acquiring != nil {
		s.acquiring(h)
	}
	rep, err := h.acquire()
	if errors.Is(err, ErrNotFound) {
		// Another request dropped the log after it was found here.
		err = fmt.Errorf("%w: the log was dropped during the request", ErrBusy)
	}
	if err == nil {
		before := rep.Len()
		s.m.pulls.Add(1)
		start := time.Now()
		err = kolosync.PullCiphertext(ctx, conn, rep)
		s.m.pullSeconds.Observe(time.Since(start).Seconds())
		s.m.pulls.Add(-1)
		n := rep.Len()
		for i := before; i < n; i++ {
			if r, rerr := rep.Record(i); rerr == nil {
				s.m.received.Add(float64(r.Size) + float64(len(r.Encode())))
			}
		}
		h.release(n)
	}
	if err != nil {
		if created {
			o.mu.Lock()
			if o.logs[logID] == h && h.entries.Load() == 0 {
				s.dropLog(o, h, "")
			}
			o.mu.Unlock()
		}
		return Info{}, syncErr(err)
	}
	for _, x := range o.logsOf() {
		s.offer(o, x)
	}
	return s.info(o, h), nil
}

// accept installs c as o's capability if it is newer; o.mu is held.
func (s *server) accept(o *owner, c Capability, capb []byte) error {
	issued := c.Issued.Unix()
	switch {
	case o.gone:
		return errOwnerGone
	case issued < o.revoked:
		return errRevokedNote
	case issued < o.floor:
		return errReplayed
	case o.capb != nil && bytes.Equal(o.capb, capb):
		return nil
	case o.capb != nil && issued <= o.cap.Issued.Unix():
		return errReplayed
	}
	prev, prevb, prevFloor := o.cap, o.capb, o.floor
	o.cap, o.capb, o.floor = c, capb, issued
	if err := o.saveMeta(); err != nil {
		o.cap, o.capb, o.floor = prev, prevb, prevFloor
		return err
	}
	o.sp.setQuota(c.Quota)
	for id, h := range o.logs {
		if !c.Covers(id) {
			s.dropLog(o, h, "not covered")
		} else {
			h.fails = 0
		}
	}
	return nil
}

// create fetches the log's signed header from the peer, then opens a replica for it, unless one appeared meanwhile.
func (s *server) create(ctx context.Context, conn *kolosecure.Conn, o *owner, logID kololog.LogID) (*hosted, bool, error) {
	header, err := kolosync.FetchHeader(ctx, conn, o.key, logID)
	// The client serves no log of the capability's owner with this ID, or one whose header does not verify.
	if errors.Is(err, kolosync.ErrInvalid) || errors.Is(err, kolosync.ErrNotFound) {
		return nil, false, fmt.Errorf("%w: the log is not the capability owner's: %w", ErrUnauthorized, err)
	}
	if err != nil {
		return nil, false, syncErr(err)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.gone || o.capb == nil || !o.cap.Covers(logID) {
		return nil, false, fmt.Errorf("%w: the capability changed during the request", ErrBusy)
	}
	if h := o.logs[logID]; h != nil {
		return h, false, nil
	}
	rep, err := o.store.OpenReplica(o.key, logID, header)
	if err != nil {
		return nil, false, syncErr(err)
	}
	h := &hosted{o: o, id: logID}
	h.mu.Lock()
	h.rep = rep
	s.opened(h)
	h.mu.Unlock()
	o.logs[logID] = h
	return h, true, nil
}

// dropLog stops serving h and deletes it; o.mu is held. If the delete fails, h stays held, offered again
// while the capability in use covers it, and the sweep tries again later. It logs once when the delete first
// fails and once when a later try succeeds; reason, when set, names the drop in the log on success.
func (s *server) dropLog(o *owner, h *hosted, reason string) {
	s.sync.Withdraw(o.key, h.id)
	h.offered = false
	if err := h.drop(); err != nil {
		h.failed(s, err)
		return
	}
	_ = s.disk.db.Delete(entriesKey(o.key, h.id))
	delete(o.logs, h.id)
	switch {
	case h.fails > 0:
		s.log.Info("dropped after retry", "owner", hex.EncodeToString(o.key), "log", hex.EncodeToString(h.id[:]), "failures", h.fails)
	case reason != "":
		s.log.Info("dropped", "owner", hex.EncodeToString(o.key), "log", hex.EncodeToString(h.id[:]), "reason", reason)
	}
}

// dropOwner deletes every log of o and forgets its capability; o.mu is held. The caller then calls forget.
func (s *server) dropOwner(o *owner, reason string) {
	for _, h := range o.logs {
		s.dropLog(o, h, "")
	}
	o.cap, o.capb = Capability{}, nil
	o.sp.setQuota(0)
	if err := o.saveMeta(); err != nil {
		s.log.Warn("state write failed", "owner", hex.EncodeToString(o.key), "err", err.Error())
	}
	s.log.Info("dropped", "owner", hex.EncodeToString(o.key), "reason", reason, "kept", len(o.logs))
}

func (s *server) info(o *owner, h *hosted) Info {
	o.mu.Lock()
	exp := o.cap.Expires
	o.mu.Unlock()
	used, quota := o.sp.usage()
	if !h.known.Load() {
		// The count saved at the last stop may be old after a crash; only the owner can ask, so opening is fine.
		_ = h.with(func(*kolostore.Replica) error { return nil })
	}
	return Info{Entries: h.entries.Load(), Used: used, Quota: quota, Expires: exp}
}

// hostedBy returns the log logID of the owner key, if it is held under a live capability that covers it.
func (s *server) hostedBy(key []byte, logID kololog.LogID) (*owner, *hosted) {
	o := s.lookup(key)
	if o == nil {
		return nil, nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	h := o.logs[logID]
	if o.gone || !o.covered(h) || !s.now().Before(o.cap.Expires) {
		return nil, nil
	}
	return o, h
}

func (s *server) status(peer ed25519.PublicKey, logID kololog.LogID) (Info, error) {
	o, h := s.hostedBy(peer, logID)
	if h == nil {
		return Info{}, ErrNotFound
	}
	return s.info(o, h), nil
}

// remove deletes a log for its owner, who must be the peer on the connection.
func (s *server) remove(peer ed25519.PublicKey, logID kololog.LogID) error {
	o := s.lookup(peer)
	if o == nil {
		return ErrNotFound
	}
	o.mu.Lock()
	h := o.logs[logID]
	if o.gone || h == nil {
		o.mu.Unlock()
		return ErrNotFound
	}
	s.dropLog(o, h, "")
	held := o.logs[logID] != nil
	o.mu.Unlock()
	s.forget(o)
	if held {
		return ErrBusy
	}
	return nil
}

// revoke applies a revoke note. The floor is stored even for an owner the peer holds nothing for.
func (s *server) revoke(note []byte) error {
	r, err := ParseRevocation(note)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnauthorized, err)
	}
	switch {
	case !r.Peer.Equal(s.key):
		return fmt.Errorf("%w: revoke note for another pinning peer", ErrUnauthorized)
	case len(s.allow) > 0 && !s.allow[string(r.Owner)] && !s.known(r.Owner):
		return fmt.Errorf("%w: owner not accepted here", ErrUnauthorized)
	case r.Through.Unix() > s.now().Unix()+clockSkew:
		return fmt.Errorf("%w: revoke note dated in the future", ErrUnauthorized)
	}
	until := r.Through.Unix() + 1
	for {
		o, err := s.owner(r.Owner)
		if err != nil {
			return err
		}
		o.mu.Lock()
		if o.gone {
			o.mu.Unlock()
			continue
		}
		if until > o.revoked || until > o.floor {
			prevRevoked, prevFloor := o.revoked, o.floor
			o.revoked, o.floor = max(o.revoked, until), max(o.floor, until)
			if o.capb != nil && o.cap.Issued.Unix() < o.floor {
				s.dropOwner(o, "revoked")
			} else if err = o.saveMeta(); err != nil {
				o.revoked, o.floor = prevRevoked, prevFloor
			}
		}
		o.mu.Unlock()
		s.forget(o)
		return err
	}
}

// authorize gives every peer Ciphertext access; kolo-sync answers not found for a log it is not offered. A held log
// is offered when the peer starts and when an Add of it finishes; this offers it at a request if that failed.
func (s *server) authorize(_, owner ed25519.PublicKey, logID kololog.LogID) kolosync.Access {
	if o := s.lookup(owner); o != nil {
		o.mu.Lock()
		h := o.logs[logID]
		o.mu.Unlock()
		s.offer(o, h)
	}
	return kolosync.Ciphertext
}

// offer offers h to kolo-sync under its owner and ID, unless it is offered already or no longer covered.
func (s *server) offer(o *owner, h *hosted) {
	o.mu.Lock()
	skip := !o.covered(h) || h.offered
	o.mu.Unlock()
	if skip {
		return
	}
	h.Header() // opens and verifies the log outside o.mu, so Offer reads the header from memory
	if s.gap != nil {
		s.gap(h)
	}
	o.mu.Lock()
	// The log may have been dropped or its capability changed meanwhile; a dropped log is never offered again.
	if o.covered(h) {
		h.offered = s.sync.Offer(h) == nil
	}
	o.mu.Unlock()
}

// logsOf returns the logs o holds.
func (o *owner) logsOf() []*hosted {
	o.mu.Lock()
	defer o.mu.Unlock()
	hs := make([]*hosted, 0, len(o.logs))
	for _, h := range o.logs {
		hs = append(hs, h)
	}
	return hs
}

// offerLoaded offers every log load found while the peer already serves, closing each after its header is read so it keeps
// at most one open. Opening a log reads and verifies all of it, which takes minutes on a large store.
func (s *server) offerLoaded(ctx context.Context) {
	for _, o := range s.snapshot() {
		for _, h := range o.logsOf() {
			if ctx.Err() != nil {
				return
			}
			s.offer(o, h)
			h.closeIdle()
		}
	}
}

// syncErr maps a kolo-sync or kolo-store error to the pin error the peer answers with.
func syncErr(err error) error {
	switch {
	case errors.Is(err, ErrQuotaExceeded), errors.Is(err, ErrDiskFull), errors.Is(err, ErrNotFound), errors.Is(err, ErrBusy):
		return err
	case errors.Is(err, kolosync.ErrInvalid), errors.Is(err, kolosync.ErrDiverged):
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	case errors.Is(err, kolosync.ErrTooLarge):
		return fmt.Errorf("%w: %w", ErrTooLarge, err)
	case errors.Is(err, kolosync.ErrProtocol):
		return fmt.Errorf("%w: %w", ErrProtocol, err)
	case errors.Is(err, kolosync.ErrNotFound):
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	}
	return fmt.Errorf("%w: %w", ErrBusy, err)
}

type owner struct {
	s     *server
	key   ed25519.PublicKey
	sp    *space
	store *kolostore.Store

	mu      sync.Mutex // guards the fields below; never held while a peer is asked for anything
	cap     Capability
	capb    []byte // nil when no capability is in use
	floor   int64  // capabilities issued before this Unix second are refused
	revoked int64  // capabilities issued before this Unix second were revoked by a note
	logs    map[kololog.LogID]*hosted
	gone    bool // forgotten: a new owner value replaces it
}

// covered reports whether h is held under a capability in use that covers it; o.mu is held.
// A log whose delete failed stays held without being covered.
func (o *owner) covered(h *hosted) bool {
	return h != nil && o.logs[h.id] == h && o.capb != nil && o.cap.Covers(h.id)
}

// hosted is a stored replica that is opened when read and closed when idle or when too many are open,
// since kolo-store keeps an open log in memory.
type hosted struct {
	o       *owner
	id      kololog.LogID
	offered bool      // offered to kolo-sync under its owner and ID; guarded by o.mu
	fails   int       // deletes that failed since the log was last covered; guarded by o.mu
	retryAt time.Time // the sweep tries the delete again from this time; guarded by o.mu
	entries atomic.Uint64
	known   atomic.Bool  // entries comes from the replica, not from the count saved at the last stop
	last    atomic.Int64 // Unix nanoseconds of the last use

	mu    sync.Mutex
	rep   *kolostore.Replica
	pulls int
	gone  bool
	head  kololog.LogHeader
}

// open returns the replica, opening it if needed; h.mu is held.
func (h *hosted) open() (*kolostore.Replica, error) {
	if h.gone {
		return nil, ErrNotFound
	}
	if h.rep == nil {
		rep, err := h.o.store.OpenReplica(h.o.key, h.id, nil)
		if err != nil {
			return nil, err
		}
		h.rep = rep
		h.entries.Store(rep.Len())
		h.known.Store(true)
		h.o.s.opened(h)
	}
	if h.head.LogKey == nil {
		h.head = h.rep.Header()
	}
	h.last.Store(time.Now().UnixNano())
	return h.rep, nil
}

// closeRep closes the replica; h.mu is held.
func (h *hosted) closeRep() {
	if h.rep == nil {
		return
	}
	_ = h.rep.Close()
	h.rep = nil
	s := h.o.s
	s.openMu.Lock()
	delete(s.open, h)
	s.openMu.Unlock()
}

func openCost(entries uint64) uint64 { return openLogBytes + entries*openEntryBytes }

// opened records h as open and trims; h.mu is held.
func (s *server) opened(h *hosted) {
	h.last.Store(time.Now().UnixNano())
	s.openMu.Lock()
	s.open[h] = struct{}{}
	s.openMu.Unlock()
	s.trim(h)
}

// trim closes the least recently used idle replicas other than h until the open ones fit in s.maxOpen; h.mu is held.
func (s *server) trim(h *hosted) {
	s.openMu.Lock()
	var used uint64
	for o := range s.open {
		used += openCost(o.entries.Load())
	}
	var others []*hosted
	if used > s.maxOpen {
		for o := range s.open {
			if o != h {
				others = append(others, o)
			}
		}
	}
	s.openMu.Unlock()
	slices.SortFunc(others, func(a, b *hosted) int { return cmp.Compare(a.last.Load(), b.last.Load()) })
	for _, o := range others {
		if used <= s.maxOpen {
			break
		}
		// TryLock: another goroutine holding o.mu may be opening a replica itself.
		if o.mu.TryLock() {
			if o.pulls == 0 && o.rep != nil {
				used -= openCost(o.entries.Load())
				o.closeRep()
			}
			o.mu.Unlock()
		}
	}
}

func (h *hosted) with(fn func(*kolostore.Replica) error) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	r, err := h.open()
	if err != nil {
		return err
	}
	return fn(r)
}

// acquire opens the replica for a pull and keeps it open until release.
func (h *hosted) acquire() (*kolostore.Replica, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	r, err := h.open()
	if err == nil {
		h.pulls++
	}
	return r, err
}

// release ends a pull that left n entries. A failed write changes nothing in kolo-store, so the replica stays open.
func (h *hosted) release(n uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pulls--
	h.entries.Store(n)
	h.known.Store(true)
	h.last.Store(time.Now().UnixNano())
	h.o.s.trim(h)
}

// closeIdle closes the replica unless a pull is using it.
func (h *hosted) closeIdle() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pulls == 0 {
		h.closeRep()
	}
}

func (h *hosted) idle(before time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pulls == 0 && h.last.Load() < before.UnixNano() {
		h.closeRep()
	}
}

// failed records a failed delete of h and when the sweep tries again (see retryDoublings). It logs only the first
// failure; o.mu is held.
func (h *hosted) failed(s *server, err error) {
	h.fails++
	h.retryAt = s.now().Add(s.retry << min(h.fails-1, retryDoublings))
	if h.fails == 1 {
		s.log.Warn("delete failed, log kept", "owner", hex.EncodeToString(h.o.key), "log", hex.EncodeToString(h.id[:]), "err", err.Error(), "retry", s.retry.String())
	}
}

// drop closes the replica and deletes it, holding h.mu so nothing reopens it meanwhile.
// A log whose delete failed stays usable, for a later request to use or drop.
func (h *hosted) drop() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closeRep()
	err := h.o.store.Delete(h.id)
	h.gone = err == nil
	return err
}

func (h *hosted) ID() kololog.LogID { return h.id }

func (h *hosted) Header() kololog.LogHeader {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.head.LogKey == nil {
		_, _ = h.open()
	}
	return h.head
}

// Head starts every kolo-sync stream a peer opens to pull this log.
func (h *hosted) Head() (head kololog.Head, err error) {
	h.o.s.m.requests.WithLabelValues("sync_pull").Inc()
	err = h.with(func(r *kolostore.Replica) error { head, err = r.Head(); return err })
	return head, err
}

func (h *hosted) Record(i uint64) (rec kololog.Record, err error) {
	err = h.with(func(r *kolostore.Replica) error { rec, err = r.Record(i); return err })
	return rec, err
}

func (h *hosted) Entry(i uint64) (e kololog.Entry, err error) {
	err = h.with(func(r *kolostore.Replica) error { e, err = r.Entry(i); return err })
	return e, err
}

func (h *hosted) EntryInfo(i uint64) (info kololog.EntryInfo, err error) {
	err = h.with(func(r *kolostore.Replica) error { info, err = r.EntryInfo(i); return err })
	return info, err
}

// Key always fails: the pinning peer never holds an entry key, and serves its logs with Ciphertext access only.
func (h *hosted) Key(uint64) (kololog.EntryKey, error) { return nil, kololog.ErrKeyUnavailable }

func (h *hosted) InclusionProof(i, n uint64) (p kololog.InclusionProof, err error) {
	err = h.with(func(r *kolostore.Replica) error { p, err = r.InclusionProof(i, n); return err })
	return p, err
}

func (h *hosted) ConsistencyProof(a, b uint64) (p kololog.ConsistencyProof, err error) {
	err = h.with(func(r *kolostore.Replica) error { p, err = r.ConsistencyProof(a, b); return err })
	return p, err
}

var _ kolosync.Source = (*hosted)(nil)
