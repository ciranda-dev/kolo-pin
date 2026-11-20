package pin

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	kololog "github.com/ciranda-dev/kolo-log"
	kolostore "github.com/ciranda-dev/kolo-store"
	"github.com/prometheus/client_golang/prometheus"
)

// Key prefixes on the pinning peer's backend.
const (
	pData    = 'd' // 'd' ‖ owner ‖ kolo-store key: the owner's replicas
	pUsage   = 'u' // 'u' ‖ owner: uvarint bytes under the owner's data prefix
	pMeta    = 'm' // 'm' ‖ owner: the owner's capability state
	pEntries = 'n' // 'n' ‖ owner ‖ log ID: uvarint entries held, for metrics and Status
)

// disk counts every byte the pinning peer stores and refuses writes past max.
type disk struct {
	db         kolostore.Backend
	mu         sync.Mutex // guards the counts below; held for arithmetic only, never across a read or write of db
	metaMu     sync.Mutex // one putMeta at a time, so its old value is the one it replaces
	used       uint64     // includes the growth of commits in flight, reserved before they write
	max        uint64
	records    uint64 // owner records stored
	maxRecords uint64 // 0 means no limit
	markers    prometheus.Counter
}

// space is one owner's part of the disk, a kolostore.Backend under the owner's data prefix.
type space struct {
	d      *disk
	prefix []byte
	ukey   []byte
	cm     sync.Mutex // one commit at a time, so each measures the keys the one before left
	used   uint64     // guarded by d.mu
	quota  uint64     // 0 means none; guarded by d.mu
}

func ownerKey(p byte, owner []byte) []byte {
	return append([]byte{p}, owner...)
}

func newSpace(d *disk, owner []byte) (*space, error) {
	sp := &space{d: d, prefix: ownerKey(pData, owner), ukey: ownerKey(pUsage, owner)}
	v, err := d.db.Get(sp.ukey)
	if errors.Is(err, kolostore.ErrNotFound) {
		return sp, nil
	}
	if err != nil {
		return nil, err
	}
	n, k := binary.Uvarint(v)
	if k <= 0 || k != len(v) {
		return nil, kolostore.ErrCorrupt
	}
	sp.used = n
	return sp, nil
}

func (s *space) setQuota(q uint64) {
	s.d.mu.Lock()
	s.quota = q
	s.d.mu.Unlock()
}

func (s *space) usage() (used, quota uint64) {
	s.d.mu.Lock()
	defer s.d.mu.Unlock()
	return s.used, s.quota
}

func (s *space) key(k []byte) []byte {
	return append(bytes.Clone(s.prefix), k...)
}

func (s *space) Get(key []byte) ([]byte, error) { return s.d.db.Get(s.key(key)) }

func (s *space) Put(key, value []byte) error {
	b := s.NewBatch()
	b.Put(key, value)
	return b.Commit()
}

func (s *space) Delete(key []byte) error {
	b := s.NewBatch()
	b.Delete(key)
	return b.Commit()
}

func (s *space) Scan(start, end []byte, reverse bool, limit int, fn func(key, value []byte) bool) error {
	e := prefixEnd(s.prefix)
	if end != nil {
		e = s.key(end)
	}
	n := len(s.prefix)
	return s.d.db.Scan(s.key(start), e, reverse, limit, func(k, v []byte) bool { return fn(k[n:], v) })
}

func (s *space) NewBatch() kolostore.Batch { return &spaceBatch{s: s} }

// Close does nothing: the pinning peer closes the shared backend itself.
func (s *space) Close() error { return nil }

type spaceOp struct {
	del        bool
	key, value []byte // value is the range end for a DeleteRange
	rng        bool
}

type spaceBatch struct {
	s   *space
	ops []spaceOp
}

func (b *spaceBatch) Put(key, value []byte) {
	b.ops = append(b.ops, spaceOp{key: b.s.key(key), value: bytes.Clone(value)})
}

func (b *spaceBatch) Delete(key []byte) {
	b.ops = append(b.ops, spaceOp{del: true, key: b.s.key(key)})
}

func (b *spaceBatch) DeleteRange(start, end []byte) {
	b.ops = append(b.ops, spaceOp{del: true, rng: true, key: b.s.key(start), value: b.s.key(end)})
}

// Commit applies the writes and the owner's new byte count in one batch, unless the growth passes a limit. It holds
// the disk's lock only to check and update the counts, so a long delete blocks only the owner's own commits.
func (b *spaceBatch) Commit() error {
	s, d := b.s, b.s.d
	s.cm.Lock()
	defer s.cm.Unlock()
	delta, markers, err := b.measure()
	if err != nil {
		return err
	}
	d.mu.Lock()
	if delta > 0 {
		if s.quota > 0 && s.used+uint64(delta) > s.quota {
			d.mu.Unlock()
			return ErrQuotaExceeded
		}
		if d.used+uint64(delta) > d.max {
			d.mu.Unlock()
			return ErrDiskFull
		}
		d.used += uint64(delta) // reserved until the commit ends
	}
	used := uint64(int64(s.used) + delta)
	d.mu.Unlock()
	nb := d.db.NewBatch()
	for _, o := range b.ops {
		switch {
		case o.rng:
			nb.DeleteRange(o.key, o.value)
		case o.del:
			nb.Delete(o.key)
		default:
			nb.Put(o.key, o.value)
		}
	}
	nb.Put(s.ukey, binary.AppendUvarint(nil, used))
	err = nb.Commit()
	d.mu.Lock()
	switch {
	case err != nil && delta > 0:
		d.used -= uint64(delta)
	case err == nil:
		if delta < 0 {
			d.used -= uint64(-delta)
		}
		s.used = used
	}
	d.mu.Unlock()
	if err != nil {
		return err
	}
	d.markers.Add(float64(markers))
	return nil
}

// measure returns how many bytes the batch adds to the disk (negative when it frees) and how many delete markers it
// applies, reading what the keys hold now; s.cm is held.
func (b *spaceBatch) measure() (delta int64, markers int, err error) {
	s, d := b.s, b.s.d
	type value struct {
		v  []byte
		ok bool
	}
	pending := map[string]value{} // each key the batch writes, as the batch leaves it
	var ranges [][2][]byte        // the ranges the batch deletes
	inRange := func(k []byte) bool {
		for _, r := range ranges {
			if bytes.Compare(k, r[0]) >= 0 && bytes.Compare(k, r[1]) < 0 {
				return true
			}
		}
		return false
	}
	size := func(k []byte, v value) int64 {
		if !v.ok {
			return 0
		}
		return int64(len(k) + len(v.v))
	}
	for _, o := range b.ops {
		if o.rng {
			if err := d.db.Scan(o.key, o.value, false, 0, func(k, v []byte) bool {
				if _, ok := pending[string(k)]; !ok && !inRange(k) {
					delta -= int64(len(k) + len(v))
				}
				return true
			}); err != nil {
				return 0, 0, err
			}
			for k, v := range pending {
				if k >= string(o.key) && k < string(o.value) {
					delta -= size([]byte(k), v)
					pending[k] = value{}
				}
			}
			ranges = append(ranges, [2][]byte{o.key, o.value})
			continue
		}
		old, ok := pending[string(o.key)]
		if !ok && !inRange(o.key) {
			v, err := d.db.Get(o.key)
			if err != nil && !errors.Is(err, kolostore.ErrNotFound) {
				return 0, 0, err
			}
			old = value{v, err == nil}
		}
		next := value{o.value, !o.del}
		delta += size(o.key, next) - size(o.key, old)
		if markerApplied(o.key[len(s.prefix):], old.v, next.v) {
			markers++
		}
		pending[string(o.key)] = next
	}
	return delta, markers, nil
}

// kolo-store's entry layout (its layout package and README Formats): entry i of a log is stored under
// 0x01 ‖ log ID ‖ 'e' ‖ uint64be(i), with the value uvarint(3) ‖ bytes(record) ‖ bool(deleted) ‖ bytes(payload).
const (
	storeLogPrefix    = 0x01
	storeEntrySuffix  = 'e'
	storeEntryKeyLen  = 1 + kololog.LogIDSize + 1 + 8
	storeEntryVersion = 3
)

// markerApplied reports whether writing next over old under the kolo-store key k replaces a live entry with its delete marker.
func markerApplied(k, old, next []byte) bool {
	if len(k) != storeEntryKeyLen || k[0] != storeLogPrefix || k[1+kololog.LogIDSize] != storeEntrySuffix {
		return false
	}
	was, ok := entryDeleted(old)
	now, _ := entryDeleted(next) // false for a value it cannot read
	return ok && !was && now
}

// entryDeleted reads whether a kolo-store entry value holds a delete marker; ok is false for a value it cannot read.
func entryDeleted(v []byte) (deleted, ok bool) {
	d := kolocodec.NewDecoder(v)
	if ver, err := d.Uvarint(); err != nil || ver != storeEntryVersion {
		return false, false
	}
	if _, err := d.Bytes(d.Len()); err != nil {
		return false, false
	}
	deleted, err := d.Bool()
	return deleted, err == nil
}

// putMeta stores or, for a nil value, removes key outside any owner's quota, but within the disk's and the owner
// record limit.
func (d *disk) putMeta(key, value []byte) error {
	d.metaMu.Lock()
	defer d.metaMu.Unlock()
	var old int64
	v, err := d.db.Get(key)
	exists := err == nil
	switch {
	case exists:
		old = int64(len(key) + len(v))
	case !errors.Is(err, kolostore.ErrNotFound):
		return err
	}
	next := int64(0)
	if value != nil {
		next = int64(len(key) + len(value))
	}
	d.mu.Lock()
	switch {
	case next > old && d.used+uint64(next-old) > d.max:
		d.mu.Unlock()
		return ErrDiskFull
	case value != nil && !exists && d.maxRecords > 0 && d.records >= d.maxRecords:
		d.mu.Unlock()
		return ErrOwnerLimit
	}
	if next > old {
		d.used += uint64(next - old) // reserved until the write ends
	}
	d.mu.Unlock()
	if value == nil {
		err = d.db.Delete(key)
	} else {
		err = d.db.Put(key, value)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case err != nil && next > old:
		d.used -= uint64(next - old)
	case err == nil:
		if next < old {
			d.used -= uint64(old - next)
		}
		switch {
		case value != nil && !exists:
			d.records++
		case value == nil && exists:
			d.records--
		}
	}
	return err
}

// prefixEnd returns the first key after every key that starts with p.
func prefixEnd(p []byte) []byte {
	e := bytes.Clone(p)
	for i := len(e) - 1; i >= 0; i-- {
		if e[i] < 0xff {
			e[i]++
			return e[:i+1]
		}
	}
	return nil
}
