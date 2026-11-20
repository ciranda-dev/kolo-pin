package pin

import (
	"bytes"
	"errors"
	"testing"

	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolosync "github.com/ciranda-dev/kolo-sync"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

// syncReplica gives rep the entries of l it lacks, without their keys, as a pull with Ciphertext access does.
func syncReplica(t *testing.T, rep *kolostore.Replica, l *kolostore.Log) {
	t.Helper()
	h, err := l.Head()
	if err != nil {
		t.Fatal(err)
	}
	p, err := l.ConsistencyProof(rep.Len(), h.Size)
	if err != nil {
		t.Fatal(err)
	}
	var entries []kololog.Entry
	for i := rep.Len(); i < h.Size; i++ {
		e, err := l.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		e.Key = nil
		entries = append(entries, e)
	}
	if err := rep.Update(h, p, entries); err != nil {
		t.Fatal(err)
	}
}

func markersOf(t *testing.T, l *kolostore.Log, indexes ...uint64) [][]byte {
	t.Helper()
	var out [][]byte
	for _, i := range indexes {
		e, err := l.Entry(i)
		if err != nil || e.Marker == nil {
			t.Fatalf("entry %d has no marker: %v", i, err)
		}
		out = append(out, e.Marker)
	}
	return out
}

// The marker counter counts each live entry a write replaces with its delete marker, whether one ApplyDelete
// carries one marker or many, and nothing for skipped markers or for entries that arrive already deleted.
func TestSpaceCountsMarkers(t *testing.T) {
	markers := prometheus.NewCounter(prometheus.CounterOpts{Name: "markers"})
	d := &disk{db: kolostore.NewMemory(), max: 1 << 30, markers: markers}
	defer d.db.Close()
	alice := newOwner(t)
	sp, err := newSpace(d, alice.id.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	st := kolostore.New(sp)
	defer st.Close()
	l := alice.log(t, "0", "1", "2", "3", "4", "5", "6")
	if err := l.Delete(6); err != nil {
		t.Fatal(err)
	}
	rep, err := st.OpenReplica(alice.id.PublicKey(), l.ID(), l.Header().Encode())
	if err != nil {
		t.Fatal(err)
	}
	syncReplica(t, rep, l)
	check := func(step string, want float64) {
		t.Helper()
		if got := counterValue(t, markers); got != want {
			t.Fatalf("%s: %v markers counted, want %v", step, got, want)
		}
		var n int
		if err := d.db.Scan(nil, nil, false, 0, func(k, v []byte) bool {
			if k[0] == pData {
				n += len(k) + len(v)
			}
			return true
		}); err != nil {
			t.Fatal(err)
		}
		if used, _ := sp.usage(); used != uint64(n) || d.used != uint64(n) {
			t.Fatalf("%s: owner used %d, disk used %d, stored %d", step, used, d.used, n)
		}
	}
	check("entry 6 arrived deleted", 0)

	if err := l.Delete(1); err != nil {
		t.Fatal(err)
	}
	if err := rep.ApplyDelete(markersOf(t, l, 1)...); err != nil {
		t.Fatal(err)
	}
	check("one marker", 1)

	if err := l.Delete(0, 2, 4); err != nil {
		t.Fatal(err)
	}
	if err := rep.ApplyDelete(markersOf(t, l, 0, 2, 4, 1, 6, 2)...); err != nil {
		t.Fatal(err)
	}
	check("three new markers among skipped ones", 4)

	if err := rep.ApplyDelete(markersOf(t, l, 0, 1, 2, 4, 6)...); err != nil {
		t.Fatal(err)
	}
	check("markers already applied", 4)

	if _, err := l.Append([]byte("7")); err != nil {
		t.Fatal(err)
	}
	syncReplica(t, rep, l)
	check("an update", 4)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := rep.Close(); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(l.ID()); err != nil {
		t.Fatal(err)
	}
	check("log deleted", 4)
	if used, _ := sp.usage(); used != 0 {
		t.Fatalf("owner used %d after the delete, want 0", used)
	}
}

// markerApplied follows kolo-store's entry layout: it finds every entry key and reads its state, so a change
// of that layout fails here before it miscounts.
func TestStoreEntryLayout(t *testing.T) {
	db := kolostore.NewMemory()
	st := kolostore.New(db)
	defer st.Close()
	l, err := st.Create(generate(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"", "a", string(make([]byte, 70<<10))} {
		if _, err := l.Append([]byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	values := func() map[string][]byte {
		out := map[string][]byte{}
		if err := db.Scan(nil, nil, false, 0, func(k, v []byte) bool { out[string(k)] = v; return true }); err != nil {
			t.Fatal(err)
		}
		return out
	}
	before := values()
	if err := l.Delete(0, 2); err != nil {
		t.Fatal(err)
	}
	after := values()
	applied := 0
	for k, next := range after {
		if markerApplied([]byte(k), before[k], next) {
			applied++
		}
	}
	if applied != 2 {
		t.Fatalf("%d markers found, want 2", applied)
	}
	live := 0
	for k, v := range after {
		if d, ok := entryDeleted(v); ok && !d && len(k) == storeEntryKeyLen {
			live++
		}
	}
	if live != 1 {
		t.Fatalf("%d live entries read, want 1", live)
	}
	for _, c := range []struct {
		k, old, next []byte
	}{
		{nil, nil, nil},
		{make([]byte, storeEntryKeyLen), before[firstEntryKey(t, before)], after[firstEntryKey(t, before)]},
		{append([]byte(firstEntryKey(t, before)), 0), before[firstEntryKey(t, before)], after[firstEntryKey(t, before)]},
		{append([]byte{0x02}, firstEntryKey(t, before)[1:]...), before[firstEntryKey(t, before)], after[firstEntryKey(t, before)]},
		{append([]byte(firstEntryKey(t, before)[:1+kololog.LogIDSize]), append([]byte{'k'}, firstEntryKey(t, before)[2+kololog.LogIDSize:]...)...),
			before[firstEntryKey(t, before)], after[firstEntryKey(t, before)]},
		{[]byte(firstEntryKey(t, before)), []byte{storeEntryVersion}, after[firstEntryKey(t, before)]},
		{[]byte(firstEntryKey(t, before)), before[firstEntryKey(t, before)], []byte{4, 0, 1, 1, 'm'}},
		{[]byte(firstEntryKey(t, before)), before[firstEntryKey(t, before)], []byte{storeEntryVersion, 0, 2}},
		{[]byte(firstEntryKey(t, before)), after[firstEntryKey(t, before)], after[firstEntryKey(t, before)]},
		{[]byte(firstEntryKey(t, before)), []byte{storeEntryVersion, 1, 'r', 2, 1, 'c'}, after[firstEntryKey(t, before)]},
	} {
		if markerApplied(c.k, c.old, c.next) {
			t.Errorf("markerApplied(%x, %x, %x) is true", c.k, c.old, c.next)
		}
	}
}

func firstEntryKey(t *testing.T, values map[string][]byte) string {
	t.Helper()
	first := ""
	for k := range values {
		if len(k) == storeEntryKeyLen && k[1+kololog.LogIDSize] == storeEntrySuffix && (first == "" || k < first) {
			first = k
		}
	}
	if first == "" {
		t.Fatal("no entry key")
	}
	return first
}

// A quota of exactly the bytes a log takes holds it; one byte less refuses it.
func TestQuotaExact(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	alice := newOwner(t)
	l := alice.log(t, "one", string(make([]byte, 5000)), "three")
	if err := l.Delete(1); err != nil {
		t.Fatal(err)
	}
	add := func(quota uint64) (Info, error) {
		p := startPin(t, Options{})
		defer p.stop(t)
		return Add(ctx, alice.id, p.Peer, l, alice.issue(t, p.Peer, Capability{Quota: quota}))
	}
	in, err := add(0)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := add(in.Used); err != nil || got.Used != in.Used {
		t.Fatalf("Add with a quota of %d = %+v, %v", in.Used, got, err)
	}
	if _, err := add(in.Used - 1); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("Add with a quota of %d = %v, want ErrQuotaExceeded", in.Used-1, err)
	}
}

// A pinning peer serves Fetch, and neither Fetch nor a pull that asks for keys gets one from it.
func TestFetchFromPinningPeer(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	alice := newOwner(t)
	l := alice.log(t, "zero", "one", "two", "three")
	if err := l.Delete(2); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, alice.id, p.Peer, l, alice.issue(t, p.Peer, Capability{})); err != nil {
		t.Fatal(err)
	}
	conn, err := kolosecure.Dial(ctx, p.Addr, generate(t), p.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	h, err := kolosync.FetchHead(ctx, conn, alice.id.PublicKey(), l.ID())
	if err != nil {
		t.Fatal(err)
	}
	got, err := kolosync.Fetch(ctx, conn, h, 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("Fetch returned %d entries, want 4", len(got))
	}
	for i, f := range got {
		want := kololog.ErrKeyUnavailable
		if i == 2 {
			want = kololog.ErrDeleted
		}
		if f.Index != uint64(i) || f.Data != nil || !errors.Is(f.Err, want) {
			t.Fatalf("entry %d: index %d, data %q, err %v; want %v", i, f.Index, f.Data, f.Err, want)
		}
	}

	rep, err := pullFrom(t, ctx, p.Peer, alice.id.PublicKey(), l.ID())
	if err != nil {
		t.Fatal(err)
	}
	for i := range rep.Len() {
		info, err := rep.EntryInfo(i)
		if err != nil || info.Keyed || info.Deleted != (i == 2) {
			t.Fatalf("entry %d pulled from the pinning peer: %+v, %v", i, info, err)
		}
	}
	h2 := &hosted{}
	if k, err := h2.Key(0); k != nil || !errors.Is(err, kololog.ErrKeyUnavailable) {
		t.Fatalf("hosted.Key = %x, %v", k, err)
	}
}

// storedKeys returns how many kolo-store entry key values sit under the pinning peer's data prefix.
func storedKeys(t *testing.T, p *pinPeer) int {
	t.Helper()
	n := 0
	p.raw(t, func(db kolostore.Backend) {
		if err := db.Scan([]byte{pData}, []byte{pData + 1}, false, 0, func(k, _ []byte) bool {
			rel := k[1+32:]
			if len(rel) == storeEntryKeyLen && rel[0] == storeLogPrefix && rel[1+kololog.LogIDSize] == 'k' {
				n++
			}
			return true
		}); err != nil {
			t.Fatal(err)
		}
	})
	return n
}

// keyKeys returns how many entry keys a kolo-store backend holds, the same way storedKeys looks for them.
func keyKeys(t *testing.T, db kolostore.Backend) int {
	t.Helper()
	n := 0
	if err := db.Scan(nil, nil, false, 0, func(k, _ []byte) bool {
		if len(k) == storeEntryKeyLen && k[0] == storeLogPrefix && k[1+kololog.LogIDSize] == 'k' {
			n++
		}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestNoKeyStored(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	db := kolostore.NewMemory()
	alice := &ownerNode{id: generate(t), st: kolostore.New(db)}
	defer alice.st.Close()
	l := alice.log(t, "a", "b", "c")
	if n := keyKeys(t, db); n != 3 {
		t.Fatalf("the owner's store holds %d keys, want 3, so the search is wrong", n)
	}
	if _, err := Add(ctx, alice.id, p.Peer, l, alice.issue(t, p.Peer, Capability{})); err != nil {
		t.Fatal(err)
	}
	if n := storedKeys(t, p); n != 0 {
		t.Fatalf("the pinning peer stores %d entry keys", n)
	}
	id := l.ID()
	if !bytes.Contains(p.dump(t), id[:]) {
		t.Fatal("the dump does not hold the log")
	}
}

// The byte count stays exact when one batch mixes writes with overlapping deleted ranges.
func TestSpaceBatchAccounting(t *testing.T) {
	d := &disk{db: kolostore.NewMemory(), max: 1 << 30, markers: prometheus.NewCounter(prometheus.CounterOpts{Name: "m"})}
	defer d.db.Close()
	sp, err := newSpace(d, generate(t).PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	k := func(i byte) []byte { return []byte{'k', i} }
	check := func(step string) {
		t.Helper()
		n := 0
		if err := sp.Scan(nil, nil, false, 0, func(k, v []byte) bool { n += len(sp.prefix) + len(k) + len(v); return true }); err != nil {
			t.Fatal(err)
		}
		if used, _ := sp.usage(); used != uint64(n) || d.used != uint64(n) {
			t.Fatalf("%s: owner used %d, disk used %d, stored %d", step, used, d.used, n)
		}
	}
	b := sp.NewBatch()
	for i := byte(1); i <= 5; i++ {
		b.Put(k(i), bytes.Repeat([]byte{i}, int(i)*10))
	}
	if err := b.Commit(); err != nil {
		t.Fatal(err)
	}
	check("puts")

	b = sp.NewBatch()
	b.Put(k(0), []byte("zero, below every range"))
	b.Put(k(9), []byte("nine, above every range"))
	b.Put(k(1), []byte("new value of one"))
	b.Put(k(6), []byte("six, new"))
	b.Put(k(7), []byte("seven, new"))
	b.Put(k(7), []byte("seven, written twice in one batch"))
	b.DeleteRange(k(1), k(4))
	b.Put(k(5), []byte("five again, past the range"))
	b.Put(k(2), []byte("two again"))
	b.DeleteRange(k(2), k(7))
	b.Put(k(3), []byte("three again"))
	b.Put(k(6), []byte("six again"))
	b.Delete(k(8))
	if err := b.Commit(); err != nil {
		t.Fatal(err)
	}
	check("mixed batch")

	b = sp.NewBatch()
	b.DeleteRange(k(0), k(10))
	if err := b.Commit(); err != nil {
		t.Fatal(err)
	}
	check("all deleted")
	if used, _ := sp.usage(); used != 0 {
		t.Fatalf("used %d after deleting everything", used)
	}
}
