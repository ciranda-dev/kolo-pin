package pin

import (
	"bytes"
	"crypto/ed25519"
	"slices"
	"testing"
	"time"

	kololog "github.com/ciranda-dev/kolo-log"
)

func FuzzParseCapability(f *testing.F) {
	for _, b := range readVectors(f) {
		f.Add(b)
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := ParseCapability(b)
		if err != nil {
			return
		}
		if again := append(c.signed(), b[len(b)-ed25519.SignatureSize:]...); !bytes.Equal(again, b) {
			t.Fatalf("a parsed capability encodes to other bytes")
		}
		if c.check() != nil {
			t.Fatalf("a parsed capability fails Issue's checks")
		}
	})
}

func FuzzParseRevocation(f *testing.F) {
	for _, b := range readVectors(f) {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := ParseRevocation(b)
		if err == nil && !bytes.Equal(append(r.signed(), b[len(b)-ed25519.SignatureSize:]...), b) {
			t.Fatalf("a parsed revoke note encodes to other bytes")
		}
	})
}

func FuzzDecodeRequest(f *testing.F) {
	var id kololog.LogID
	f.Add(request{typ: tAdd, logID: id, data: []byte("cap")}.encode())
	f.Add(request{typ: tStatus, logID: id}.encode())
	f.Add(request{typ: tRevoke, data: []byte("note")}.encode())
	f.Add(answer{code: codeOwnerLimit}.encode())
	f.Add(answer{info: &Info{Entries: 3, Used: 9, Expires: time.Unix(7, 0)}}.encode())
	f.Fuzz(func(t *testing.T, b []byte) {
		if r, err := decodeRequest(b); err == nil && !bytes.Equal(r.encode(), b) {
			t.Fatalf("a decoded request encodes to other bytes")
		}
		_, _ = decodeAnswer(b, true)
		_, _ = decodeAnswer(b, false)
	})
}

// FuzzSelect checks Select on random peer IDs: n peers or all, no repeats, heaviest first, and independent of order.
func FuzzSelect(f *testing.F) {
	f.Add(bytes.Repeat([]byte{7}, 32*5), []byte("abcab"), byte(2))
	f.Fuzz(func(t *testing.T, ids, groups []byte, n byte) {
		var peers []Peer
		for i := 0; i+32 <= len(ids) && len(peers) < 64; i += 32 {
			g := ""
			if len(groups) > 0 {
				g = string(groups[len(peers)%len(groups)] % 4)
			}
			peers = append(peers, Peer{ID: ids[i : i+32], Group: g})
		}
		var logID kololog.LogID
		copy(logID[:], ids)
		want := int(n%8) + 1
		sel := Select(peers, logID, want)
		if distinct := len(rank(peers, logID)); len(sel.Peers) != min(want, distinct) {
			t.Fatalf("selected %d of %d distinct peers, n %d", len(sel.Peers), distinct, want)
		}
		rev := slices.Clone(peers)
		slices.Reverse(rev)
		got := Select(rev, logID, want)
		if !slices.EqualFunc(got.Peers, sel.Peers, func(a, b Peer) bool { return a.ID.Equal(b.ID) && a.Group == b.Group }) || got.SharedGroups != sel.SharedGroups {
			t.Fatal("Select depends on the input order")
		}
		for i := 1; i < len(sel.Peers); i++ {
			if !heavier(logID, sel.Peers[i-1].ID, sel.Peers[i].ID) {
				t.Fatal("selection is not ordered heaviest first")
			}
		}
	})
}

// FuzzMarkerApplied reads any key and values without panicking, and finds a marker only where both values read.
func FuzzMarkerApplied(f *testing.F) {
	k := append(append([]byte{storeLogPrefix}, make([]byte, kololog.LogIDSize)...), storeEntrySuffix, 0, 0, 0, 0, 0, 0, 0, 1)
	f.Add(k, []byte{storeEntryVersion, 1, 'r', 0, 1, 'c'}, []byte{storeEntryVersion, 1, 'r', 1, 1, 'm'})
	f.Add(k, []byte{storeEntryVersion, 0xff, 0xff, 0x03}, []byte{storeEntryVersion, 1, 'r', 2})
	f.Add([]byte{}, []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, k, old, next []byte) {
		if !markerApplied(k, old, next) {
			return
		}
		was, ok1 := entryDeleted(old)
		now, ok2 := entryDeleted(next)
		if !ok1 || !ok2 || was || !now || len(k) != storeEntryKeyLen {
			t.Fatalf("marker found for key %x, old %x, next %x", k, old, next)
		}
	})
}
