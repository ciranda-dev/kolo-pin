package pin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	koloid "github.com/ciranda-dev/kolo-id"
	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolostore "github.com/ciranda-dev/kolo-store"
	kolosync "github.com/ciranda-dev/kolo-sync"
)

// tampered serves a log but changes what it returns for entries from index on.
type tampered struct {
	kolosync.Source
	index uint64
	entry func(kololog.Entry) (kololog.Entry, error)
}

func (s tampered) Entry(i uint64) (kololog.Entry, error) {
	e, err := s.Source.Entry(i)
	if err != nil || i < s.index {
		return e, err
	}
	return s.entry(e)
}

// A peer serving forged or truncated entries is refused, and the pinning peer keeps only what verified.
func TestForgedAndTruncatedEntries(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	for _, c := range []struct {
		name  string
		entry func(kololog.Entry) (kololog.Entry, error)
		want  error
	}{
		{"flipped ciphertext", func(e kololog.Entry) (kololog.Entry, error) { e.Ciphertext[5] ^= 1; return e, nil }, ErrInvalid},
		{"truncated ciphertext", func(e kololog.Entry) (kololog.Entry, error) { e.Ciphertext = e.Ciphertext[:7]; return e, nil }, ErrInvalid},
		{"forged record", func(e kololog.Entry) (kololog.Entry, error) { e.Record[len(e.Record)-1] ^= 1; return e, nil }, ErrInvalid},
		{"forged marker", func(e kololog.Entry) (kololog.Entry, error) {
			e.Marker, e.Ciphertext = bytes.Repeat([]byte{1}, 200), nil
			return e, nil
		}, ErrInvalid},
		{"truncated log", func(kololog.Entry) (kololog.Entry, error) { return kololog.Entry{}, io.ErrUnexpectedEOF }, ErrBusy},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := startPin(t, Options{})
			alice := newOwner(t)
			l := alice.log(t, "good")
			capb := alice.issue(t, p.Peer, Capability{})
			if _, err := Add(ctx, alice.id, p.Peer, l, capb); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				if _, err := l.Append([]byte("more")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Add(ctx, alice.id, p.Peer, tampered{l, 2, c.entry}, capb); !errors.Is(err, c.want) {
				t.Fatalf("Add = %v, want %v", err, c.want)
			}
			in, err := Status(ctx, alice.id, p.Peer, l.ID())
			if err != nil || in.Entries != 1 {
				t.Fatalf("Status = %+v, %v; want the one verified entry", in, err)
			}
			rep, err := pullFrom(t, ctx, p.Peer, alice.id.PublicKey(), l.ID())
			if err != nil {
				t.Fatal(err)
			}
			mustEqualEntries(t, l, rep, 1)
			if _, err := Add(ctx, alice.id, p.Peer, l, capb); err != nil {
				t.Fatalf("Add from the honest log after the refusal = %v", err)
			}
		})
	}
}

// largestEntry is the largest entry value that syncs: kolo-log pads a frame (a uvarint length and the value) to a
// multiple of 64 KiB at this size, and the 4 MiB kolo-sync message also holds the record and framing, so the
// largest frame that fits is 4 MiB - 64 KiB, and its 4-byte length leaves 4,128,764 bytes for the value.
const largestEntry = kolosync.MaxMessageSize - 64<<10 - 4

// The largest entry syncs; one byte more is refused with ErrTooLarge.
func TestLargestEntry(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	alice := newOwner(t)
	l := alice.log(t, string(make([]byte, largestEntry)))
	c := alice.issue(t, p.Peer, Capability{})
	if in, err := Add(ctx, alice.id, p.Peer, l, c); err != nil || in.Entries != 1 {
		t.Fatalf("Add of a %d-byte entry = %+v, %v", largestEntry, in, err)
	}
	if _, err := l.Append(make([]byte, largestEntry+1)); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, alice.id, p.Peer, l, c); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Add of a %d-byte entry = %v, want ErrTooLarge", largestEntry+1, err)
	}
	if in, err := Status(ctx, alice.id, p.Peer, l.ID()); err != nil || in.Entries != 1 {
		t.Fatalf("Status = %+v, %v; want the first entry kept", in, err)
	}
}

// rawCall sends b as one request on conn and returns the error the answer carries.
func rawCall(t *testing.T, conn *kolosecure.Conn, b []byte) error {
	t.Helper()
	ctx := testCtx(t)
	ss, err := conn.OpenUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = ss.Write(b)
		_ = ss.Close()
	}()
	rs, err := conn.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a, err := readAll(rs, maxAnswerSize)
	if err != nil {
		t.Fatal(err)
	}
	_, err = decodeAnswer(a, false)
	return err
}

func heapGrowth(t *testing.T, fn func()) uint64 {
	t.Helper()
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	fn()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

// Malformed, oversized and hostile requests are refused cleanly, without large allocations.
func TestHostilePeer(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	alice := newOwner(t)
	capb := alice.issue(t, p.Peer, Capability{})
	dial := func() *kolosecure.Conn {
		c, err := kolosecure.Dial(ctx, p.Addr, alice.id, p.ID, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	logID := alice.log(t, "x").ID()
	for _, c := range []struct {
		name string
		req  []byte
		want error
	}{
		{"garbage", []byte{0xff, 0xff, 0xff}, ErrProtocol},
		{"version 1", []byte{1, tStatus}, ErrProtocol},
		{"unknown type", []byte{0, 9}, ErrProtocol},
		{"short log ID", []byte{0, tStatus, 1, 2, 3}, ErrProtocol},
		{"trailing bytes", append(request{typ: tStatus, logID: logID}.encode(), 0), ErrProtocol},
		{"capability length past the request", append(request{typ: tAdd, logID: logID}.encode()[:34], 0xff, 0x7f), ErrProtocol},
		{"huge request", make([]byte, 64<<20), ErrTooLarge},
	} {
		if g := heapGrowth(t, func() {
			conn := dial()
			defer conn.Close()
			if err := rawCall(t, conn, c.req); !errors.Is(err, c.want) {
				t.Errorf("%s: answer %v, want %v", c.name, err, c.want)
			}
		}); g > 40<<20 {
			t.Errorf("%s: %d bytes allocated", c.name, g)
		}
	}

	// A peer that answers the pinning peer's pull with a 1 GiB length prefix.
	conn := dial()
	go func() {
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		_, _ = st.Read(make([]byte, 64))
		var h [4]byte
		binary.LittleEndian.PutUint32(h[:], 1<<30)
		_, _ = st.Write(h[:])
		_, _ = st.Write(make([]byte, 1<<20))
		_ = st.Close()
	}()
	if g := heapGrowth(t, func() {
		if err := rawCall(t, conn, request{typ: tAdd, logID: logID, data: capb}.encode()); !errors.Is(err, ErrTooLarge) {
			t.Errorf("1 GiB frame: answer %v, want ErrTooLarge", err)
		}
	}); g > 64<<20 {
		t.Errorf("1 GiB frame: %d bytes allocated", g)
	}
	if _, err := Status(ctx, alice.id, p.Peer, logID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Status after the hostile Add = %v, want ErrNotFound", err)
	}
}

// The pinning peer's whole store holds no plaintext, no entry key and no owner seed.
func TestNoPlaintextOrKeysStored(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	p := startPin(t, Options{})
	seed := make([]byte, ed25519.SeedSize)
	_, _ = rand.Read(seed)
	id, err := koloid.FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	alice := &ownerNode{id: id, st: kolostore.New(kolostore.NewMemory())}
	defer alice.st.Close()
	var plain []string
	for i := range 20 {
		plain = append(plain, fmt.Sprintf("plaintext marker %02d, which must never reach the pinning peer", i))
	}
	l := alice.log(t, plain...)
	if err := l.Delete(3); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, alice.id, p.Peer, l, alice.issue(t, p.Peer, Capability{})); err != nil {
		t.Fatal(err)
	}
	secrets := [][]byte{seed, ed25519.NewKeyFromSeed(seed)}
	for i := range l.Len() {
		e, err := l.Entry(i)
		if err != nil {
			t.Fatal(err)
		}
		if e.Key != nil {
			secrets = append(secrets, e.Key)
		}
	}
	if len(secrets) != 2+19 {
		t.Fatalf("%d secrets, want 21", len(secrets))
	}
	for _, v := range plain {
		secrets = append(secrets, []byte(v), []byte(v[:16]))
	}

	dump := p.dump(t)
	if len(dump) < 20*64 {
		t.Fatalf("dump of %d bytes is too small to hold the log", len(dump))
	}
	e, _ := l.Entry(0)
	if !bytes.Contains(dump, e.Ciphertext) {
		t.Fatal("the dump does not hold the ciphertext, so the scan is wrong")
	}
	p.stop(t)
	var files []byte
	err = filepath.WalkDir(p.dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() == "identity.key" {
			return err
		}
		b, err := os.ReadFile(path)
		files = append(files, b...)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range secrets {
		if bytes.Contains(dump, s) || bytes.Contains(files, s) {
			t.Errorf("secret %d found in the pinning peer's store", i)
		}
	}
}
