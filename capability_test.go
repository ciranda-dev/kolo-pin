package pin

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kololog "github.com/ciranda-dev/kolo-log"
)

func seeded(t *testing.T, b byte) *koloid.Identity {
	t.Helper()
	id, err := koloid.FromSeed(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// vectors are the cases in testdata/capability-v0.txt: owner seed 32 × 0x01, pinning peer seed 32 × 0x02.
func vectors(t *testing.T) (owner *koloid.Identity, caps map[string]Capability, through time.Time) {
	owner, peer := seeded(t, 1), seeded(t, 2)
	var a, b kololog.LogID
	a[0], b[0] = 0xaa, 0xbb
	issued, expires := time.Unix(1767225600, 0), time.Unix(1798761600, 0)
	return owner, map[string]Capability{
		"all-logs":      {Owner: owner.PublicKey(), Peer: peer.PublicKey(), Issued: issued, Expires: expires},
		"two-logs":      {Owner: owner.PublicKey(), Peer: peer.PublicKey(), Logs: []kololog.LogID{a, b}, Issued: issued, Expires: expires, Quota: 1_000_000_000},
		"one-log-quota": {Owner: owner.PublicKey(), Peer: peer.PublicKey(), Logs: []kololog.LogID{b}, Issued: issued, Expires: expires, Quota: 1 << 20},
	}, time.Unix(1767312000, 0)
}

func readVectors(t testing.TB) map[string][]byte {
	t.Helper()
	f, err := os.Open("testdata/capability-v0.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string][]byte{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, h, ok := strings.Cut(line, " ")
		b, err := hex.DecodeString(h)
		if !ok || err != nil {
			t.Fatalf("bad vector line %q", line)
		}
		out[name] = b
	}
	return out
}

func TestCapabilityVectors(t *testing.T) {
	owner, caps, through := vectors(t)
	file := readVectors(t)
	for name, c := range caps {
		b, err := Issue(owner, c)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b, file[name]) {
			t.Errorf("%s: Issue = %x, vector %x", name, b, file[name])
		}
		got, err := ParseCapability(file[name])
		if err != nil || !reflect.DeepEqual(got, c) {
			t.Errorf("%s: ParseCapability = %+v, %v", name, got, err)
		}
	}
	note, err := IssueRevocation(owner, caps["all-logs"].Peer, through)
	if err != nil || !bytes.Equal(note, file["revoke"]) {
		t.Errorf("revoke: IssueRevocation = %x, %v; vector %x", note, err, file["revoke"])
	}
	r, err := ParseRevocation(file["revoke"])
	if err != nil || !r.Through.Equal(through) || !r.Owner.Equal(owner.PublicKey()) {
		t.Errorf("ParseRevocation = %+v, %v", r, err)
	}
}

func TestCapabilityRefused(t *testing.T) {
	owner, caps, _ := vectors(t)
	good, err := Issue(owner, caps["two-logs"])
	if err != nil {
		t.Fatal(err)
	}
	// A capability signed under the revoke context, or a revoke note under the capability one, does not verify.
	msg := good[:len(good)-64]
	otherCtx, _ := owner.Sign(RevokeContext, msg)
	unsorted := bytes.Clone(msg)
	copy(unsorted[len(unsorted)-64:], bytes.Repeat([]byte{0xbb}, 1))
	copy(unsorted[len(unsorted)-32:], bytes.Repeat([]byte{0xaa}, 1))
	unsortedSig, _ := owner.Sign(CapabilityContext, unsorted)
	cases := map[string][]byte{
		"empty":           nil,
		"short":           good[:10],
		"no signature":    msg,
		"flipped bit":     append(bytes.Clone(msg[:5]), append([]byte{msg[5] ^ 1}, good[6:]...)...),
		"other context":   append(bytes.Clone(msg), otherCtx...),
		"trailing byte":   append(bytes.Clone(good), 0),
		"unsorted logs":   append(unsorted, unsortedSig...),
		"version 1":       append([]byte{1}, good[1:]...),
		"over max size":   make([]byte, MaxCapabilitySize+1),
		"zero everything": make([]byte, 200),
	}
	for name, b := range cases {
		if _, err := ParseCapability(b); !errors.Is(err, ErrInvalidCapability) {
			t.Errorf("%s: ParseCapability = %v, want ErrInvalidCapability", name, err)
		}
	}
	if _, err := ParseRevocation(good); !errors.Is(err, ErrInvalidCapability) {
		t.Errorf("a capability parsed as a revoke note: %v", err)
	}
}

func TestIssueChecks(t *testing.T) {
	owner, caps, _ := vectors(t)
	c := caps["all-logs"]
	for name, bad := range map[string]Capability{
		"no peer":         {Expires: c.Expires},
		"peer is owner":   {Peer: owner.PublicKey(), Expires: c.Expires},
		"no expiry":       {Peer: c.Peer},
		"expiry first":    {Peer: c.Peer, Issued: c.Expires, Expires: c.Issued},
		"too many logs":   {Peer: c.Peer, Expires: c.Expires, Logs: make([]kololog.LogID, MaxLogs+1)},
		"before the 1970": {Peer: c.Peer, Issued: time.Unix(-5, 0), Expires: c.Expires},
	} {
		if _, err := Issue(owner, bad); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: Issue = %v, want ErrInvalidArgument", name, err)
		}
	}
	if _, err := Issue(nil, c); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("Issue(nil) = %v", err)
	}
	var a kololog.LogID
	b, err := Issue(owner, Capability{Peer: c.Peer, Expires: time.Now().Add(time.Hour), Logs: []kololog.LogID{a, a}})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParseCapability(b); err != nil || len(got.Logs) != 1 || got.Issued.IsZero() {
		t.Fatalf("Issue with a repeated log = %+v, %v", got, err)
	}
	full := make([]kololog.LogID, MaxLogs)
	for i := range full {
		full[i][0], full[i][1] = byte(i>>8), byte(i)
	}
	b, err = Issue(owner, Capability{Peer: c.Peer, Issued: time.Unix(maxTime-1, 0), Expires: time.Unix(maxTime, 0), Quota: ^uint64(0), Logs: full})
	if err != nil || len(b) > MaxCapabilitySize {
		t.Fatalf("largest capability: %d bytes, %v; MaxCapabilitySize %d", len(b), err, MaxCapabilitySize)
	}
	if len(request{typ: tAdd, data: b}.encode()) > MaxRequestSize {
		t.Fatal("an ADD with the largest capability is over MaxRequestSize")
	}
}
