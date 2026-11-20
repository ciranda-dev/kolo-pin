package pin

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolosync "github.com/ciranda-dev/kolo-sync"
)

// TestCrashChild is the pinning peer process that TestCrashMidSync kills.
func TestCrashChild(t *testing.T) {
	dir := os.Getenv("KOLO_PIN_CHILD_DIR")
	if dir == "" {
		t.Skip("run by TestCrashMidSync")
	}
	id, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := kolosecure.Listen(context.Background(), "127.0.0.1:0", id, nil)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("PIN %s %s\n", ln.Addr(), hex.EncodeToString(id.PublicKey()))
	t.Fatal(Serve(context.Background(), ln, Options{Dir: dir}))
}

func startChild(t *testing.T, dir string) (*exec.Cmd, Peer) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), "KOLO_PIN_CHILD_DIR="+dir)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) == 3 && f[0] == "PIN" {
			key, err := hex.DecodeString(f[2])
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				for sc.Scan() {
				}
			}()
			return cmd, Peer{ID: key, Addr: f[1]}
		}
	}
	t.Fatal("child did not start")
	return nil, Peer{}
}

// signal serves a log and closes reached when the pinning peer reads entry index.
type signal struct {
	kolosync.Source
	index   uint64
	once    sync.Once
	reached chan struct{}
}

func (s *signal) Entry(i uint64) (kololog.Entry, error) {
	if i == s.index {
		s.once.Do(func() { close(s.reached) })
	}
	return s.Source.Entry(i)
}

// The pinning peer process is killed in the middle of a sync; after a restart its store opens, keeps its key,
// and the next Add completes a log that a second device pulls and verifies.
func TestCrashMidSync(t *testing.T) {
	ctx := testCtx(t)
	dir := privateDir(t)
	cmd, p := startChild(t, dir)
	alice := newOwner(t)
	var values []string
	for i := range 24 {
		values = append(values, fmt.Sprintf("%d%s", i, make([]byte, 512<<10)))
	}
	l := alice.log(t, values...)
	capb := alice.issue(t, p, Capability{})
	src := &signal{Source: l, index: 12, reached: make(chan struct{})}
	done := make(chan error, 1)
	actx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		_, err := Add(actx, alice.id, p, src, capb)
		done <- err
	}()
	select {
	case <-src.reached:
	case err := <-done:
		t.Fatalf("Add ended before the kill: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	cancel() // the dead peer sends nothing, so stop waiting for the idle timeout
	if err := <-done; err == nil {
		t.Fatal("Add succeeded although the pinning peer was killed")
	}

	_, p2 := startChild(t, dir)
	if !p2.ID.Equal(p.ID) {
		t.Fatal("the pinning peer's key changed across the restart")
	}
	in, err := Status(ctx, alice.id, p2, l.ID())
	if err != nil && !errors.Is(err, ErrNotFound) {
		t.Fatalf("Status after the crash = %v", err)
	}
	if in.Entries >= 24 {
		t.Fatalf("the killed sync held %d entries", in.Entries)
	}
	if in, err = Add(ctx, alice.id, p2, l, capb); err != nil || in.Entries != 24 {
		t.Fatalf("Add after the restart = %+v, %v", in, err)
	}
	rep, err := pullFrom(t, ctx, p2, alice.id.PublicKey(), l.ID())
	if err != nil {
		t.Fatal(err)
	}
	mustEqualEntries(t, l, rep, 24)
}
