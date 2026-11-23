package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	"github.com/ciranda-dev/kolo-pin"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	"github.com/prometheus/common/expfmt"
)

// syncBuffer is a bytes.Buffer safe for the logger and the test at once.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func noEnv(string) string { return "" }

// started runs the binary and returns the address each named log event reports once all have appeared.
func started(t *testing.T, ctx context.Context, args []string, env map[string]string, events ...string) (map[string]string, *syncBuffer, chan int) {
	t.Helper()
	var stderr syncBuffer
	code := make(chan int, 1)
	go func() { code <- run(ctx, args, func(k string) string { return env[k] }, io.Discard, &stderr) }()
	addrs := map[string]string{}
	deadline := time.Now().Add(20 * time.Second)
	for len(addrs) < len(events) && time.Now().Before(deadline) {
		for line := range strings.SplitSeq(stderr.String(), "\n") {
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) != nil {
				continue
			}
			for _, e := range events {
				if m["msg"] == e {
					a, _ := m["addr"].(string)
					if e == "serving" {
						a, _ = m["key"].(string)
					}
					addrs[e] = a
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(addrs) < len(events) {
		t.Fatalf("events %v not all logged:\n%s", events, stderr.String())
	}
	return addrs, &stderr, code
}

func get(t *testing.T, url string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// The binary starts from flags and env, answers /healthz and /metrics on loopback, and stops cleanly.
func TestRunHealthMetricsAndShutdown(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	env := map[string]string{"KOLO_PIN_MAX_BYTES": "1GiB", "KOLO_PIN_LOG_FORMAT": "json", "KOLO_PIN_METRICS": "127.0.0.1:0"}
	programStart = time.Now().Add(-time.Hour) // as if the program had started an hour before the listener
	t.Cleanup(func() { programStart = time.Now() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addrs, stderr, code := started(t, ctx, []string{"run", "-data", dir, "-listen", "127.0.0.1:0", "-health", "127.0.0.1:0"},
		env, "health", "metrics", "serving")
	if c, body := get(t, "http://"+addrs["health"]+"/healthz"); c != 200 || string(body) != "ok\n" {
		t.Fatalf("/healthz = %d %q", c, body)
	}
	if !strings.HasPrefix(addrs["metrics"], "127.0.0.1:") {
		t.Fatalf("metrics on %s", addrs["metrics"])
	}
	c, body := get(t, "http://"+addrs["metrics"]+"/metrics")
	var p expfmt.TextParser
	fams, err := p.TextToMetricFamilies(bytes.NewReader(body))
	if c != 200 || err != nil {
		t.Fatalf("/metrics = %d, parse %v", c, err)
	}
	for _, name := range []string{"kolo_pin_build_info", "kolo_pin_uptime_seconds", "kolo_pin_requests_total", "kolo_pin_bytes_used", "go_goroutines"} {
		if fams[name] == nil {
			t.Errorf("metric %s missing", name)
		}
	}
	if v := fams["kolo_pin_uptime_seconds"].GetMetric()[0].GetGauge().GetValue(); v < 3600 {
		t.Errorf("kolo_pin_uptime_seconds %v, want it counted from the program start", v)
	}
	if v := fams["kolo_pin_bytes_max"].GetMetric()[0].GetGauge().GetValue(); v != 1<<30 {
		t.Errorf("kolo_pin_bytes_max %v", v)
	}
	key, _ := hex.DecodeString(addrs["serving"])
	if bytes.Contains(body, []byte(addrs["serving"])) || bytes.Contains(body, key) || bytes.Contains(body, []byte("127.0.0.1")) {
		t.Error("the metrics hold the peer key or an address")
	}
	cancel()
	select {
	case c := <-code:
		if c != 0 || !strings.Contains(stderr.String(), `"msg":"stopped"`) {
			t.Fatalf("exit %d; log:\n%s", c, stderr.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("run did not stop")
	}
	for _, a := range []string{addrs["health"], addrs["metrics"]} {
		if _, err := http.Get("http://" + a + "/"); err == nil {
			t.Fatalf("%s still answers after the stop", a)
		}
	}

	var out bytes.Buffer
	if c := run(context.Background(), []string{"id", "-data", dir}, noEnv, &out, io.Discard); c != 0 {
		t.Fatalf("id exit %d", c)
	}
	id, err := pin.LoadIdentity(dir)
	if err != nil || strings.TrimSpace(out.String()) != hex.EncodeToString(id.PublicKey()) {
		t.Fatalf("id printed %q, key %v", out.String(), err)
	}
}

// The endpoints default to loopback, and "off" opens no port.
func TestEndpointDefaultsAndOff(t *testing.T) {
	c, err := parse("run", []string{"-data", "x"}, noEnv, io.Discard)
	if err != nil || c.metrics != "127.0.0.1:7452" || c.health != "127.0.0.1:7451" || c.listen != "127.0.0.1:7450" {
		t.Fatalf("defaults %+v, %v", c, err)
	}
	// Hold the default ports, so a stray listener would fail the run and an "off" one must not touch them.
	var held []net.Listener
	for _, a := range []string{"127.0.0.1:7451", "127.0.0.1:7452"} {
		if l, err := net.Listen("tcp4", a); err == nil {
			held = append(held, l)
		}
	}
	defer func() {
		for _, l := range held {
			l.Close()
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := filepath.Join(t.TempDir(), "data")
	_, stderr, code := started(t, ctx, []string{"run", "-data", dir, "-listen", "127.0.0.1:0", "-health", "off", "-metrics", "off", "-log-format", "json"},
		nil, "serving")
	if s := stderr.String(); strings.Contains(s, `"msg":"metrics"`) || strings.Contains(s, `"msg":"health"`) {
		t.Fatalf("an endpoint started although off:\n%s", s)
	}
	cancel()
	if c := <-code; c != 0 {
		t.Fatalf("exit %d:\n%s", c, stderr.String())
	}
}

func TestRunRefusesBadConfig(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	base := []string{"run", "-data", dir, "-listen", "127.0.0.1:0", "-health", "off"}
	held, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	busy := held.Addr().String() // a valid address that cannot be bound
	heldUDP, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer heldUDP.Close()
	busyUDP := heldUDP.LocalAddr().String()
	for _, c := range []struct {
		args []string
		code int
		msg  string
	}{
		{nil, 2, "usage"},
		{[]string{"nope"}, 2, "unknown command"},
		{[]string{"run"}, 2, "-data is required"},
		{[]string{"run", "-data", dir, "extra"}, 2, "unexpected argument"},
		{[]string{"run", "-data", dir, "-listen", "[::1]:7450"}, 2, "IPv6"},
		{[]string{"run", "-data", dir, "-listen", "127.0.0.1:99999"}, 2, "-listen"},
		{[]string{"run", "-data", dir, "-listen", "999.1.1.1:7450"}, 2, "want an IPv4 address"},
		{append(base, "-metrics", "[::1]:7452"), 2, "IPv6"},
		{append(base, "-metrics", "nonsense"), 2, `-metrics "nonsense"`},
		{append(base, "-metrics", "999.1.1.1:7452"), 2, "want an IPv4 address"},
		{append(base, "-metrics", "localhost:7452"), 2, "want an IPv4 address"},
		{append(base, "-metrics", "127.0.0.1:99999"), 2, "want a port"},
		{append(base, "-metrics", "127.0.0.1:+80"), 2, "want a port"},
		{[]string{"run", "-data", dir, "-listen", "127.0.0.1:0", "-health", "999.1.1.1:7451"}, 2, "-health"},
		{append(base, "-metrics", busy), 1, "metrics listen failed"},
		{[]string{"run", "-data", dir, "-listen", busyUDP, "-health", "off", "-metrics", "off"}, 1, "listen failed"},
		{append(base, "-max-bytes", "0"), 2, "-max-bytes"},
		{append(base, "-max-bytes", "20000000TiB"), 2, "-max-bytes"},
		{append(base, "-owners", "abcd"), 2, "-owners"},
		{append(base, "-max-owners", "0"), 2, "-max-owners"},
		{append(base, "-max-owners", "-3"), 2, "-max-owners"},
		{append(base, "-max-conns", "2017"), 1, "MaxMemory"},
		{append(base, "-max-conns", "0"), 2, "-max-conns"},
		{append(base, "-max-open-bytes", "0"), 2, "-max-open-bytes"},
		{append(base, "-max-open-bytes", "x"), 2, "-max-open-bytes"},
		{append(base, "-max-conns", "x"), 2, "-max-conns"},
		{append(base, "-peer-bytes-per-second", "0"), 2, "-peer-bytes-per-second"},
		{append(base, "-peer-burst-bytes", "9223372036854775808"), 2, "-peer-burst-bytes"},
		{append(base, "-peer-burst-bytes", "1MiB"), 1, "peer byte budget"},
		{append(base, "-max-conns-per-ip", "0"), 2, "-max-conns-per-ip"},
		{append(base, "-add-timeout", "10"), 2, "-add-timeout"},
		{append(base, "-add-timeout", "-1m"), 2, "-add-timeout"},
		{append(base, "-max-conns", "2", "-max-conns-per-ip", "3"), 1, "listen failed"},
		{append(base, "-log-format", "xml"), 2, "log format"},
	} {
		var stderr bytes.Buffer
		if got := run(context.Background(), c.args, noEnv, io.Discard, &stderr); got != c.code || !strings.Contains(stderr.String(), c.msg) {
			t.Errorf("%q: exit %d, want %d with %q; stderr:\n%s", c.args, got, c.code, c.msg, stderr.String())
		}
	}
}

func TestParseBytes(t *testing.T) {
	for s, want := range map[string]uint64{"1": 1, "100GB": 100e9, "5MiB": 5 << 20, "7B": 7, "2TiB": 2 << 40} {
		if got, err := parseBytes("-max-bytes", s); err != nil || got != want {
			t.Errorf("parseBytes(%q) = %d, %v; want %d", s, got, err, want)
		}
	}
	for _, s := range []string{"", "-1", "GB", "1.5GB", "18446744073709551616", "abc"} {
		if _, err := parseBytes("-max-bytes", s); err == nil {
			t.Errorf("parseBytes(%q) accepted", s)
		}
	}
}

// serving returns the key and address of the "serving" event in the JSON log.
func serving(t *testing.T, stderr *syncBuffer) (key, addr string) {
	t.Helper()
	for line := range strings.SplitSeq(stderr.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["msg"] == "serving" {
			key, _ = m["key"].(string)
			addr, _ = m["addr"].(string)
		}
	}
	return key, addr
}

// Without -owners the binary logs an unmistakable warning at start; with it, none.
func TestOpenWarning(t *testing.T) {
	for _, owners := range []string{"", hex.EncodeToString(make([]byte, 32))} {
		ctx, cancel := context.WithCancel(context.Background())
		args := []string{"run", "-data", filepath.Join(t.TempDir(), "data"), "-listen", "127.0.0.1:0", "-health", "off", "-metrics", "off",
			"-log-format", "json"}
		if owners != "" {
			args = append(args, "-owners", owners)
		}
		// The warning follows the "serving" event.
		var stderr syncBuffer
		code := make(chan int, 1)
		go func() { code <- run(ctx, args, noEnv, io.Discard, &stderr) }()
		if owners != "" {
			for !strings.Contains(stderr.String(), `"msg":"serving"`) {
				select {
				case <-code:
					t.Fatalf("run ended:\n%s", stderr.String())
				case <-time.After(10 * time.Millisecond):
				}
			}
		}
		if owners == "" {
			for !strings.Contains(stderr.String(), "open peer") && ctx.Err() == nil {
				select {
				case <-code:
					t.Fatalf("run ended:\n%s", stderr.String())
				case <-time.After(10 * time.Millisecond):
				}
			}
			if !strings.Contains(stderr.String(), `"level":"WARN"`) || !strings.Contains(stderr.String(), "open peer: every owner key is accepted") {
				t.Errorf("no warning for an open peer:\n%s", stderr.String())
			}
			cancel()
			<-code
			continue
		}
		cancel()
		<-code
		if !strings.Contains(stderr.String(), `"msg":"serving"`) || strings.Contains(stderr.String(), "open peer") {
			t.Errorf("a warning with -owners, or no start:\n%s", stderr.String())
		}
	}
}

// -max-conns-per-ip limits the connections one address can hold.
func TestConnLimitFlags(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := filepath.Join(t.TempDir(), "data")
	_, stderr, code := started(t, ctx, []string{"run", "-data", dir, "-listen", "127.0.0.1:0", "-health", "off", "-metrics", "off",
		"-log-format", "json", "-max-conns", "5", "-max-conns-per-ip", "2", "-max-owners", "7", "-max-open-bytes", "64MiB", "-add-timeout", "10m",
		"-peer-bytes-per-second", "64MiB", "-peer-burst-bytes", "512MiB"}, nil, "serving")
	key, addr := serving(t, stderr)
	if !strings.Contains(stderr.String(), `"max-owners":7`) {
		t.Errorf("the serving event does not show -max-owners:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), `"max-open-bytes":67108864`) {
		t.Errorf("the serving event does not show -max-open-bytes:\n%s", stderr.String())
	}
	peer, _ := hex.DecodeString(key)
	var held []*kolosecure.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for i := range 3 {
		dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
		id, _ := koloid.Generate()
		c, err := kolosecure.Dial(dctx, addr, id, peer, nil)
		dcancel()
		switch {
		case i < 2 && err != nil:
			t.Fatalf("connection %d = %v", i, err)
		case i < 2:
			held = append(held, c)
		case err == nil:
			c.Close()
			t.Fatal("a third connection from one address was accepted with -max-conns-per-ip 2")
		}
	}
	cancel()
	if c := <-code; c != 0 {
		t.Fatalf("exit %d", c)
	}
}

// Without -max-conns the binary takes more than 100 connections: its default is the most kolo-transport's memory check allows.
func TestDefaultMaxConns(t *testing.T) {
	if defaultMaxConns != 2016 {
		t.Fatalf("defaultMaxConns = %d, want 2016", defaultMaxConns)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := filepath.Join(t.TempDir(), "data")
	_, stderr, code := started(t, ctx, []string{"run", "-data", dir, "-listen", "127.0.0.1:0", "-health", "off", "-metrics", "off",
		"-log-format", "json", "-max-conns-per-ip", "200"}, nil, "serving")
	key, addr := serving(t, stderr)
	peer, _ := hex.DecodeString(key)
	for i := range 101 {
		dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
		id, _ := koloid.Generate()
		c, err := kolosecure.Dial(dctx, addr, id, peer, nil)
		dcancel()
		if err != nil {
			t.Fatalf("connection %d = %v", i, err)
		}
		defer c.Close()
	}
	cancel()
	if c := <-code; c != 0 {
		t.Fatalf("exit %d", c)
	}
}

func TestParseCountAndTimeout(t *testing.T) {
	if n, err := parseCount("-x", "", 10); n != 0 || err != nil {
		t.Errorf("empty = %d, %v", n, err)
	}
	if n, err := parseCount("-x", "10", 10); n != 10 || err != nil {
		t.Errorf("10 = %d, %v", n, err)
	}
	for _, s := range []string{"0", "11", "-1", "1.5", "abc"} {
		if _, err := parseCount("-x", s, 10); err == nil {
			t.Errorf("parseCount(%q) accepted", s)
		}
	}
	if d, err := parseTimeout("90s"); d != 90*time.Second || err != nil {
		t.Errorf("90s = %v, %v", d, err)
	}
	for _, s := range []string{"0s", "-1m", "5", "x"} {
		if _, err := parseTimeout(s); err == nil {
			t.Errorf("parseTimeout(%q) accepted", s)
		}
	}
}
