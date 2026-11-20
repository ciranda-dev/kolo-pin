package pin

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	kololog "github.com/ciranda-dev/kolo-log"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolosync "github.com/ciranda-dev/kolo-sync"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

// scrape fetches url and parses it with the official text parser.
func scrape(t *testing.T, url string) (map[string]*dto.MetricFamily, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var p expfmt.TextParser
	fams, err := p.TextToMetricFamilies(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("metrics do not parse: %v\n%s", err, body)
	}
	return fams, body
}

// value returns the value of the metric name with the label pair, if given; a histogram gives its count.
func value(t *testing.T, fams map[string]*dto.MetricFamily, name string, label ...string) float64 {
	t.Helper()
	f := fams[name]
	if f == nil {
		t.Fatalf("metric %s missing", name)
	}
	for _, m := range f.Metric {
		if len(label) == 2 && !hasLabel(m, label[0], label[1]) {
			continue
		}
		switch {
		case m.Counter != nil:
			return m.Counter.GetValue()
		case m.Gauge != nil:
			return m.Gauge.GetValue()
		case m.Histogram != nil:
			return float64(m.Histogram.GetSampleCount())
		}
	}
	t.Fatalf("metric %s %v missing", name, label)
	return 0
}

func hasLabel(m *dto.Metric, name, v string) bool {
	for _, l := range m.Label {
		if l.GetName() == name && l.GetValue() == v {
			return true
		}
	}
	return false
}

func TestMetrics(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	reg := prometheus.NewRegistry()
	p := startPin(t, Options{Metrics: reg, MaxBytes: 1 << 30})
	hs := httptest.NewServer(promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	defer hs.Close()
	if !strings.HasPrefix(hs.URL, "http://127.0.0.1:") {
		t.Fatalf("test server on %s", hs.URL)
	}
	url := hs.URL + "/metrics"
	prev, _ := scrape(t, url)
	for name, typ := range map[string]dto.MetricType{
		"kolo_pin_requests_total": dto.MetricType_COUNTER, "kolo_pin_refused_total": dto.MetricType_COUNTER,
		"kolo_pin_delete_markers_applied_total": dto.MetricType_COUNTER, "kolo_pin_bytes_received_total": dto.MetricType_COUNTER,
		"kolo_pin_bytes_served_total": dto.MetricType_COUNTER, "kolo_pin_bytes_used": dto.MetricType_GAUGE,
		"kolo_pin_bytes_max": dto.MetricType_GAUGE, "kolo_pin_disk_free_bytes": dto.MetricType_GAUGE,
		"kolo_pin_owners": dto.MetricType_GAUGE, "kolo_pin_logs": dto.MetricType_GAUGE, "kolo_pin_entries": dto.MetricType_GAUGE,
		"kolo_pin_active_connections": dto.MetricType_GAUGE, "kolo_pin_active_sync_streams": dto.MetricType_GAUGE,
		"kolo_pin_active_pulls":               dto.MetricType_GAUGE,
		"kolo_pin_sync_pull_duration_seconds": dto.MetricType_HISTOGRAM, "kolo_pin_request_duration_seconds": dto.MetricType_HISTOGRAM,
	} {
		if f := prev[name]; f == nil || f.GetType() != typ {
			t.Errorf("%s: %v, want type %v", name, f, typ)
		}
	}
	for _, r := range refuseReasons {
		// The helper's readiness check is one refused Status.
		if want := map[bool]float64{true: 1}[r == "other"]; value(t, prev, "kolo_pin_refused_total", "reason", r) != want {
			t.Errorf("refused %s at start is not %v", r, want)
		}
	}
	if value(t, prev, "kolo_pin_bytes_max") != 1<<30 || value(t, prev, "kolo_pin_disk_free_bytes") <= 0 {
		t.Fatal("bytes_max or disk_free_bytes wrong")
	}

	// step runs fn and checks that each listed counter grew by exactly its amount.
	step := func(name string, fn func(), want map[[3]string]float64) {
		t.Helper()
		fn()
		now, _ := scrape(t, url)
		for k, d := range want {
			var label []string
			if k[1] != "" {
				label = []string{k[1], k[2]}
			}
			if got := value(t, now, k[0], label...) - value(t, prev, k[0], label...); got != d {
				t.Errorf("%s: %s %v changed by %v, want %v", name, k[0], label, got, d)
			}
		}
		prev = now
	}
	add := func(op string) [3]string { return [3]string{"kolo_pin_requests_total", "op", op} }
	refused := func(r string) [3]string { return [3]string{"kolo_pin_refused_total", "reason", r} }

	alice, bob, carol := newOwner(t), newOwner(t), newOwner(t)
	al := alice.log(t, "one", "two", "three")
	ac := alice.issue(t, p.Peer, Capability{Issued: time.Now().Add(-time.Second)})
	step("add", func() {
		if _, err := Add(ctx, alice.id, p.Peer, al, ac); err != nil {
			t.Fatal(err)
		}
	}, map[[3]string]float64{add("add"): 1, {"kolo_pin_logs"}: 1, {"kolo_pin_owners"}: 1, {"kolo_pin_entries"}: 3,
		{"kolo_pin_sync_pull_duration_seconds"}: 1, {"kolo_pin_request_duration_seconds", "op", "add"}: 1})
	if value(t, prev, "kolo_pin_bytes_received_total") < 3*16 || value(t, prev, "kolo_pin_bytes_used") == 0 {
		t.Fatal("bytes_received_total or bytes_used did not grow")
	}

	now := time.Now()
	forged := alice.issue(t, p.Peer, Capability{})
	forged[len(forged)-1] ^= 1
	for _, c := range []struct {
		reason string
		cap    []byte
		want   error
	}{
		{"expired_token", alice.issue(t, p.Peer, Capability{Issued: now.Add(-2 * time.Hour), Expires: now.Add(-time.Hour)}), ErrExpired},
		{"bad_signature", forged, ErrUnauthorized},
		{"bad_token", alice.issue(t, Peer{ID: bob.id.PublicKey()}, Capability{}), ErrUnauthorized},
		{"replayed_token", alice.issue(t, p.Peer, Capability{Issued: now.Add(-time.Hour)}), ErrRevoked},
	} {
		step(c.reason, func() {
			if _, err := Add(ctx, alice.id, p.Peer, al, c.cap); !errors.Is(err, c.want) {
				t.Fatalf("%s: %v", c.reason, err)
			}
		}, map[[3]string]float64{refused(c.reason): 1, add("add"): 1, refused("other"): 0})
	}

	bl := bob.log(t, string(make([]byte, 64<<10)))
	bc := bob.issue(t, p.Peer, Capability{Quota: 100 << 10})
	if _, err := Add(ctx, bob.id, p.Peer, bl, bc); err != nil {
		t.Fatal(err)
	}
	_, _ = bl.Append(make([]byte, 64<<10))
	step("quota", func() {
		if _, err := Add(ctx, bob.id, p.Peer, bl, bc); !errors.Is(err, ErrQuotaExceeded) {
			t.Fatalf("quota: %v", err)
		}
	}, map[[3]string]float64{refused("quota_exceeded"): 1, refused("disk_full"): 0})

	cl := carol.log(t, "c")
	step("carol", func() {
		if _, err := Add(ctx, carol.id, p.Peer, cl, carol.issue(t, p.Peer, Capability{Issued: now.Add(-time.Minute)})); err != nil {
			t.Fatal(err)
		}
	}, map[[3]string]float64{{"kolo_pin_logs"}: 1, {"kolo_pin_owners"}: 1})
	_ = cl.Close()
	note, _ := IssueRevocation(carol.id, p.ID, now.Add(-time.Second))
	step("revoke", func() {
		if err := Revoke(ctx, generate(t), p.Peer, note); err != nil {
			t.Fatal(err)
		}
	}, map[[3]string]float64{add("revoke"): 1, {"kolo_pin_logs"}: -1, {"kolo_pin_owners"}: -1})
	cl2, err := carol.st.Open(carol.id, cl.ID())
	if err != nil {
		t.Fatal(err)
	}
	step("revoked", func() {
		if _, err := Add(ctx, carol.id, p.Peer, cl2, carol.issue(t, p.Peer, Capability{Issued: now.Add(-time.Hour)})); !errors.Is(err, ErrRevoked) {
			t.Fatalf("revoked: %v", err)
		}
	}, map[[3]string]float64{refused("revoked"): 1, refused("replayed_token"): 0})

	if err := al.Delete(1); err != nil {
		t.Fatal(err)
	}
	step("delete marker", func() {
		if _, err := Add(ctx, alice.id, p.Peer, al, ac); err != nil {
			t.Fatal(err)
		}
	}, map[[3]string]float64{{"kolo_pin_delete_markers_applied_total"}: 1})
	step("delete marker again", func() {
		if _, err := Add(ctx, alice.id, p.Peer, al, ac); err != nil {
			t.Fatal(err)
		}
	}, map[[3]string]float64{{"kolo_pin_delete_markers_applied_total"}: 0, add("add"): 1})
	more := func() {
		if _, err := al.Append([]byte("more")); err != nil {
			t.Fatal(err)
		}
	}
	for range 5 {
		more()
	}
	step("more entries", func() {
		if _, err := Add(ctx, alice.id, p.Peer, al, ac); err != nil {
			t.Fatal(err)
		}
	}, map[[3]string]float64{{"kolo_pin_delete_markers_applied_total"}: 0, {"kolo_pin_entries"}: 5})
	more()
	// Entries 0, 3, 5 and 7 lose their ciphertext; 1 was deleted before and 8 arrives deleted.
	if err := al.Delete(0, 1, 3, 5, 7, 8); err != nil {
		t.Fatal(err)
	}
	step("batched delete markers", func() {
		if _, err := Add(ctx, alice.id, p.Peer, al, ac); err != nil {
			t.Fatal(err)
		}
	}, map[[3]string]float64{{"kolo_pin_delete_markers_applied_total"}: 4, {"kolo_pin_entries"}: 1})

	dev := generate(t)
	step("sync pull", func() {
		if _, err := pullFrom(t, ctx, p.Peer, alice.id.PublicKey(), al.ID()); err != nil {
			t.Fatal(err)
		}
	}, map[[3]string]float64{add("sync_pull"): 2, add("add"): 0})
	if value(t, prev, "kolo_pin_bytes_served_total") == 0 {
		t.Fatal("bytes_served_total did not grow")
	}
	step("fetch", func() {
		conn, err := kolosecure.Dial(ctx, p.Addr, dev, p.ID, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		h, err := kolosync.FetchHead(ctx, conn, alice.id.PublicKey(), al.ID())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := kolosync.Fetch(ctx, conn, h, 2, 4); err != nil {
			t.Fatal(err)
		}
	}, map[[3]string]float64{add("sync_pull"): 2, {"kolo_pin_delete_markers_applied_total"}: 0})
	step("status", func() {
		if _, err := Status(ctx, alice.id, p.Peer, al.ID()); err != nil {
			t.Fatal(err)
		}
	}, map[[3]string]float64{add("status"): 1})
	step("unknown status", func() {
		if _, err := Status(ctx, dev, p.Peer, al.ID()); !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
	}, map[[3]string]float64{add("status"): 1, refused("other"): 1})

	deadline := time.Now().Add(5 * time.Second)
	for {
		fams, body := scrape(t, url)
		if value(t, fams, "kolo_pin_active_connections") == 0 && value(t, fams, "kolo_pin_active_sync_streams") == 0 &&
			value(t, fams, "kolo_pin_active_pulls") == 0 {
			assertNoIdentifiers(t, body, p, []*ownerNode{alice, bob, carol}, []kololog.LogID{al.ID(), bl.ID(), cl.ID()}, dev.PublicKey())
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("active_connections did not return to 0")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// assertNoIdentifiers fails if the metrics text holds any key, log ID or address, in hex or raw form.
func assertNoIdentifiers(t *testing.T, body []byte, p *pinPeer, owners []*ownerNode, logs []kololog.LogID, others ...[]byte) {
	t.Helper()
	ids := append([][]byte{p.ID}, others...)
	for _, o := range owners {
		ids = append(ids, o.id.PublicKey())
	}
	for _, l := range logs {
		ids = append(ids, l[:])
	}
	for i, id := range ids {
		if bytes.Contains(body, id) || bytes.Contains(bytes.ToLower(body), []byte(hex.EncodeToString(id))) ||
			bytes.Contains(body, []byte(hex.EncodeToString(id)[:16])) {
			t.Errorf("identifier %d appears in the metrics", i)
		}
	}
	for _, s := range []string{"127.0.0.1", p.Addr} {
		if bytes.Contains(body, []byte(s)) {
			t.Errorf("address %s appears in the metrics", s)
		}
	}
}

// Serve frees its metrics when it returns, so a restart registers them again.
func TestMetricsRegistration(t *testing.T) {
	checkGoroutines(t)
	reg := prometheus.NewRegistry()
	p := startPin(t, Options{Metrics: reg})
	p.restart(t)
	if fams, err := reg.Gather(); err != nil || len(fams) == 0 {
		t.Fatalf("Gather after restart: %d families, %v", len(fams), err)
	}
	p.stop(t)
	if fams, _ := reg.Gather(); len(fams) != 0 {
		t.Fatalf("%d metric families left after Serve returned", len(fams))
	}
}

// A served kolo-sync stream shows in active_sync_streams while it runs, and bytes_served_total counts its answer exactly.
func TestMetricsServedStream(t *testing.T) {
	checkGoroutines(t)
	ctx := testCtx(t)
	reg := prometheus.NewRegistry()
	p := startPin(t, Options{Metrics: reg})
	hs := httptest.NewServer(promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	defer hs.Close()
	alice := newOwner(t)
	l := alice.log(t, "x")
	if _, err := Add(ctx, alice.id, p.Peer, l, alice.issue(t, p.Peer, Capability{})); err != nil {
		t.Fatal(err)
	}
	before, _ := scrape(t, hs.URL)
	conn, err := kolosecure.Dial(ctx, p.Addr, generate(t), p.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	st, err := conn.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id := l.ID()
	req := binary.LittleEndian.AppendUint32(nil, 2+32+kololog.LogIDSize)
	req = append(append(append(req, 1, 1), alice.id.PublicKey()...), id[:]...) // version 1, HEAD_REQ, owner, log ID
	if _, err := st.Write(req); err != nil {
		t.Fatal(err)
	}
	var hdr [4]byte
	if _, err := io.ReadFull(st, hdr[:]); err != nil {
		t.Fatal(err)
	}
	n := binary.LittleEndian.Uint32(hdr[:])
	if _, err := io.ReadFull(st, make([]byte, n)); err != nil {
		t.Fatal(err)
	}
	during, _ := scrape(t, hs.URL)
	if v := value(t, during, "kolo_pin_active_sync_streams"); v != 1 || value(t, during, "kolo_pin_active_pulls") != 0 {
		t.Fatalf("active_sync_streams %v during one served stream", v)
	}
	if d := value(t, during, "kolo_pin_bytes_served_total") - value(t, before, "kolo_pin_bytes_served_total"); d != float64(4+n) {
		t.Fatalf("bytes_served_total grew by %v, the answer was %d bytes", d, 4+n)
	}
	conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		after, _ := scrape(t, hs.URL)
		if value(t, after, "kolo_pin_active_sync_streams") == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("active_sync_streams did not return to 0")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The op labels of kolo_pin_request_duration_seconds are the ones docs/operations.md lists.
func TestRequestDurationOps(t *testing.T) {
	m := newMetrics()
	reg := prometheus.NewRegistry()
	reg.MustRegister(m.reqSeconds)
	fams, err := reg.Gather()
	if err != nil || len(fams) != 1 {
		t.Fatalf("Gather = %d, %v", len(fams), err)
	}
	var got []string
	for _, mt := range fams[0].Metric {
		for _, l := range mt.Label {
			got = append(got, l.GetValue())
		}
	}
	doc, err := os.ReadFile("docs/operations.md")
	if err != nil {
		t.Fatalf("metrics table: %v", err)
	}
	var want []string
	for line := range strings.SplitSeq(string(doc), "\n") {
		if strings.HasPrefix(line, "| `kolo_pin_request_duration_seconds`") {
			_, labels, _ := strings.Cut(line, "`op`:")
			labels, _, _ = strings.Cut(labels, "|")
			for f := range strings.SplitSeq(labels, ",") {
				want = append(want, strings.Trim(strings.TrimSpace(f), "`"))
			}
		}
	}
	slices.Sort(got)
	slices.Sort(want)
	if len(want) == 0 {
		t.Fatal("docs/operations.md has no kolo_pin_request_duration_seconds row with `op`: labels")
	}
	if !slices.Equal(got, want) {
		t.Fatalf("histogram ops %v, docs/operations.md lists %v", got, want)
	}
}
