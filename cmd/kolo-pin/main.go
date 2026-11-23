// Command kolo-pin runs a pinning peer: a peer that stores encrypted data for others without being able to read it.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/bits"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ciranda-dev/kolo-pin"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const usage = `usage:
  kolo-pin run -data DIR [flags]   run a pinning peer
  kolo-pin id -data DIR            print the pinning peer's public key, creating it if needed

Run "kolo-pin run -h" for the flags and their environment variables.
`

// defaultMaxConns is kolo-transport's default MaxMemory divided by its default MaxConnReceiveWindow, less its default
// MaxDialed (32), the most connections its memory check accepts.
const defaultMaxConns = kolotransport.DefaultMaxMemory/kolotransport.DefaultMaxConnReceiveWindow - 32

// programStart is when the program started; kolo_pin_uptime_seconds counts from it.
var programStart = time.Now()

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

type config struct {
	data, listen, health, metrics, owners, logFormat, logLevel, maxBytes string
	maxOwners, maxConns, maxConnsPerIP, addTimeout, maxOpenBytes         string
	peerRate, peerBurst                                                  string
}

func parse(name string, args []string, env func(string) string, stderr io.Writer) (config, error) {
	def := func(key, value string) string {
		if v := env(key); v != "" {
			return v
		}
		return value
	}
	var c config
	fs := flag.NewFlagSet("kolo-pin "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&c.data, "data", def("KOLO_PIN_DATA", ""), "data `dir`, private (0700): identity.key and the store (KOLO_PIN_DATA)")
	if name == "run" {
		fs.StringVar(&c.listen, "listen", def("KOLO_PIN_LISTEN", "127.0.0.1:7450"), "UDP `address` for kolo-secure connections, IPv4; \"0.0.0.0:7450\" on a VPS (KOLO_PIN_LISTEN)")
		fs.StringVar(&c.maxBytes, "max-bytes", def("KOLO_PIN_MAX_BYTES", "100GB"), "the most `bytes` stored for all owners, such as 500MB or 2TiB (KOLO_PIN_MAX_BYTES)")
		fs.StringVar(&c.maxOwners, "max-owners", def("KOLO_PIN_MAX_OWNERS", ""), "the most owner records an open peer keeps, one per owner key ever seen; default 100000, ignored with -owners (KOLO_PIN_MAX_OWNERS)")
		fs.StringVar(&c.maxOpenBytes, "max-open-bytes", def("KOLO_PIN_MAX_OPEN_BYTES", ""), "the memory the open logs may take, counted as 128 bytes per log and 256 per entry, such as 512MiB; default 256MiB (KOLO_PIN_MAX_OPEN_BYTES)")
		fs.StringVar(&c.maxConns, "max-conns", def("KOLO_PIN_MAX_CONNS", ""), "the most connections at once, handshaking or open; default 2016, the most kolo-transport's default memory allows (KOLO_PIN_MAX_CONNS)")
		fs.StringVar(&c.maxConnsPerIP, "max-conns-per-ip", def("KOLO_PIN_MAX_CONNS_PER_IP", ""), "the most connections from one source address; default 4, at most -max-conns (KOLO_PIN_MAX_CONNS_PER_IP)")
		fs.StringVar(&c.peerRate, "peer-bytes-per-second", def("KOLO_PIN_PEER_BYTES_PER_SECOND", ""), "the `bytes` each peer key may pull per second over all its connections, such as 64MiB; default 32MiB (KOLO_PIN_PEER_BYTES_PER_SECOND)")
		fs.StringVar(&c.peerBurst, "peer-burst-bytes", def("KOLO_PIN_PEER_BURST_BYTES", ""), "the most `bytes` a peer key may pull at once, at least 8MiB; default 256MiB (KOLO_PIN_PEER_BURST_BYTES)")
		fs.StringVar(&c.addTimeout, "add-timeout", def("KOLO_PIN_ADD_TIMEOUT", ""), "the most `time` one add may spend pulling a log, such as 10m; default none (KOLO_PIN_ADD_TIMEOUT)")
		fs.StringVar(&c.owners, "owners", def("KOLO_PIN_OWNERS", ""), "comma-separated hex owner `keys` to accept; empty accepts any owner, and anyone can then fill the disk (KOLO_PIN_OWNERS)")
		fs.StringVar(&c.health, "health", def("KOLO_PIN_HEALTH", "127.0.0.1:7451"), "TCP `address` of the HTTP health endpoint /healthz, IPv4, or \"off\" (KOLO_PIN_HEALTH)")
		fs.StringVar(&c.metrics, "metrics", def("KOLO_PIN_METRICS", "127.0.0.1:7452"), "TCP `address` of the Prometheus endpoint /metrics, IPv4, or \"off\" (KOLO_PIN_METRICS)")
		fs.StringVar(&c.logFormat, "log-format", def("KOLO_PIN_LOG_FORMAT", "text"), "`format` of the logs on stderr: text or json (KOLO_PIN_LOG_FORMAT)")
		fs.StringVar(&c.logLevel, "log-level", def("KOLO_PIN_LOG_LEVEL", "info"), "`level`: debug, info, warn or error (KOLO_PIN_LOG_LEVEL)")
	}
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if fs.NArg() > 0 {
		return c, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if c.data == "" {
		return c, errors.New("-data is required")
	}
	return c, nil
}

func run(ctx context.Context, args []string, env func(string) string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "run", "id":
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "kolo-pin: unknown command\n%s", usage)
		return 2
	}
	c, err := parse(args[0], args[1:], env, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "kolo-pin:", err)
		return 2
	}
	if args[0] == "id" {
		id, err := pin.LoadIdentity(c.data)
		if err != nil {
			fmt.Fprintln(stderr, "kolo-pin:", err)
			return 1
		}
		fmt.Fprintln(stdout, hex.EncodeToString(id.PublicKey()))
		return 0
	}
	return serve(ctx, c, stderr)
}

func serve(ctx context.Context, c config, stderr io.Writer) int {
	log, err := newLogger(stderr, c.logFormat, c.logLevel)
	if err == nil {
		err = checkAddrs(c)
	}
	maxBytes, err2 := parseBytes("-max-bytes", c.maxBytes)
	owners, err3 := parseOwners(c.owners)
	maxOwners, err4 := parseCount("-max-owners", c.maxOwners, math.MaxInt64)
	maxConns, err5 := parseCount("-max-conns", c.maxConns, math.MaxInt32)
	perIP, err6 := parseCount("-max-conns-per-ip", c.maxConnsPerIP, math.MaxInt32)
	addTimeout, err7 := parseTimeout(c.addTimeout)
	var maxOpen uint64
	var err8 error
	if c.maxOpenBytes != "" {
		maxOpen, err8 = parseBytes("-max-open-bytes", c.maxOpenBytes)
	}
	peerRate, err9 := parseBudget("-peer-bytes-per-second", c.peerRate)
	peerBurst, err10 := parseBudget("-peer-burst-bytes", c.peerBurst)
	if err := errors.Join(err, err2, err3, err4, err5, err6, err7, err8, err9, err10); err != nil {
		fmt.Fprintln(stderr, "kolo-pin:", err)
		return 2
	}
	id, err := pin.LoadIdentity(c.data)
	if err != nil {
		log.Error("identity failed", "err", err.Error())
		return 1
	}
	if maxConns == 0 {
		maxConns = defaultMaxConns
	}
	cfg := &kolosecure.Config{Transport: &kolotransport.Config{MaxConns: int(maxConns), MaxConnsPerIP: int(perIP)}}
	ln, err := kolosecure.Listen(ctx, c.listen, id, cfg)
	if err != nil {
		log.Error("listen failed", "err", err.Error())
		return 1
	}
	defer ln.Close()

	reg := registry()
	var servers []*http.Server
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, hs := range servers {
			_ = hs.Shutdown(sctx)
		}
	}()
	for _, e := range []struct {
		name, addr string
		h          http.Handler
	}{
		{"health", c.health, health()},
		{"metrics", c.metrics, metrics(reg)},
	} {
		if e.addr == "off" {
			continue
		}
		hl, err := net.Listen("tcp4", e.addr)
		if err != nil {
			log.Error(e.name+" listen failed", "err", err.Error())
			return 1
		}
		hs := &http.Server{Handler: e.h, ReadHeaderTimeout: 5 * time.Second}
		go func() { _ = hs.Serve(hl) }()
		servers = append(servers, hs)
		log.Info(e.name, "addr", hl.Addr().String())
	}
	done := make(chan error, 1)
	go func() {
		done <- pin.Serve(ctx, ln, pin.Options{Dir: c.data, MaxBytes: maxBytes, Owners: owners, MaxOwners: maxOwners, MaxOpenBytes: maxOpen,
			PeerBytesPerSecond: peerRate, PeerBurstBytes: peerBurst, AddTimeout: addTimeout, Logger: log, Metrics: reg})
	}()
	err = <-done
	if ctx.Err() == nil {
		log.Error("stopped", "err", err.Error())
		return 1
	}
	log.Info("stopped")
	return 0
}

// health answers 200 on /healthz while the pinning peer runs; it is shut down when the peer stops.
func health() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	return mux
}

// registry holds the Go runtime and process metrics, kolo_pin_build_info and kolo_pin_uptime_seconds;
// Serve adds the pinning peer's own.
func registry() *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "kolo_pin_build_info", Help: "Always 1; the labels name the build.",
			ConstLabels: prometheus.Labels{"version": version(), "go_version": runtime.Version()}}, func() float64 { return 1 }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "kolo_pin_uptime_seconds", Help: "Seconds since the program started."},
			func() float64 { return time.Since(programStart).Seconds() }),
	)
	return reg
}

// metrics answers GET /metrics in the Prometheus text format.
func metrics(reg *prometheus.Registry) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	return mux
}

func version() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "(devel)"
}

func newLogger(w io.Writer, format, level string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("unknown log level %q", level)
	}
	o := &slog.HandlerOptions{Level: l}
	switch format {
	case "text":
		return slog.New(slog.NewTextHandler(w, o)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, o)), nil
	}
	return nil, fmt.Errorf("unknown log format %q", format)
}

// checkAddrs refuses an address that is not an IPv4 host and port; IPv6 is refused, since Kolo is IPv4 only.
func checkAddrs(c config) error {
	for _, f := range []struct{ name, addr string }{{"-listen", c.listen}, {"-health", c.health}, {"-metrics", c.metrics}} {
		if f.addr != "off" || f.name == "-listen" {
			if err := httpAddr(f.addr); err != nil {
				return fmt.Errorf("%s %q: %w", f.name, f.addr, err)
			}
		}
	}
	return nil
}

// httpAddr checks an IPv4 address and port (0 to 65535); an empty host means every interface.
func httpAddr(a string) error {
	host, port, err := net.SplitHostPort(a)
	if err != nil {
		return err
	}
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || strconv.FormatUint(n, 10) != port {
		return errors.New("want a port from 0 to 65535")
	}
	if host == "" {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	switch {
	case err != nil:
		return errors.New("want an IPv4 address and port, such as 127.0.0.1:7452")
	case !ip.Is4():
		return errors.New("IPv6 is not supported, use IPv4")
	}
	return nil
}

var units = []struct {
	suffix string
	n      uint64
}{
	{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}, {"TiB", 1 << 40},
	{"KB", 1e3}, {"MB", 1e6}, {"GB", 1e9}, {"TB", 1e12}, {"B", 1},
}

// parseBytes reads the positive byte count of the flag name, such as 1048576, 500MB or 2TiB.
func parseBytes(name, s string) (uint64, error) {
	mult := uint64(1)
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			s, mult = strings.TrimSuffix(s, u.suffix), u.n
			break
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	hi, v := bits.Mul64(n, mult)
	if err != nil || hi != 0 || v == 0 {
		return 0, fmt.Errorf("%s %q: want a positive number of bytes, such as 500MB", name, s)
	}
	return v, nil
}

// parseBudget reads a byte count of the flag name up to math.MaxInt64; empty is 0, which means the default.
func parseBudget(name, s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	n, err := parseBytes(name, s)
	if err == nil && n > math.MaxInt64 {
		err = fmt.Errorf("%s %q: want at most %d bytes", name, s, int64(math.MaxInt64))
	}
	return int64(n), err
}

// parseCount reads a count from 1 to max; empty is 0, which means the default.
func parseCount(name, s string, max uint64) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(s, 10, 63)
	if err != nil || n == 0 || n > max {
		return 0, fmt.Errorf("%s %q: want a whole number from 1 to %d", name, s, max)
	}
	return n, nil
}

// parseTimeout reads a positive duration such as 10m; empty means none.
func parseTimeout(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("-add-timeout %q: want a positive duration, such as 10m", s)
	}
	return d, nil
}

func parseOwners(s string) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for f := range strings.SplitSeq(s, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		k, err := hex.DecodeString(f)
		if err != nil || len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("-owners: %q is not a 64-digit hex key", f)
		}
		out = append(out, k)
	}
	return out, nil
}
