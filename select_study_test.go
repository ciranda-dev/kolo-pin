package pin

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"os"
	"runtime"
	"slices"
	"sync"
	"testing"

	kolodht "github.com/ciranda-dev/kolo-dht"
	kololog "github.com/ciranda-dev/kolo-log"
)

// The Select study compares rendezvous hashing (Select) with XOR distance (kolodht.Distance), for n = 2.
// KOLO_PIN_SELECT_STUDY=1 runs it on 1,000,000 logs and 20 peer sets per peer count (a few minutes):
//
//	KOLO_PIN_SELECT_STUDY=1 go test -run '^TestSelectStudy$' -v -timeout 0 .
//
// Without it, a small run keeps the code checked.

type studyMethod struct {
	name  string
	score func(peer []byte, logID kololog.LogID) [32]byte // higher wins
}

var studyMethods = []studyMethod{
	{"hrw", func(p []byte, id kololog.LogID) [32]byte { return weight(p, id) }},
	{"xor", func(p []byte, id kololog.LogID) [32]byte {
		d := kolodht.Distance([32]byte(id), [32]byte(p))
		for i := range d {
			d[i] = ^d[i] // closer is higher
		}
		return d
	}},
}

// pick2 returns the indexes of the two highest scores among scores[from:to], skipping skip, with Select's group
// rule when groups is set: the second comes from another group if any peer there is in range.
func pick2(scores [][32]byte, groups []int, from, to, skip int) (int, int) {
	best, second := -1, -1
	higher := func(i, j int) bool { return j < 0 || bytes.Compare(scores[i][:], scores[j][:]) > 0 }
	for i := from; i < to; i++ {
		if i == skip {
			continue
		}
		if higher(i, best) {
			best, second = i, best
		} else if higher(i, second) {
			second = i
		}
	}
	if groups == nil || groups[best] != groups[second] {
		return best, second
	}
	other := -1
	for i := from; i < to; i++ {
		if i != skip && groups[i] != groups[best] && higher(i, other) {
			other = i
		}
	}
	if other >= 0 {
		return best, other
	}
	return best, second
}

type studyResult struct {
	maxLoad, minLoad, movedAdd, movedRemove, sameGroup float64
}

// studySet measures one method on one set of N+1 peer IDs: the first N are the list, the last one joins, the first
// one leaves. raw counts how often the plain top two share a group; groups, if set, apply Select's group rule.
func studySet(logs []kololog.LogID, ids [][]byte, groups []int, m studyMethod) studyResult {
	n := len(ids) - 1
	load := make([]int, n)
	var add, remove, same int
	scores := make([][32]byte, n+1)
	for _, id := range logs {
		for i, p := range ids {
			scores[i] = m.score(p, id)
		}
		a, b := pick2(scores, groups, 0, n, -1)
		load[a]++
		load[b]++
		if x, y := pick2(scores, groups, 0, n+1, -1); !samePair(a, b, x, y) {
			add++
		}
		if n > 2 {
			if x, y := pick2(scores, groups, 0, n, 0); !samePair(a, b, x, y) {
				remove++
			}
		}
		if groups != nil {
			if x, y := pick2(scores, nil, 0, n, -1); groups[x] == groups[y] {
				same++
			}
		}
	}
	mean := float64(2*len(logs)) / float64(n)
	total := float64(len(logs))
	return studyResult{
		maxLoad: float64(slices.Max(load)) / mean, minLoad: float64(slices.Min(load)) / mean,
		movedAdd: float64(add) / total, movedRemove: float64(remove) / total, sameGroup: float64(same) / total,
	}
}

func samePair(a, b, x, y int) bool { return (a == x && b == y) || (a == y && b == x) }

// studyGroups assigns groups to n peers: "equal" is 3 groups round-robin, "skewed" puts 70% in one group and the rest
// in two others, at least one peer each.
func studyGroups(kind string, n int) []int {
	g := make([]int, n)
	switch kind {
	case "equal":
		for i := range g {
			g[i] = i % 3
		}
	case "skewed":
		big := max(1, min(n-2, n*7/10))
		for i := big; i < n; i++ {
			g[i] = 1 + (i-big)%2
		}
	default:
		return nil
	}
	return g
}

func quantiles(v []float64) (p5, med, p95 float64) {
	s := slices.Clone(v)
	slices.Sort(s)
	at := func(q float64) float64 { return s[int(q*float64(len(s)-1)+0.5)] }
	return at(0.05), at(0.5), at(0.95)
}

func TestSelectStudy(t *testing.T) {
	logsN, sets, counts := 2000, 2, []int{3, 25}
	if os.Getenv("KOLO_PIN_SELECT_STUDY") != "" {
		logsN, sets, counts = 1_000_000, 20, []int{3, 5, 10, 25, 50, 200}
	}
	r := rand.New(rand.NewPCG(2026, 11))
	logs := make([]kololog.LogID, logsN)
	for i := range logs {
		logs[i] = randomLog(r)
	}

	// The study's pick2 must choose exactly what Select chooses.
	check := randomPeers(r, 9, "a", "b", "c")
	ids := make([][]byte, len(check))
	for i, p := range check {
		ids[i] = p.ID
	}
	for _, id := range logs[:min(len(logs), 500)] {
		scores := make([][32]byte, len(ids))
		for i, p := range ids {
			scores[i] = weight(p, id)
		}
		a, b := pick2(scores, studyGroups("equal", len(ids)), 0, len(ids), -1)
		if got := Select(check, id, 2).Peers; !samePeers(got, []Peer{check[min(a, b)], check[max(a, b)]}) && !samePeers(got, []Peer{check[max(a, b)], check[min(a, b)]}) {
			t.Fatal("the study's selection differs from Select")
		}
	}

	for _, setup := range []string{"none", "equal", "skewed"} {
		for _, n := range counts {
			if setup != "none" && n < 3 {
				continue
			}
			results := map[string][]studyResult{}
			var mu sync.Mutex
			var wg sync.WaitGroup
			sem := make(chan struct{}, runtime.GOMAXPROCS(0))
			for set := range sets {
				pr := rand.New(rand.NewPCG(uint64(n), uint64(set)))
				var ids [][]byte
				for _, p := range randomPeers(pr, n+1) {
					ids = append(ids, p.ID)
				}
				groups := studyGroups(setup, n+1)
				for _, m := range studyMethods {
					sem <- struct{}{}
					wg.Go(func() {
						defer func() { <-sem }()
						res := studySet(logs, ids, groups, m)
						mu.Lock()
						results[m.name] = append(results[m.name], res)
						mu.Unlock()
					})
				}
			}
			wg.Wait()
			for _, m := range studyMethods {
				rs := results[m.name]
				col := func(f func(studyResult) float64) []float64 {
					var out []float64
					for _, x := range rs {
						out = append(out, f(x))
					}
					return out
				}
				line := fmt.Sprintf("groups=%s N=%d %s", setup, n, m.name)
				for _, c := range []struct {
					name  string
					v     []float64
					worst func([]float64) float64
				}{
					{"fullest/mean", col(func(x studyResult) float64 { return x.maxLoad }), slices.Max[[]float64]},
					{"emptiest/mean", col(func(x studyResult) float64 { return x.minLoad }), slices.Min[[]float64]},
					{"moved on join", col(func(x studyResult) float64 { return x.movedAdd }), slices.Max[[]float64]},
					{"moved on leave", col(func(x studyResult) float64 { return x.movedRemove }), slices.Max[[]float64]},
					{"top two in one group", col(func(x studyResult) float64 { return x.sameGroup }), slices.Max[[]float64]},
				} {
					if setup == "none" && c.name == "top two in one group" {
						continue
					}
					p5, med, p95 := quantiles(c.v)
					line += fmt.Sprintf(" | %s med %.3f p5 %.3f p95 %.3f worst %.3f", c.name, med, p5, p95, c.worst(c.v))
				}
				t.Log(line)
			}
		}
	}
}

func BenchmarkSelect(b *testing.B) {
	r := rand.New(rand.NewPCG(7, 8))
	for _, n := range []int{3, 5, 10, 25, 50, 200} {
		peers := randomPeers(r, n, "a", "b", "c")
		logID := randomLog(r)
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				Select(peers, logID, 2)
			}
		})
	}
}
