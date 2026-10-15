// Copyright 2018 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !noprocesses

package collector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
)

// statTemplate is a complete /proc/[pid]/stat line (44 fields). The variable
// fields are: pid/comm (1-2), state (3), num threads (field 20) and start time
// (field 22, clock ticks since boot).
const statTemplate = "%d (fake) %s 0 0 0 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 %d 0 %d 0 0 18446744073709551615 1 1 0 0 0 0 0 4096 0 0 0 0 17 0 0 0 0 0 0 0 0"

// fakeProc describes one process in a synthetic /proc tree. threadStates lists
// the run state of every thread; the first entry is also the main thread and
// process state. TIDs are pid, pid+1, ...
type fakeProc struct {
	pid          int
	startTime    uint64
	threadStates []string
}

func writeFakeStat(tb testing.TB, fullPath string, id int, state string, numThreads int, startTime uint64) {
	tb.Helper()
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		tb.Fatal(err)
	}
	line := fmt.Sprintf(statTemplate+"\n", id, state, numThreads, startTime)
	if err := os.WriteFile(fullPath, []byte(line), 0o644); err != nil {
		tb.Fatal(err)
	}
}

func createFakeProc(tb testing.TB, root string, p fakeProc) {
	tb.Helper()
	if len(p.threadStates) == 0 {
		tb.Fatalf("fake proc %d needs at least one thread", p.pid)
	}
	state := p.threadStates[0]
	pidDir := filepath.Join(root, strconv.Itoa(p.pid))
	writeFakeStat(tb, filepath.Join(pidDir, "stat"), p.pid, state, len(p.threadStates), p.startTime)
	for i, st := range p.threadStates {
		tid := p.pid + i
		writeFakeStat(tb, filepath.Join(pidDir, "task", strconv.Itoa(tid), "stat"), tid, st, len(p.threadStates), p.startTime)
	}
}

func newFakeProcfs(tb testing.TB, procs []fakeProc) string {
	tb.Helper()
	root := tb.TempDir()
	for _, p := range procs {
		createFakeProc(tb, root, p)
	}
	for _, name := range []string{"sys/kernel/pid_max", "sys/kernel/threads-max"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.Dir(name)), 0o755); err != nil {
			tb.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte("4194320\n"), 0o644); err != nil {
			tb.Fatal(err)
		}
	}
	*procPath = root
	return root
}

func newTestProcessCollector(tb testing.TB, root string) *processCollector {
	tb.Helper()
	// Go through the real constructor so that the metric descriptors are
	// initialized for tests exercising UpdateContext as well.
	c, err := NewProcessStatCollector(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		tb.Fatalf("failed to create process collector: %v", err)
	}
	pc := c.(*processCollector)
	pc.fs, err = procfs.NewFS(root)
	if err != nil {
		tb.Fatalf("failed to open procfs: %v", err)
	}
	return pc
}

func mustScan(tb testing.TB, c *processCollector, ctx context.Context) processScan {
	tb.Helper()
	result, err := c.scan(ctx)
	if err != nil {
		tb.Fatalf("unexpected scan error: %v", err)
	}
	return result
}

func TestReadProcessStatus(t *testing.T) {
	*procPath = "fixtures/proc"
	fs, err := procfs.NewFS(*procPath)
	if err != nil {
		t.Errorf("failed to open procfs: %v", err)
	}
	c := processCollector{fs: fs, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	result := mustScan(t, &c, context.Background())
	if result.threads < 1 {
		t.Fatalf("Current threads: %d shouldn't be less than wanted 1", result.threads)
	}
	if result.procStates == nil {
		t.Fatalf("Process states cannot be nil %v:", result.procStates)
	}
	maxPid, err := readUintFromFile(procFilePath("sys/kernel/pid_max"))
	if err != nil {
		t.Fatalf("Unable to retrieve limit number of maximum pids allowed %v\n", err)
	}
	if uint64(result.pids) > maxPid || result.pids == 0 {
		t.Fatalf("Total running pids cannot be greater than %d or equals to 0", maxPid)
	}
}

func TestProcessScanAggregates(t *testing.T) {
	procs := []fakeProc{
		{1000, 100, []string{"S", "S", "R"}},
		{2000, 200, []string{"R", "D"}},
	}
	root := newFakeProcfs(t, procs)
	c := newTestProcessCollector(t, root)

	result := mustScan(t, c, context.Background())

	if result.pids != 2 {
		t.Errorf("want 2 pids, got %d", result.pids)
	}
	if result.threads != 5 {
		t.Errorf("want 5 threads, got %d", result.threads)
	}
	if result.procStates["S"] != 1 || result.procStates["R"] != 1 {
		t.Errorf("unexpected process states: %v", result.procStates)
	}
	if result.threadStates["S"] != 2 || result.threadStates["R"] != 2 || result.threadStates["D"] != 1 {
		t.Errorf("unexpected thread states: %v", result.threadStates)
	}
}

func TestProcessScanCacheEvictsVanishedProcesses(t *testing.T) {
	procs := []fakeProc{
		{1000, 100, []string{"S", "S", "R"}},
		{2000, 200, []string{"R", "D"}},
	}
	root := newFakeProcfs(t, procs)
	c := newTestProcessCollector(t, root)

	first := mustScan(t, c, context.Background())
	second := mustScan(t, c, context.Background())
	if first.pids != second.pids || first.threads != second.threads {
		t.Fatalf("repeated scans are not stable: %v vs %v", first, second)
	}
	if len(c.cache) != 2 {
		t.Fatalf("want 2 cached processes, got %d", len(c.cache))
	}

	// Process 2000 exits between scrapes.
	if err := os.RemoveAll(filepath.Join(root, "2000")); err != nil {
		t.Fatal(err)
	}
	third := mustScan(t, c, context.Background())
	if third.pids != 1 || third.threads != 3 {
		t.Errorf("want 1 pid / 3 threads after exit, got %d / %d", third.pids, third.threads)
	}
	if third.procStates["S"] != 1 {
		t.Errorf("want state S=1 after exit, got %v", third.procStates)
	}
	if _, ok := c.cache[2000]; ok {
		t.Error("cache entry for exited process was not evicted")
	}
}

func TestProcessScanPIDReuse(t *testing.T) {
	root := newFakeProcfs(t, []fakeProc{{3000, 1000, []string{"S", "S"}}})
	c := newTestProcessCollector(t, root)

	before := mustScan(t, c, context.Background())
	if before.procStates["S"] != 1 || before.threadStates["S"] != 2 || before.threads != 2 {
		t.Fatalf("unexpected aggregate before PID reuse: %v", before)
	}

	// PID 3000 exits and is immediately reused by a different process with a
	// different start time and a completely different shape.
	if err := os.RemoveAll(filepath.Join(root, "3000")); err != nil {
		t.Fatal(err)
	}
	createFakeProc(t, root, fakeProc{3000, 9000, []string{"R", "R", "R"}})

	after := mustScan(t, c, context.Background())
	if after.pids != 1 {
		t.Errorf("reused PID must be counted exactly once, got %d pids", after.pids)
	}
	if after.threads != 3 {
		t.Errorf("want 3 threads for the new process, got %d", after.threads)
	}
	if after.procStates["R"] != 1 {
		t.Errorf("want new process state R=1, got %v", after.procStates)
	}
	if _, ok := after.procStates["S"]; ok {
		t.Errorf("old process state S was attributed to the new process: %v", after.procStates)
	}
	if after.threadStates["R"] != 3 {
		t.Errorf("want new thread states R=3, got %v", after.threadStates)
	}
	if _, ok := after.threadStates["S"]; ok {
		t.Errorf("old thread states were attributed to the new process: %v", after.threadStates)
	}
	entry := c.cache[3000]
	if entry.startTime != 9000 {
		t.Errorf("cached start time %d, want 9000", entry.startTime)
	}
}

func TestProcessScanShortLivedAndVanishedTaskDir(t *testing.T) {
	root := newFakeProcfs(t, []fakeProc{{4000, 100, []string{"S", "S"}}})
	// 4001 is present in the directory listing but exits before its stat can
	// be read: its directory contains nothing.
	if err := os.MkdirAll(filepath.Join(root, "4001"), 0o755); err != nil {
		t.Fatal(err)
	}
	// 4002 has a readable stat but its task directory vanishes before threads
	// are enumerated, so it contributes process counters but no thread states.
	writeFakeStat(t, filepath.Join(root, "4002", "stat"), 4002, "S", 2, 300)

	c := newTestProcessCollector(t, root)
	result := mustScan(t, c, context.Background())

	if result.pids != 2 {
		t.Errorf("want 2 readable pids, got %d", result.pids)
	}
	if result.threads != 4 {
		t.Errorf("want 4 threads from process stats, got %d", result.threads)
	}
	if result.procStates["S"] != 2 {
		t.Errorf("want process state S=2, got %v", result.procStates)
	}
	if result.threadStates["S"] != 2 {
		t.Errorf("want thread states only for the fully readable process: S=2, got %v", result.threadStates)
	}
	if len(c.cache) != 2 {
		t.Errorf("short-lived process must not be cached, cache=%v", c.cache)
	}
}

func TestProcessScanPermissionDeniedKeepsLastKnownState(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission checks are bypassed when running as root")
	}
	root := newFakeProcfs(t, []fakeProc{{5000, 10, []string{"D", "D"}}})
	pidDir := filepath.Join(root, "5000")
	t.Cleanup(func() { _ = os.Chmod(pidDir, 0o755) })
	c := newTestProcessCollector(t, root)

	before := mustScan(t, c, context.Background())

	// Simulate a permission change (e.g. hidepid) making the process unreadable.
	if err := os.Chmod(pidDir, 0o000); err != nil {
		t.Fatal(err)
	}
	denied := mustScan(t, c, context.Background())
	if denied.pids != before.pids || denied.threads != before.threads {
		t.Errorf("counts regressed during permission denial: before=%v denied=%v", before, denied)
	}
	if denied.procStates["D"] != 1 || denied.threadStates["D"] != 2 {
		t.Errorf("last known state not used during permission denial: %v / %v", denied.procStates, denied.threadStates)
	}
	if c.cache[5000].readable {
		t.Error("cached process should be marked unreadable after EACCES")
	}

	// Visibility returns, but meanwhile the PID was reused by another process.
	if err := os.Chmod(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(pidDir); err != nil {
		t.Fatal(err)
	}
	createFakeProc(t, root, fakeProc{5000, 99, []string{"R"}})
	after := mustScan(t, c, context.Background())
	if after.procStates["R"] != 1 || after.threads != 1 {
		t.Errorf("want new process R=1 / 1 thread, got %v / %d", after.procStates, after.threads)
	}
	if _, ok := after.procStates["D"]; ok {
		t.Errorf("old process state D survived PID reuse: %v", after.procStates)
	}
}

func TestProcessScanUnknownDeniedProcessIsNotCounted(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission checks are bypassed when running as root")
	}
	root := newFakeProcfs(t, nil)
	pidDir := filepath.Join(root, "6000")
	if err := os.MkdirAll(pidDir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(pidDir, 0o755) })
	c := newTestProcessCollector(t, root)

	result := mustScan(t, c, context.Background())
	if result.pids != 0 || result.threads != 0 {
		t.Errorf("never-observable process must not be counted, got %v", result)
	}
}

// cancelAfterChecksContext cancels after a number of Err() calls, which lets a
// test deterministically abort a scan midway through a large process table.
type cancelAfterChecksContext struct {
	checks atomic.Int64
	after  int64
}

func (c *cancelAfterChecksContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *cancelAfterChecksContext) Done() <-chan struct{}       { return nil }
func (c *cancelAfterChecksContext) Value(any) any               { return nil }
func (c *cancelAfterChecksContext) Err() error {
	if c.checks.Add(1) >= c.after {
		return context.Canceled
	}
	return nil
}

func TestProcessScanContextCanceled(t *testing.T) {
	procs := make([]fakeProc, 500)
	for i := range procs {
		procs[i] = fakeProc{10000 + i, uint64(i), []string{"S", "R"}}
	}
	root := newFakeProcfs(t, procs)
	c := newTestProcessCollector(t, root)

	want := mustScan(t, c, context.Background())

	// Already canceled context: the scan aborts before listing processes and
	// UpdateContext emits no partial metrics.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.scan(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	ch := make(chan prometheus.Metric, 64)
	if err := c.UpdateContext(ctx, ch); !errors.Is(err, context.Canceled) {
		t.Fatalf("UpdateContext want context.Canceled, got %v", err)
	}
	if len(ch) != 0 {
		t.Fatalf("canceled scrape emitted %d partial metrics", len(ch))
	}

	// Cancellation midway through the process table leaves the cache
	// consistent: the next complete scrape reproduces the original counters.
	midway := &cancelAfterChecksContext{after: 3}
	if _, err := c.scan(midway); !errors.Is(err, context.Canceled) {
		t.Fatalf("want mid-scan context.Canceled, got %v", err)
	}
	after := mustScan(t, c, context.Background())
	if after.pids != want.pids || after.threads != want.threads {
		t.Errorf("counters regressed after canceled scrape: before=%v after=%v", want, after)
	}
}

func TestProcessScanHighProcessCount(t *testing.T) {
	const n = 2000
	procs := make([]fakeProc, n)
	for i := range procs {
		procs[i] = fakeProc{20000 + i, uint64(i + 1), []string{"S", "R"}}
	}
	root := newFakeProcfs(t, procs)
	c := newTestProcessCollector(t, root)

	result := mustScan(t, c, context.Background())
	if result.pids != n {
		t.Errorf("want %d pids, got %d", n, result.pids)
	}
	if result.threads != 2*n {
		t.Errorf("want %d threads, got %d", 2*n, result.threads)
	}
	if sum := threadStateTotal(result); sum != int32(2*n) {
		t.Errorf("thread state breakdown sums to %d, want %d", sum, 2*n)
	}
	if len(c.cache) != n {
		t.Errorf("want %d cached processes, got %d", n, len(c.cache))
	}

	// Repeated scans must not grow the cache.
	mustScan(t, c, context.Background())
	if len(c.cache) != n {
		t.Errorf("cache grew across scrapes: %d", len(c.cache))
	}

	// Half of the processes exit; cache and counters must shrink accordingly.
	for i := 0; i < n/2; i++ {
		if err := os.RemoveAll(filepath.Join(root, strconv.Itoa(20000+i))); err != nil {
			t.Fatal(err)
		}
	}
	shrunk := mustScan(t, c, context.Background())
	if shrunk.pids != n/2 || len(c.cache) != n/2 {
		t.Errorf("want %d pids/cache entries after exits, got %d/%d", n/2, shrunk.pids, len(c.cache))
	}
	if sum := threadStateTotal(shrunk); sum != int32(n) {
		t.Errorf("thread state breakdown sums to %d, want %d", sum, n)
	}
}

func TestUpdateContextEmitsMetrics(t *testing.T) {
	root := newFakeProcfs(t, []fakeProc{{7000, 1, []string{"S", "R"}}})
	c := newTestProcessCollector(t, root)

	ch := make(chan prometheus.Metric, 32)
	if err := c.UpdateContext(context.Background(), ch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ch) < 6 {
		t.Fatalf("want at least 6 metrics, got %d", len(ch))
	}
}

func TestProcessCollectorConcurrentScrapes(t *testing.T) {
	procs := make([]fakeProc, 20)
	for i := range procs {
		procs[i] = fakeProc{80000 + i, uint64(i), []string{"S", "R"}}
	}
	root := newFakeProcfs(t, procs)
	c := newTestProcessCollector(t, root)

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				ch := make(chan prometheus.Metric, 32)
				if err := c.UpdateContext(context.Background(), ch); err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if len(ch) < 6 {
					t.Errorf("want at least 6 metrics, got %d", len(ch))
				}
			}
		}()
	}
	wg.Wait()
}

func TestProcessScanErrorClassifiers(t *testing.T) {
	for _, err := range []error{
		os.ErrPermission,
		syscall.EACCES,
		syscall.EPERM,
		fmt.Errorf("open /proc/123/stat: %w", syscall.EACCES),
	} {
		if !isPermissionDeniedError(err) {
			t.Errorf("expected permission error for %v", err)
		}
		if isProcessGoneError(err) {
			t.Errorf("permission error must not be classified as gone: %v", err)
		}
	}

	for _, err := range []error{
		os.ErrNotExist,
		syscall.ESRCH,
		fmt.Errorf("read /proc/123/stat: %w", os.ErrNotExist),
		fmt.Errorf("read /proc/123/stat: %s", syscall.ESRCH.Error()),
	} {
		if !isProcessGoneError(err) {
			t.Errorf("expected gone error for %v", err)
		}
		if isPermissionDeniedError(err) {
			t.Errorf("gone error must not be classified as permission denied: %v", err)
		}
	}
}

func TestRetainCachedProcess(t *testing.T) {
	c := &processCollector{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		cache: map[int]*cachedProcess{
			5000: {
				startTime:    10,
				state:        "D",
				threads:      2,
				threadStates: map[string]int32{"D": 2},
				readable:     true,
				lastSeen:     1,
			},
		},
		gen: 1,
	}

	// A known process that becomes unreadable keeps its last known counters.
	result := processScan{
		procStates:   map[string]int32{},
		threadStates: map[string]int32{},
	}
	c.retainCachedProcess(5000, 2, &result)
	if result.pids != 1 || result.threads != 2 || result.procStates["D"] != 1 || result.threadStates["D"] != 2 {
		t.Fatalf("last known state not retained: %v", result)
	}
	if c.cache[5000].readable || c.cache[5000].lastSeen != 2 {
		t.Fatalf("cached entry not marked for current generation: %+v", c.cache[5000])
	}

	// A process that has never been observed cannot be counted while denied.
	c.retainCachedProcess(9999, 2, &result)
	if result.pids != 1 {
		t.Fatalf("unknown denied process must not be counted: %v", result)
	}
	if _, ok := c.cache[9999]; ok {
		t.Fatal("unknown denied process must not be cached")
	}
}

func threadStateTotal(s processScan) int32 {
	var total int32
	for _, n := range s.threadStates {
		total += n
	}
	return total
}

func BenchmarkProcessScan(b *testing.B) {
	const n = 1000
	procs := make([]fakeProc, n)
	for i := range procs {
		procs[i] = fakeProc{90000 + i, uint64(i + 1), []string{"S", "R"}}
	}
	root := newFakeProcfs(b, procs)
	fs, err := procfs.NewFS(root)
	if err != nil {
		b.Fatal(err)
	}
	c := &processCollector{fs: fs, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.scan(ctx); err != nil {
			b.Fatal(err)
		}
	}
}
