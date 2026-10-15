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
	"log/slog"
	"os"
	"strings"
	"sync"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
)

// cancelCheckInterval is how many processes (or threads) are scanned between
// scrape cancellation checks. Checking every iteration on hosts with hundreds
// of thousands of tasks would add noticeable overhead for no extra benefit.
const cancelCheckInterval = 128

type processCollector struct {
	fs           procfs.FS
	threadAlloc  *prometheus.Desc
	threadLimit  *prometheus.Desc
	threadsState *prometheus.Desc
	procsState   *prometheus.Desc
	pidUsed      *prometheus.Desc
	pidMax       *prometheus.Desc
	logger       *slog.Logger

	// cache holds the last consistent view of the process table, keyed by
	// PID. Entries additionally carry the process start time (field 22 of
	// /proc/[pid]/stat), so a recycled PID is never mistaken for the process
	// that was previously observed at that PID. The map is updated in place
	// generation by generation and is only consulted for stale-while-revalidate
	// fallbacks while a process is temporarily unreadable.
	mu    sync.Mutex
	cache map[int]*cachedProcess
	gen   uint64
}

// cachedProcess records the last successfully observed state of one process.
type cachedProcess struct {
	// startTime is expressed in clock ticks since boot. Together with the PID
	// it identifies the process; a changed startTime means the kernel reused
	// the PID for a different process.
	startTime uint64
	state     string
	threads   int
	// threadStates is the per-state thread breakdown observed during the
	// last successful scan of this process. It is reused only while the task
	// directory is temporarily unreadable.
	threadStates map[string]int32
	// readable reports whether /proc/[pid]/stat could be read during the most
	// recent scan the process was part of.
	readable bool
	// lastSeen is the scan generation during which the entry was observed.
	// Entries missing from a completed scan are evicted.
	lastSeen uint64
}

// processScan is the aggregated result of a single process-table scan.
type processScan struct {
	pids         int
	threads      int
	procStates   map[string]int32
	threadStates map[string]int32
}

func init() {
	registerCollector("processes", defaultDisabled, NewProcessStatCollector)
}

// NewProcessStatCollector returns a new Collector exposing process data read from the proc filesystem.
func NewProcessStatCollector(logger *slog.Logger) (Collector, error) {
	fs, err := procfs.NewFS(*procPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open procfs: %w", err)
	}
	subsystem := "processes"
	return &processCollector{
		fs: fs,
		threadAlloc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "threads"),
			"Allocated threads in system",
			nil, nil,
		),
		threadLimit: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "max_threads"),
			"Limit of threads in the system",
			nil, nil,
		),
		threadsState: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "threads_state"),
			"Number of threads in each state.",
			[]string{"thread_state"}, nil,
		),
		procsState: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, "state"),
			"Number of processes in each state.",
			[]string{"state"}, nil,
		),
		pidUsed: prometheus.NewDesc(prometheus.BuildFQName(namespace, subsystem, "pids"),
			"Number of PIDs", nil, nil,
		),
		pidMax: prometheus.NewDesc(prometheus.BuildFQName(namespace, subsystem, "max_processes"),
			"Number of max PIDs limit", nil, nil,
		),
		logger: logger,
	}, nil
}

func (c *processCollector) Update(ch chan<- prometheus.Metric) error {
	return c.UpdateContext(context.Background(), ch)
}

// UpdateContext implements CollectorWithContext. A canceled context aborts an
// in-flight scan as soon as the next cancellation checkpoint is reached; no
// partial metrics are emitted and the cached view is left consistent for the
// next scrape.
func (c *processCollector) UpdateContext(ctx context.Context, ch chan<- prometheus.Metric) error {
	scan, err := c.scan(ctx)
	if err != nil {
		return fmt.Errorf("unable to retrieve number of allocated threads: %w", err)
	}

	ch <- prometheus.MustNewConstMetric(c.threadAlloc, prometheus.GaugeValue, float64(scan.threads))
	maxThreads, err := readUintFromFile(procFilePath("sys/kernel/threads-max"))
	if err != nil {
		return fmt.Errorf("unable to retrieve limit number of threads: %w", err)
	}
	ch <- prometheus.MustNewConstMetric(c.threadLimit, prometheus.GaugeValue, float64(maxThreads))

	for state := range scan.procStates {
		ch <- prometheus.MustNewConstMetric(c.procsState, prometheus.GaugeValue, float64(scan.procStates[state]), state)
	}

	for state := range scan.threadStates {
		ch <- prometheus.MustNewConstMetric(c.threadsState, prometheus.GaugeValue, float64(scan.threadStates[state]), state)
	}

	pidM, err := readUintFromFile(procFilePath("sys/kernel/pid_max"))
	if err != nil {
		return fmt.Errorf("unable to retrieve limit number of maximum pids allowed: %w", err)
	}
	ch <- prometheus.MustNewConstMetric(c.pidUsed, prometheus.GaugeValue, float64(scan.pids))
	ch <- prometheus.MustNewConstMetric(c.pidMax, prometheus.GaugeValue, float64(pidM))

	return nil
}

// scan walks the process table once and returns its aggregated counters. The
// walk is tolerant of the three races that make /proc inherently racy:
//
//   - A PID listed by the directory scan can exit before its stat file is read
//     (short-lived process). Such PIDs are skipped; their stale cache entry (if
//     any) is evicted because they cannot be marked as seen.
//   - A PID can be reused by a different process. The process start time is
//     used as part of the identity, so on reuse the previous entry is replaced
//     wholesale and data gathered for the old process is never attributed to
//     the new one.
//   - A process can become temporarily unreadable because of a permission
//     change (for example a hidepid mount). Its last known state is carried
//     over for that scrape, keeping the aggregated totals stable. Identity is
//     revalidated on the next successful read before any data is merged again.
//
// Cache entries are only evicted after a complete, successful scan, so an
// aborted (for example canceled) scrape can never shrink the counters or
// replace a consistent view with a partial one.
func (c *processCollector) scan(ctx context.Context) (processScan, error) {
	if err := ctx.Err(); err != nil {
		return processScan{}, err
	}

	procs, err := c.fs.AllProcs()
	if err != nil {
		return processScan{}, fmt.Errorf("unable to list all processes: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.gen++
	gen := c.gen
	if c.cache == nil {
		c.cache = make(map[int]*cachedProcess, len(procs))
	}

	result := processScan{
		procStates:   make(map[string]int32),
		threadStates: make(map[string]int32),
	}

	for i, proc := range procs {
		if i%cancelCheckInterval == 0 {
			if err := ctx.Err(); err != nil {
				return processScan{}, err
			}
		}

		stat, err := proc.Stat()
		if err != nil {
			switch {
			case isProcessGoneError(err):
				// The process vanished between the directory listing and the
				// stat read. Nothing trustworthy can be recorded for it; a
				// stale cache entry (if any) is evicted at the end of the scan.
				c.logger.Debug("process vanished before its stat could be read", "pid", proc.PID, "err", err)
				continue
			case isPermissionDeniedError(err):
				c.logger.Debug("permission denied reading process stat", "pid", proc.PID, "err", err)
				// An unreadable process cannot be counted unless it was
				// successfully observed before.
				c.retainCachedProcess(proc.PID, gen, &result)
				continue
			default:
				return processScan{}, fmt.Errorf("error reading stat for pid %d: %w", proc.PID, err)
			}
		}

		entry, identityChanged := c.observeProcess(proc.PID, stat, gen)
		result.pids++
		result.procStates[entry.state]++
		result.threads += entry.threads

		if err := c.collectThreadStates(ctx, proc.PID, stat, entry, identityChanged, result.threadStates); err != nil {
			return processScan{}, err
		}
	}

	// Evict processes that were not observed during this scan generation, i.e.
	// processes that exited or stopped being listable. Processes retained
	// through a permission denial were marked with the current generation and
	// therefore survive the outage.
	for pid, entry := range c.cache {
		if entry.lastSeen != gen {
			delete(c.cache, pid)
		}
	}

	return result, nil
}

// observeProcess inserts or refreshes the cache entry for a process whose stat
// was successfully read. It reports whether the refreshed entry belongs to a
// different process (PID reuse) than the one previously cached for the PID.
func (c *processCollector) observeProcess(pid int, stat procfs.ProcStat, gen uint64) (*cachedProcess, bool) {
	entry, ok := c.cache[pid]
	if !ok {
		c.cache[pid] = &cachedProcess{
			startTime: stat.Starttime,
			state:     stat.State,
			threads:   stat.NumThreads,
			readable:  true,
			lastSeen:  gen,
		}
		return c.cache[pid], false
	}

	identityChanged := entry.startTime != stat.Starttime
	wasUnreadable := !entry.readable
	if identityChanged {
		// PID reuse: a different process now owns this PID. Drop every piece
		// of state known about the previous occupant so the old process is
		// never counted or attributed to the new one.
		c.logger.Debug(
			"pid reused by a different process",
			"pid", pid,
			"previous_start_time", entry.startTime,
			"start_time", stat.Starttime,
		)
		entry.threadStates = nil
		entry.startTime = stat.Starttime
	} else if wasUnreadable {
		c.logger.Debug("process is readable again", "pid", pid)
	}

	entry.state = stat.State
	entry.threads = stat.NumThreads
	entry.readable = true
	entry.lastSeen = gen
	return entry, identityChanged
}

// retainCachedProcess carries the last known state of an unreadable process
// into the aggregated counters and marks it as observed for the current scan
// generation. It does nothing for processes that have never been observed,
// because their identity cannot be verified while stat is unreadable.
func (c *processCollector) retainCachedProcess(pid int, gen uint64, result *processScan) {
	entry, ok := c.cache[pid]
	if !ok {
		return
	}
	entry.readable = false
	entry.lastSeen = gen
	result.pids++
	result.procStates[entry.state]++
	result.threads += entry.threads
	for state, count := range entry.threadStates {
		result.threadStates[state] += count
	}
}

// collectThreadStates enumerates the threads of one process and adds their
// states to out, refreshing the cached breakdown. The main thread reuses the
// already read process stat. Transient failures degrade gracefully:
//
//   - vanished task directories or thread stats are skipped,
//   - permission errors fall back to the cached breakdown for the same process
//     identity (never for a process that reused the PID this scrape),
//   - other errors abort the scrape.
func (c *processCollector) collectThreadStates(
	ctx context.Context,
	pid int,
	pidStat procfs.ProcStat,
	entry *cachedProcess,
	identityChanged bool,
	out map[string]int32,
) error {
	tasks, err := c.fs.AllThreads(pid)
	if err != nil {
		switch {
		case isProcessGoneError(err):
			c.logger.Debug("task directory vanished while scanning process", "pid", pid, "err", err)
			entry.threadStates = nil
			return nil
		case isPermissionDeniedError(err):
			c.logger.Debug("permission denied listing threads", "pid", pid, "err", err)
			// Only trust the cached breakdown when the identity behind the PID
			// did not change this scrape.
			if !identityChanged {
				for state, count := range entry.threadStates {
					out[state] += count
				}
			}
			return nil
		default:
			return fmt.Errorf("unable to list threads for pid %d: %w", pid, err)
		}
	}

	threadStates := make(map[string]int32, len(entry.threadStates))
	for i, task := range tasks {
		if i%cancelCheckInterval == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}

		if task.PID == pid {
			// The main thread's stat is the process stat already read above.
			threadStates[pidStat.State]++
			continue
		}

		threadStat, err := task.Stat()
		if err != nil {
			switch {
			case isProcessGoneError(err):
				c.logger.Debug("thread vanished before its stat could be read", "pid", pid, "tid", task.PID, "err", err)
				continue
			case isPermissionDeniedError(err):
				c.logger.Debug("permission denied reading thread stat", "pid", pid, "tid", task.PID, "err", err)
				continue
			default:
				return fmt.Errorf("error reading stat for pid %d thread %d: %w", pid, task.PID, err)
			}
		}
		threadStates[threadStat.State]++
	}

	entry.threadStates = threadStates
	for state, count := range threadStates {
		out[state] += count
	}
	return nil
}

// isProcessGoneError reports whether err indicates that a process or thread
// disappeared while it was being scanned. procfs wraps raw syscall errors in
// *os.PathError (matched via errors.Is), but older error strings may carry an
// ESRCH text without wrapping, so the message is inspected as well.
func isProcessGoneError(err error) bool {
	return errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, syscall.ESRCH) ||
		strings.Contains(err.Error(), syscall.ESRCH.Error())
}

// isPermissionDeniedError reports whether err is caused by a permission
// change, such as a hidepid mount or revoked credentials.
func isPermissionDeniedError(err error) bool {
	return errors.Is(err, os.ErrPermission) ||
		errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.EPERM)
}
