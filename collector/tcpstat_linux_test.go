// Copyright 2015 The Prometheus Authors
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

//go:build !notcpstat

package collector

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func encodeInetDiagMsg(t *testing.T, m InetDiagMsg) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.NativeEndian, m); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// metricSet collects the exported gauge values keyed by their "state" label.
func metricSet(t *testing.T, ch chan prometheus.Metric) map[string]float64 {
	t.Helper()
	close(ch)
	values := map[string]float64{}
	pb := &dto.Metric{}
	for m := range ch {
		pb.Reset()
		if err := m.Write(pb); err != nil {
			t.Fatalf("error writing metric: %v", err)
		}
		values[pb.Label[0].GetValue()] = pb.GetGauge().GetValue()
	}
	return values
}

// allStateLabels is the complete, stable set of series exported for a
// successfully scraped (possibly empty) socket table.
var allStateLabels = []string{
	"established", "syn_sent", "syn_recv", "fin_wait1", "fin_wait2",
	"time_wait", "close", "close_wait", "last_ack", "listen", "closing",
	"rx_queued_bytes", "tx_queued_bytes",
}

func Test_parseTCPStats(t *testing.T) {
	msgs := []netlink.Message{
		{
			Data: encodeInetDiagMsg(t, InetDiagMsg{
				Family: syscall.AF_INET,
				State:  uint8(tcpEstablished),
				RQueue: 11,
				WQueue: 21,
			}),
		},
		{
			Data: encodeInetDiagMsg(t, InetDiagMsg{
				Family: syscall.AF_INET,
				State:  uint8(tcpListen),
				RQueue: 11,
				WQueue: 21,
			}),
		},
	}

	tcpStats := parseTCPStats(msgs, syscall.AF_INET)

	if want, got := 1, int(tcpStats[tcpEstablished]); want != got {
		t.Errorf("want tcpstat number of established state %d, got %d", want, got)
	}
	if want, got := 1, int(tcpStats[tcpListen]); want != got {
		t.Errorf("want tcpstat number of listen state %d, got %d", want, got)
	}
	if want, got := 42, int(tcpStats[tcpTxQueuedBytes]); want != got {
		t.Errorf("want tcpstat number of bytes in tx queue %d, got %d", want, got)
	}
	if want, got := 22, int(tcpStats[tcpRxQueuedBytes]); want != got {
		t.Errorf("want tcpstat number of bytes in rx queue %d, got %d", want, got)
	}
}

// An AF_INET6 dump must not count IPv4 sockets. Some kernel versions and
// backports include AF_INET sockets in AF_INET6 dumps; truncated messages
// must be ignored instead of panicking.
func Test_parseTCPStats_familyFilter(t *testing.T) {
	msgs := []netlink.Message{
		{
			// Genuine IPv6 established socket.
			Data: encodeInetDiagMsg(t, InetDiagMsg{
				Family: syscall.AF_INET6,
				State:  uint8(tcpEstablished),
				RQueue: 11,
				WQueue: 21,
			}),
		},
		{
			// IPv4 socket showing up in the IPv6 dump: counting it here
			// would double count it against the AF_INET results.
			Data: encodeInetDiagMsg(t, InetDiagMsg{
				Family: syscall.AF_INET,
				State:  uint8(tcpListen),
				RQueue: 99,
				WQueue: 99,
			}),
		},
		{
			// Genuine IPv6 listen socket.
			Data: encodeInetDiagMsg(t, InetDiagMsg{
				Family: syscall.AF_INET6,
				State:  uint8(tcpListen),
				RQueue: 5,
				WQueue: 7,
			}),
		},
		{
			// Truncated message, shorter than the fixed inet_diag_msg.
			Data: []byte{syscall.AF_INET6, uint8(tcpEstablished), 0, 0},
		},
	}

	tcpStats := parseTCPStats(msgs, syscall.AF_INET6)

	if want, got := 1, int(tcpStats[tcpEstablished]); want != got {
		t.Errorf("want established state %d, got %d", want, got)
	}
	if want, got := 1, int(tcpStats[tcpListen]); want != got {
		t.Errorf("want listen state %d, got %d", want, got)
	}
	if want, got := 28, int(tcpStats[tcpTxQueuedBytes]); want != got {
		t.Errorf("want bytes in tx queue %d, got %d", want, got)
	}
	if want, got := 16, int(tcpStats[tcpRxQueuedBytes]); want != got {
		t.Errorf("want bytes in rx queue %d, got %d", want, got)
	}
}

// An empty table must still yield zero values for every known state instead
// of making the series disappear.
func Test_parseTCPStats_empty(t *testing.T) {
	tcpStats := parseTCPStats(nil, syscall.AF_INET)

	if want, got := len(allStateLabels), len(tcpStats); want != got {
		t.Fatalf("want %d pre-seeded states, got %d (%v)", want, got, tcpStats)
	}
	for _, label := range allStateLabels {
		found := false
		for st := range tcpStats {
			if st.String() == label {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing zero value for state %q", label)
		}
	}
}

const procTCPHeader = "  sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode"

func Test_parseTCPStatsFromProc(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		want      map[tcpConnectionState]float64
		malformed int
	}{
		{
			name: " populated table",
			content: procTCPHeader + "\n" +
				"   0: 00000000:0050 00000000:0000 0A 00000015:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 0 0\n" +
				"   1: 0100007F:1F90 0100007F:0050 01 0000000A:00000014 01:00000010 00000000     0        0 12346 1 0000000000000000 100 0 0 0 0\n" +
				"   2: 0100007F:1F91 0100007F:0050 06 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 100 0 0 0 0\n",
			want: map[tcpConnectionState]float64{
				tcpListen:        1,
				tcpEstablished:   1,
				tcpTimeWait:      1,
				tcpTxQueuedBytes: 31,
				tcpRxQueuedBytes: 20,
			},
		},
		{
			name:      "empty table with header only",
			content:   procTCPHeader + "\n",
			want:      map[tcpConnectionState]float64{},
			malformed: 0,
		},
		{
			name:    "completely empty file",
			content: "",
			want:    map[tcpConnectionState]float64{},
		},
		{
			name: "last line truncated mid-record without newline",
			content: procTCPHeader + "\n" +
				"   0: 00000000:0050 00000000:0000 0A 00000015:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 0 0\n" +
				"   1: 0100007F:1F90 0100007F:0050 01 0000000A:00000014 01:00000010 00000000     0        0 12346 1 0000000000000000 100 0 0 0 0\n" +
				"   2: 0100007F:1F9",
			want: map[tcpConnectionState]float64{
				tcpListen:        1,
				tcpEstablished:   1,
				tcpTxQueuedBytes: 31,
				tcpRxQueuedBytes: 20,
			},
			malformed: 1,
		},
		{
			name: "malformed line in the middle is skipped",
			content: procTCPHeader + "\n" +
				"   0: 00000000:0050 00000000:0000 0A 00000015:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 0 0\n" +
				"   broken line with not enough fields at all\n" +
				"   1: 0100007F:1F90 0100007F:0050 XX 0000000A:00000014 01:00000010 00000000     0        0 12346 1 0000000000000000 100 0 0 0 0\n" +
				"   2: 0100007F:1F91 0100007F:0050 01 xxxx:yyyy 00:00000000 00000000     0        0 12347 1 0000000000000000 100 0 0 0 0\n",
			want: map[tcpConnectionState]float64{
				tcpListen:        1,
				tcpTxQueuedBytes: 21,
			},
			malformed: 3,
		},
		{
			name: "unknown kernel state is kept under its raw value",
			content: procTCPHeader + "\n" +
				"   0: 00000000:0050 00000000:0000 0F 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 0 0\n",
			want: map[tcpConnectionState]float64{
				tcpConnectionState(0x0F): 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, malformed, err := parseTCPStatsFromProc(strings.NewReader(tt.content))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if malformed != tt.malformed {
				t.Errorf("want %d malformed lines, got %d", tt.malformed, malformed)
			}
			for st, want := range tt.want {
				if got[st] != want {
					t.Errorf("state %d (%s): want %v, got %v", st, st.String(), want, got[st])
				}
			}
			// Every parse result must contain all zero-seeded known states.
			for _, st := range []tcpConnectionState{
				tcpEstablished, tcpSynSent, tcpSynRecv, tcpFinWait1, tcpFinWait2,
				tcpTimeWait, tcpClose, tcpCloseWait, tcpLastAck, tcpListen, tcpClosing,
				tcpRxQueuedBytes, tcpTxQueuedBytes,
			} {
				if _, ok := got[st]; !ok {
					t.Errorf("missing pre-seeded state %q", st.String())
				}
			}
		})
	}
}

// getTCPStatsFromProc must surface a missing file as os.ErrNotExist so the
// caller can distinguish "unsupported family" from a real failure.
func Test_getTCPStatsFromProc_missingFile(t *testing.T) {
	withTempProcPath(t, func() {
		if _, err := getTCPStatsFromProc(syscall.AF_INET, testLogger()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("want os.ErrNotExist, got %v", err)
		}
	})
}

// Permission denied (or any other primary-source failure) must trigger the
// /proc fallback without swallowing the fallback's error.
func Test_getTCPStatsWithFallback(t *testing.T) {
	t.Run("primary denied uses fallback", func(t *testing.T) {
		primaryCalls, fallbackCalls := 0, 0
		fallbackStats := newTCPStats()
		fallbackStats[tcpEstablished] = 7

		stats, err := getTCPStatsWithFallback(syscall.AF_INET, testLogger(),
			func() (map[tcpConnectionState]float64, error) {
				primaryCalls++
				return nil, syscall.EPERM
			},
			func() (map[tcpConnectionState]float64, error) {
				fallbackCalls++
				return fallbackStats, nil
			},
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if primaryCalls != 1 || fallbackCalls != 1 {
			t.Errorf("want primary/fallback called once each, got %d/%d", primaryCalls, fallbackCalls)
		}
		if got := stats[tcpEstablished]; got != 7 {
			t.Errorf("want fallback established count 7, got %v", got)
		}
	})

	t.Run("primary success skips fallback", func(t *testing.T) {
		fallbackCalls := 0
		primaryStats := newTCPStats()
		primaryStats[tcpListen] = 2

		stats, err := getTCPStatsWithFallback(syscall.AF_INET, testLogger(),
			func() (map[tcpConnectionState]float64, error) {
				return primaryStats, nil
			},
			func() (map[tcpConnectionState]float64, error) {
				fallbackCalls++
				return nil, nil
			},
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if fallbackCalls != 0 {
			t.Errorf("fallback must not be called, got %d calls", fallbackCalls)
		}
		if got := stats[tcpListen]; got != 2 {
			t.Errorf("want listen count 2, got %v", got)
		}
	})

	t.Run("both sources fail", func(t *testing.T) {
		_, err := getTCPStatsWithFallback(syscall.AF_INET, testLogger(),
			func() (map[tcpConnectionState]float64, error) {
				return nil, syscall.EACCES
			},
			func() (map[tcpConnectionState]float64, error) {
				return nil, syscall.ENOENT
			},
		)
		if !errors.Is(err, syscall.ENOENT) {
			t.Fatalf("want fallback error syscall.ENOENT, got %v", err)
		}
	})
}

// fakeTCPGatherer returns canned per-family statistics and records the
// families it was asked for.
type fakeTCPGatherer struct {
	stats map[uint8]map[tcpConnectionState]float64
	errs  map[uint8]error
	mu    sync.Mutex
	calls []uint8
}

func (f *fakeTCPGatherer) gather(family uint8) (map[tcpConnectionState]float64, error) {
	f.mu.Lock()
	f.calls = append(f.calls, family)
	f.mu.Unlock()
	if err := f.errs[family]; err != nil {
		return nil, err
	}
	// Every real read (netlink or /proc) returns a freshly allocated map;
	// return a copy so concurrent scrapes never share mutable state.
	stats := newTCPStats()
	mergeTCPStats(stats, f.stats[family])
	return stats, nil
}

func statsMap(pairs ...any) map[tcpConnectionState]float64 {
	m := newTCPStats()
	for i := 0; i < len(pairs); i += 2 {
		m[pairs[i].(tcpConnectionState)] = pairs[i+1].(float64)
	}
	return m
}

func Test_tcpStatCollector_collect(t *testing.T) {
	tests := []struct {
		name       string
		hasIPv6    bool
		gatherer   *fakeTCPGatherer
		wantErr    bool
		wantValues map[string]float64
	}{
		{
			name:    "ipv4 and ipv6 are added without duplication",
			hasIPv6: true,
			gatherer: &fakeTCPGatherer{
				stats: map[uint8]map[tcpConnectionState]float64{
					syscall.AF_INET:  statsMap(tcpEstablished, 2.0, tcpListen, 1.0, tcpTxQueuedBytes, 10.0),
					syscall.AF_INET6: statsMap(tcpEstablished, 3.0, tcpClosing, 1.0, tcpTxQueuedBytes, 4.0),
				},
			},
			wantValues: map[string]float64{
				"established":     5,
				"listen":          1,
				"closing":         1,
				"tx_queued_bytes": 14,
				"rx_queued_bytes": 0,
				"syn_sent":        0,
			},
		},
		{
			name:    "ipv4 permission denied only affects ipv4 metrics",
			hasIPv6: true,
			gatherer: &fakeTCPGatherer{
				stats: map[uint8]map[tcpConnectionState]float64{
					syscall.AF_INET6: statsMap(tcpEstablished, 3.0),
				},
				errs: map[uint8]error{
					syscall.AF_INET: syscall.EPERM,
				},
			},
			wantValues: map[string]float64{
				"established": 3,
				"listen":      0,
			},
		},
		{
			name:    "ipv6 failure only affects ipv6 metrics",
			hasIPv6: true,
			gatherer: &fakeTCPGatherer{
				stats: map[uint8]map[tcpConnectionState]float64{
					syscall.AF_INET: statsMap(tcpEstablished, 2.0),
				},
				errs: map[uint8]error{
					syscall.AF_INET6: errors.New("netlink dump interrupted"),
				},
			},
			wantValues: map[string]float64{
				"established": 2,
				"closing":     0,
			},
		},
		{
			name:    "kernel without ipv6 skips ipv6 silently",
			hasIPv6: false,
			gatherer: &fakeTCPGatherer{
				stats: map[uint8]map[tcpConnectionState]float64{
					syscall.AF_INET: statsMap(tcpTimeWait, 4.0),
				},
			},
			wantValues: map[string]float64{
				"time_wait": 4,
			},
		},
		{
			name:    "both families fail surfaces an error",
			hasIPv6: true,
			gatherer: &fakeTCPGatherer{
				stats: map[uint8]map[tcpConnectionState]float64{},
				errs: map[uint8]error{
					syscall.AF_INET:  syscall.EACCES,
					syscall.AF_INET6: syscall.EACCES,
				},
			},
			wantErr: true,
		},
		{
			name:    "empty tables export zeroes",
			hasIPv6: true,
			gatherer: &fakeTCPGatherer{
				stats: map[uint8]map[tcpConnectionState]float64{
					syscall.AF_INET:  newTCPStats(),
					syscall.AF_INET6: newTCPStats(),
				},
			},
			wantValues: map[string]float64{
				"established":     0,
				"time_wait":       0,
				"tx_queued_bytes": 0,
				"rx_queued_bytes": 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withTempProcPath(t, func() {
				if tt.hasIPv6 {
					writeProcFile(t, "net/tcp6", procTCPHeader+"\n")
				}

				c, err := NewTCPStatCollector(testLogger())
				if err != nil {
					t.Fatal(err)
				}

				ch := make(chan prometheus.Metric, 32)
				collectErr := c.(*tcpStatCollector).collect(ch, tt.gatherer.gather)
				if tt.wantErr {
					if collectErr == nil {
						t.Fatal("want error, got nil")
					}
					if len(ch) != 0 {
						t.Fatalf("want no metrics on total failure, got %d", len(ch))
					}
					return
				}
				if collectErr != nil {
					t.Fatalf("unexpected error: %v", collectErr)
				}

				values := metricSet(t, ch)
				if len(values) != len(allStateLabels) {
					t.Errorf("want %d series, got %d (%v)", len(allStateLabels), len(values), values)
				}
				for label, want := range tt.wantValues {
					if got := values[label]; got != want {
						t.Errorf("metric %q: want %v, got %v", label, want, got)
					}
				}
			})
		})
	}
}

// Many concurrent scrapes against the same collector must not race or
// corrupt each other's counters. Run with -race.
func Test_tcpStatCollector_concurrentScrapes(t *testing.T) {
	withTempProcPath(t, func() {
		writeProcFile(t, "net/tcp6", procTCPHeader+"\n")

		c, err := NewTCPStatCollector(testLogger())
		if err != nil {
			t.Fatal(err)
		}
		tc := c.(*tcpStatCollector)

		gatherer := &fakeTCPGatherer{
			stats: map[uint8]map[tcpConnectionState]float64{
				syscall.AF_INET:  statsMap(tcpEstablished, 2.0, tcpListen, 1.0, tcpTxQueuedBytes, 10.0, tcpRxQueuedBytes, 3.0),
				syscall.AF_INET6: statsMap(tcpEstablished, 4.0, tcpTimeWait, 5.0, tcpTxQueuedBytes, 6.0, tcpRxQueuedBytes, 7.0),
			},
		}

		const goroutines, iterations = 64, 100
		var wg sync.WaitGroup
		for range goroutines {
			wg.Go(func() {
				for range iterations {
					ch := make(chan prometheus.Metric, 32)
					if err := tc.collect(ch, gatherer.gather); err != nil {
						t.Errorf("unexpected collect error: %v", err)
						return
					}
					values := metricSet(t, ch)
					for label, want := range map[string]float64{
						"established":     6,
						"listen":          1,
						"time_wait":       5,
						"tx_queued_bytes": 16,
						"rx_queued_bytes": 10,
					} {
						if values[label] != want {
							t.Errorf("metric %q: want %v, got %v", label, want, values[label])
							return
						}
					}
				}
			})
		}
		wg.Wait()
	})
}

// Concurrent parsing of the same proc content must be safe.
func Test_parseTCPStatsFromProc_concurrent(t *testing.T) {
	content := procTCPHeader + "\n" +
		"   0: 00000000:0050 00000000:0000 0A 00000015:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 0 0\n" +
		"   1: 0100007F:1F90 0100007F:0050 01 0000000A:00000014 01:00000010 00000000     0        0 12346 1 0000000000000000 100 0 0 0 0\n"

	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 100 {
				stats, malformed, err := parseTCPStatsFromProc(strings.NewReader(content))
				if err != nil || malformed != 0 {
					t.Errorf("unexpected err=%v malformed=%d", err, malformed)
					return
				}
				if stats[tcpListen] != 1 || stats[tcpEstablished] != 1 ||
					stats[tcpTxQueuedBytes] != 31 || stats[tcpRxQueuedBytes] != 20 {
					t.Errorf("unexpected stats: %v", stats)
					return
				}
			}
		})
	}
	wg.Wait()
}

func withTempProcPath(t *testing.T, fn func()) {
	t.Helper()
	dir := t.TempDir()
	oldProcPath := *procPath
	*procPath = dir
	t.Cleanup(func() { *procPath = oldProcPath })
	fn()
}

func writeProcFile(t *testing.T, name, content string) {
	t.Helper()
	path := filepath.Join(*procPath, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
