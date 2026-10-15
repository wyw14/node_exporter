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
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/mdlayher/netlink"
	"github.com/prometheus/client_golang/prometheus"
)

type tcpConnectionState int

const (
	// TCP_ESTABLISHED
	tcpEstablished tcpConnectionState = iota + 1
	// TCP_SYN_SENT
	tcpSynSent
	// TCP_SYN_RECV
	tcpSynRecv
	// TCP_FIN_WAIT1
	tcpFinWait1
	// TCP_FIN_WAIT2
	tcpFinWait2
	// TCP_TIME_WAIT
	tcpTimeWait
	// TCP_CLOSE
	tcpClose
	// TCP_CLOSE_WAIT
	tcpCloseWait
	// TCP_LAST_ACK
	tcpLastAck
	// TCP_LISTEN
	tcpListen
	// TCP_CLOSING
	tcpClosing
	// TCP_RX_BUFFER
	tcpRxQueuedBytes
	// TCP_TX_BUFFER
	tcpTxQueuedBytes
)

type tcpStatCollector struct {
	desc   typedDesc
	logger *slog.Logger
}

func init() {
	registerCollector("tcpstat", defaultDisabled, NewTCPStatCollector)
}

// NewTCPStatCollector returns a new Collector exposing network stats.
func NewTCPStatCollector(logger *slog.Logger) (Collector, error) {
	return &tcpStatCollector{
		desc: typedDesc{prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "tcp", "connection_states"),
			"Number of connection states.",
			[]string{"state"}, nil,
		), prometheus.GaugeValue},
		logger: logger,
	}, nil
}

// InetDiagSockID (inet_diag_sockid) contains the socket identity.
// https://github.com/torvalds/linux/blob/v4.0/include/uapi/linux/inet_diag.h#L13
type InetDiagSockID struct {
	SourcePort [2]byte
	DestPort   [2]byte
	SourceIP   [4][4]byte
	DestIP     [4][4]byte
	Interface  uint32
	Cookie     [2]uint32
}

// InetDiagReqV2 (inet_diag_req_v2) is used to request diagnostic data.
// https://github.com/torvalds/linux/blob/v4.0/include/uapi/linux/inet_diag.h#L37
type InetDiagReqV2 struct {
	Family   uint8
	Protocol uint8
	Ext      uint8
	Pad      uint8
	States   uint32
	ID       InetDiagSockID
}

const sizeOfDiagRequest = 0x38

func (req *InetDiagReqV2) Serialize() []byte {
	return (*(*[sizeOfDiagRequest]byte)(unsafe.Pointer(req)))[:]
}

func (req *InetDiagReqV2) Len() int {
	return sizeOfDiagRequest
}

type InetDiagMsg struct {
	Family  uint8
	State   uint8
	Timer   uint8
	Retrans uint8
	ID      InetDiagSockID
	Expires uint32
	RQueue  uint32
	WQueue  uint32
	UID     uint32
	Inode   uint32
}

// sizeOfDiagMsg is the size of the fixed part of an inet_diag_msg reply.
// Netlink attributes may follow, but they are ignored here.
const sizeOfDiagMsg = unsafe.Sizeof(InetDiagMsg{})

// parseInetDiagMsg decodes a single inet_diag_msg. It returns nil for
// messages that are too short to hold the fixed header, e.g. truncated
// replies from old or non-conformant kernels.
func parseInetDiagMsg(b []byte) *InetDiagMsg {
	if uintptr(len(b)) < sizeOfDiagMsg {
		return nil
	}
	return (*InetDiagMsg)(unsafe.Pointer(&b[0]))
}

// tcpStatsFunc returns the TCP statistics of a single address family.
type tcpStatsFunc func() (map[tcpConnectionState]float64, error)

func (c *tcpStatCollector) Update(ch chan<- prometheus.Metric) error {
	return c.collect(ch, func(family uint8) (map[tcpConnectionState]float64, error) {
		return getTCPStats(family, c.logger)
	})
}

// collect gathers IPv4 and, when the kernel supports it, IPv6 TCP statistics
// independently: a failure to read one family only drops that family's
// contribution, the other family is still scraped and exported. The gather
// function is injected so the data sources can be replaced in tests.
func (c *tcpStatCollector) collect(ch chan<- prometheus.Metric, gather func(uint8) (map[tcpConnectionState]float64, error)) error {
	var errs []error
	familiesSucceeded := 0

	tcpStats, err := gather(syscall.AF_INET)
	if err != nil {
		c.logger.Warn("couldn't get IPv4 TCP statistics", "err", err)
		errs = append(errs, fmt.Errorf("ipv4: %w", err))
		tcpStats = newTCPStats()
	} else {
		familiesSucceeded++
	}

	// Only query IPv6 if the kernel exposes /proc/net/tcp6. A missing
	// file means IPv6 is disabled or not built into the kernel, which is
	// not a scrape failure. A stat error (e.g. permission denied) keeps
	// the historical behavior of skipping IPv6.
	if _, err := os.Stat(procFilePath("net/tcp6")); err == nil {
		tcp6Stats, err := gather(syscall.AF_INET6)
		if err != nil {
			c.logger.Warn("couldn't get IPv6 TCP statistics", "err", err)
			errs = append(errs, fmt.Errorf("ipv6: %w", err))
		} else {
			familiesSucceeded++
			mergeTCPStats(tcpStats, tcp6Stats)
		}
	} else {
		c.logger.Debug("IPv6 not available, not collecting IPv6 TCP statistics", "err", err)
	}

	// Every family failed (or IPv6 is unavailable and IPv4 failed): there
	// is nothing meaningful to export, surface the error to the scraper.
	if familiesSucceeded == 0 {
		return errors.Join(errs...)
	}

	// Export all known states, including zeroes for empty socket tables,
	// so metrics keep being emitted with value 0 instead of disappearing.
	for st, value := range tcpStats {
		ch <- c.desc.mustNewConstMetric(value, st.String())
	}

	return nil
}

// getTCPStats returns TCP statistics for the given address family. The
// inet_diag netlink interface is preferred; on kernels too old to provide
// SOCK_DIAG_BY_FAMILY (before Linux 3.3) or when the netlink socket is
// blocked (e.g. seccomp or a missing capability returns EPERM/EACCES), it
// transparently falls back to parsing /proc/net/tcp{,6}, which is
// world-readable and available on every supported kernel. Note that for
// listening sockets inet_diag reports the accept backlog in the queue
// fields while /proc reports zero there; state counts are identical.
func getTCPStats(family uint8, logger *slog.Logger) (map[tcpConnectionState]float64, error) {
	return getTCPStatsWithFallback(family, logger,
		func() (map[tcpConnectionState]float64, error) {
			return getTCPStatsFromNetlink(family)
		},
		func() (map[tcpConnectionState]float64, error) {
			return getTCPStatsFromProc(family, logger)
		},
	)
}

// getTCPStatsWithFallback runs the primary source and only uses the fallback
// when the primary one failed. Errors are not swallowed: the caller decides
// how a failure of both sources is handled.
func getTCPStatsWithFallback(family uint8, logger *slog.Logger, primary, fallback tcpStatsFunc) (map[tcpConnectionState]float64, error) {
	stats, err := primary()
	if err == nil {
		return stats, nil
	}

	logger.Debug("inet_diag netlink request failed, falling back to /proc/net/tcp",
		"family", tcpFamilyName(family), "err", err)
	return fallback()
}

// newTCPStats returns a result map pre-seeded with every known state and
// queue counter at zero so that empty tables still export a stable,
// complete metric set.
func newTCPStats() map[tcpConnectionState]float64 {
	return map[tcpConnectionState]float64{
		tcpEstablished:   0,
		tcpSynSent:       0,
		tcpSynRecv:       0,
		tcpFinWait1:      0,
		tcpFinWait2:      0,
		tcpTimeWait:      0,
		tcpClose:         0,
		tcpCloseWait:     0,
		tcpLastAck:       0,
		tcpListen:        0,
		tcpClosing:       0,
		tcpRxQueuedBytes: 0,
		tcpTxQueuedBytes: 0,
	}
}

// mergeTCPStats adds the statistics of one family into the aggregated map.
// Each source only counts sockets matching the requested address family,
// so a socket is counted exactly once even on dual-stack systems.
func mergeTCPStats(dst, src map[tcpConnectionState]float64) {
	for st, value := range src {
		dst[st] += value
	}
}

func getTCPStatsFromNetlink(family uint8) (map[tcpConnectionState]float64, error) {
	const TCPFAll = 0xFFF
	const InetDiagInfo = 2
	const SockDiagByFamily = 20

	conn, err := netlink.Dial(syscall.NETLINK_INET_DIAG, nil)
	if err != nil {
		return nil, fmt.Errorf("couldn't connect netlink: %w", err)
	}
	defer conn.Close()

	msg := netlink.Message{
		Header: netlink.Header{
			Type:  SockDiagByFamily,
			Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_DUMP,
		},
		Data: (&InetDiagReqV2{
			Family:   family,
			Protocol: syscall.IPPROTO_TCP,
			States:   TCPFAll,
			Ext:      0 | 1<<(InetDiagInfo-1),
		}).Serialize(),
	}

	messages, err := conn.Execute(msg)
	if err != nil {
		return nil, err
	}

	return parseTCPStats(messages, family), nil
}

// parseTCPStats converts inet_diag_msg replies into state and queue
// counters. Only sockets matching the requested family are counted. This is
// a no-op on spec-conformant kernels (SOCK_DIAG_BY_FAMILY exact-filters
// since Linux 3.3), but prevents IPv4/IPv6 double counting on older,
// vendor or backported kernels whose AF_INET6 dump also reports IPv4
// sockets, and ignores stray replies of another family. Truncated messages
// shorter than the fixed header are skipped as well.
func parseTCPStats(msgs []netlink.Message, family uint8) map[tcpConnectionState]float64 {
	tcpStats := newTCPStats()

	for _, m := range msgs {
		msg := parseInetDiagMsg(m.Data)
		if msg == nil {
			continue
		}
		if msg.Family != family {
			continue
		}

		tcpStats[tcpTxQueuedBytes] += float64(msg.WQueue)
		tcpStats[tcpRxQueuedBytes] += float64(msg.RQueue)
		tcpStats[tcpConnectionState(msg.State)]++
	}

	return tcpStats
}

// getTCPStatsFromProc reads /proc/net/tcp (IPv4) or /proc/net/tcp6 (IPv6).
// These files are world-readable, making them a reliable fallback when
// inet_diag is unavailable or denied.
func getTCPStatsFromProc(family uint8, logger *slog.Logger) (map[tcpConnectionState]float64, error) {
	name := "net/tcp"
	if family == syscall.AF_INET6 {
		name = "net/tcp6"
	}

	file, err := os.Open(procFilePath(name))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	tcpStats, malformed, err := parseTCPStatsFromProc(file)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse %s: %w", name, err)
	}
	if malformed > 0 {
		// /proc files can be truncated or change while they are read
		// (sockets appearing/disappearing during a scrape); complete
		// records remain usable, only the cut-off line is dropped.
		logger.Debug("ignored malformed or truncated lines while parsing proc file",
			"file", name, "lines", malformed)
	}

	return tcpStats, nil
}

// parseTCPStatsFromProc parses the socket table exposed by
// /proc/net/tcp{,6}. The first line holds the column header and is
// skipped. Lines that are truncated or otherwise malformed are skipped
// instead of aborting the whole read; only actual read errors are
// returned. The second return value reports how many lines were skipped.
//
// Column layout (see Linux Documentation/networking/proc_net_tcp.rst):
//
//	sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
func parseTCPStatsFromProc(r io.Reader) (map[tcpConnectionState]float64, int, error) {
	tcpStats := newTCPStats()
	malformed := 0

	// Lines in /proc/net/tcp are short, but allow generous headroom for
	// unusually long token sequences.
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 512), 1024*1024)

	// Skip the header line. An empty file (no header at all) is treated
	// as an empty socket table rather than an error.
	if !scanner.Scan() {
		return tcpStats, 0, scanner.Err()
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			malformed++
			continue
		}

		state, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			malformed++
			continue
		}

		txQueue, rxQueue, err := parseProcTCPQueues(fields[4])
		if err != nil {
			malformed++
			continue
		}

		tcpStats[tcpTxQueuedBytes] += float64(txQueue)
		tcpStats[tcpRxQueuedBytes] += float64(rxQueue)
		tcpStats[tcpConnectionState(state)]++
	}

	if err := scanner.Err(); err != nil {
		return nil, malformed, err
	}

	return tcpStats, malformed, nil
}

// parseProcTCPQueues parses the "tx_queue:rx_queue" column, two hexadecimal
// numbers separated by a colon.
func parseProcTCPQueues(field string) (txQueue, rxQueue uint64, err error) {
	queues := strings.Split(field, ":")
	if len(queues) != 2 {
		return 0, 0, fmt.Errorf("missing colon in queue field %q", field)
	}
	if txQueue, err = strconv.ParseUint(queues[0], 16, 64); err != nil {
		return 0, 0, err
	}
	if rxQueue, err = strconv.ParseUint(queues[1], 16, 64); err != nil {
		return 0, 0, err
	}
	return txQueue, rxQueue, nil
}

func tcpFamilyName(family uint8) string {
	switch family {
	case syscall.AF_INET:
		return "ipv4"
	case syscall.AF_INET6:
		return "ipv6"
	default:
		return strconv.Itoa(int(family))
	}
}

func (st tcpConnectionState) String() string {
	switch st {
	case tcpEstablished:
		return "established"
	case tcpSynSent:
		return "syn_sent"
	case tcpSynRecv:
		return "syn_recv"
	case tcpFinWait1:
		return "fin_wait1"
	case tcpFinWait2:
		return "fin_wait2"
	case tcpTimeWait:
		return "time_wait"
	case tcpClose:
		return "close"
	case tcpCloseWait:
		return "close_wait"
	case tcpLastAck:
		return "last_ack"
	case tcpListen:
		return "listen"
	case tcpClosing:
		return "closing"
	case tcpRxQueuedBytes:
		return "rx_queued_bytes"
	case tcpTxQueuedBytes:
		return "tx_queued_bytes"
	default:
		return "unknown"
	}
}
