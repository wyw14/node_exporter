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

//go:build !nofilesystem

package collector

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"golang.org/x/sys/unix"

	"github.com/prometheus/procfs"
)

const (
	defMountPointsExcluded = "^/(dev|proc|run/credentials/.+|sys|var/lib/docker/.+|var/lib/containers/storage/.+)($|/)"
	// efivarfs and ramfs are pseudo filesystems without usable capacity
	// information (ramfs is in particular used for /run/credentials on modern
	// systemd and other API/pin mounts in containers).
	defFSTypesExcluded = "^(autofs|binfmt_misc|bpf|cgroup2?|configfs|debugfs|devpts|devtmpfs|efivarfs|fusectl|hugetlbfs|iso9660|mqueue|nsfs|overlay|proc|procfs|pstore|ramfs|rpc_pipefs|securityfs|selinuxfs|squashfs|erofs|sysfs|tracefs)$"
)

const (
	defaultMountTimeout = 5 * time.Second
)

var mountTimeout = kingpin.Flag("collector.filesystem.mount-timeout",
	"how long to wait for a mount to respond before marking it as stale").
	Hidden().Default(defaultMountTimeout.String()).Duration()

var statWorkerCount = kingpin.Flag("collector.filesystem.stat-workers",
	"how many stat calls to process simultaneously").
	Hidden().Default("4").Int()

// Stable values for the device_error label; they must not contain variable
// information (such as raw OS error strings) so that label sets stay stable
// across scrapes.
const (
	deviceErrorStatfsFailed = "statfs error"
	deviceErrorMountTimeout = "mountpoint timeout"
)

var (
	stuckMounts    = make(map[string]struct{})
	stuckMountsMtx = &sync.Mutex{}
)

// GetStats returns filesystem stats.
func (c *filesystemCollector) GetStats() ([]filesystemStats, error) {
	mps, err := mountPointDetails(c.logger)
	if err != nil {
		return nil, err
	}

	workerCount := max(*statWorkerCount, 1)
	// The channels are sized to the complete mount list so that neither the
	// feeder nor a worker can block on a slow consumer or on a mount that is
	// stuck in an uninterruptible statfs call.
	labelChan := make(chan filesystemLabels, len(mps))
	statChan := make(chan filesystemStats, len(mps))
	wg := sync.WaitGroup{}

	for range workerCount {
		wg.Go(func() {
			for labels := range labelChan {
				if stat, ok := c.processStat(labels); ok {
					statChan <- stat
				}
			}
		})
	}

	// A single orchestrator goroutine feeds the workers, emits results for
	// mounts already known to be stuck and closes statChan only after every
	// worker has finished. All stats travel through statChan; the stats slice
	// is assembled by this (single) goroutine, which keeps GetStats safe for
	// concurrent scrapes.
	go func() {
		defer func() {
			close(labelChan)
			wg.Wait()
			close(statChan)
		}()

		for _, labels := range mps {
			if c.mountPointFilter.ignored(labels.mountPoint) {
				c.logger.Debug("Ignoring mount point", "mountpoint", labels.mountPoint)
				continue
			}
			if c.fsTypeFilter.ignored(labels.fsType) {
				c.logger.Debug("Ignoring fs type", "type", labels.fsType)
				continue
			}

			if mountPointIsStuck(labels.mountPoint) {
				// Match the label set produced by processStat(): options are
				// dropped and device_error uses a stable token.
				labels.mountOptions = ""
				labels.superOptions = ""
				labels.deviceError = deviceErrorMountTimeout
				statChan <- filesystemStats{
					labels:      labels,
					deviceError: 1,
				}
				c.logger.Debug("Mount point is in an unresponsive state", "mountpoint", labels.mountPoint)
				continue
			}

			labelChan <- labels
		}
	}()

	stats := []filesystemStats{}
	for stat := range statChan {
		stats = append(stats, stat)
	}
	return stats, nil
}

// processStat collects the statistics for a single mount point.
//
// It returns false (and no stats) when the mount disappears between reading
// mountinfo and the statfs call, so that such mounts do not produce flapping
// time series. A statfs call that does not return within
// --collector.filesystem.mount-timeout is reported with a device_error metric
// and the mount is marked as stuck instead of blocking the whole scrape.
func (c *filesystemCollector) processStat(labels filesystemLabels) (filesystemStats, bool) {
	var ro float64
	if isFilesystemReadOnly(labels) {
		ro = 1
	}

	// Options are only needed for the read-only check above. Drop them before
	// metrics are built so repeated mountinfo entries for the same mount (a
	// common sight with bind-mount propagation into containers) collapse into
	// a single, stable label set.
	labels.mountOptions = ""
	labels.superOptions = ""

	path := rootfsFilePath(labels.mountPoint)

	type statfsResult struct {
		buf *unix.Statfs_t
		err error
	}
	// The channel is buffered: when this scrape times out and moves on, the
	// goroutine below must still be able to deliver a result that arrives
	// later (a statfs call against an unreachable NFS export can remain blocked
	// in the kernel indefinitely; Go cannot cancel a running syscall).
	done := make(chan statfsResult, 1)
	go func() {
		buf := new(unix.Statfs_t)
		err := unix.Statfs(path, buf)
		done <- statfsResult{buf: buf, err: err}
		// If this scrape already gave up but statfs eventually succeeds, the
		// mount has recovered. Unmark it so monitoring resumes automatically.
		if err == nil {
			clearStuckMount(labels.mountPoint, c.logger)
		}
	}()

	// Guard against a zero duration (e.g. flags not parsed in embedded
	// usage): NewTimer(0) fires immediately and would label every mount
	// stuck.
	timeout := *mountTimeout
	if timeout <= 0 {
		timeout = defaultMountTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	var result statfsResult
	select {
	case result = <-done:
	case <-timer.C:
		// statfs may have completed right after the timeout fired; re-check
		// before declaring the mount stuck.
		select {
		case result = <-done:
		default:
			markStuckMount(labels.mountPoint, c.logger)
			labels.deviceError = deviceErrorMountTimeout
			return filesystemStats{
				labels:      labels,
				deviceError: 1,
				ro:          ro,
			}, true
		}
	}

	if result.err != nil {
		if errors.Is(result.err, os.ErrNotExist) {
			// The mount point vanished (or is no longer reachable as a path)
			// between reading mountinfo and calling statfs. Skip it instead
			// of emitting a device_error series that disappears on the next
			// scrape.
			c.logger.Debug("Mount point disappeared before statfs()", "mountpoint", labels.mountPoint, "path", path, "err", result.err)
			return filesystemStats{}, false
		}
		// Keep the label value stable; the concrete error text is logged at
		// debug level instead of becoming part of the metric label set.
		labels.deviceError = deviceErrorStatfsFailed
		c.logger.Debug("Error on statfs() system call", "rootfs", path, "err", result.err)
		return filesystemStats{
			labels:      labels,
			deviceError: 1,
			ro:          ro,
		}, true
	}

	// A successful statfs alone does not prove the mount still exists: when a
	// mount is detached while its directory remains, statfs silently reports
	// the statistics of the parent filesystem. Cross-check the device number
	// of the mount point against the major:minor pair from mountinfo.
	if !mountDeviceStillMatches(c.logger, path, labels.major, labels.minor) {
		c.logger.Debug("Mount point disappeared after statfs()", "mountpoint", labels.mountPoint, "path", path)
		return filesystemStats{}, false
	}

	return filesystemStats{
		labels:    labels,
		size:      float64(result.buf.Blocks) * float64(result.buf.Bsize),
		free:      float64(result.buf.Bfree) * float64(result.buf.Bsize),
		avail:     float64(result.buf.Bavail) * float64(result.buf.Bsize),
		files:     float64(result.buf.Files),
		filesFree: float64(result.buf.Ffree),
		ro:        ro,
	}, true
}

func mountPointIsStuck(mountPoint string) bool {
	stuckMountsMtx.Lock()
	defer stuckMountsMtx.Unlock()
	_, ok := stuckMounts[mountPoint]
	return ok
}

func markStuckMount(mountPoint string, logger *slog.Logger) {
	stuckMountsMtx.Lock()
	defer stuckMountsMtx.Unlock()
	if _, ok := stuckMounts[mountPoint]; !ok {
		logger.Debug("Mount point timed out, it is being labeled as stuck and will not be monitored", "mountpoint", mountPoint)
		stuckMounts[mountPoint] = struct{}{}
	}
}

func clearStuckMount(mountPoint string, logger *slog.Logger) {
	stuckMountsMtx.Lock()
	defer stuckMountsMtx.Unlock()
	if _, ok := stuckMounts[mountPoint]; ok {
		logger.Debug("Mount point has recovered, monitoring will resume", "mountpoint", mountPoint)
		delete(stuckMounts, mountPoint)
	}
}

// mountDeviceStillMatches verifies that the device number of the mount point
// on disk still matches the major:minor pair reported by mountinfo. This
// detects mounts that disappeared after mountinfo was read but whose
// directory remains, in which case statfs would return the parent
// filesystem's statistics.
func mountDeviceStillMatches(logger *slog.Logger, path, major, minor string) bool {
	wantMajor, errMajor := strconv.Atoi(major)
	wantMinor, errMinor := strconv.Atoi(minor)
	if errMajor != nil || errMinor != nil {
		// Unknown identity from mountinfo: do not suppress metrics on a guess.
		return true
	}

	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false
		}
		// A verification failure must not hide real capacity metrics.
		logger.Debug("Failed to verify mount device identity", "path", path, "err", err)
		return true
	}

	return int(unix.Major(st.Dev)) == wantMajor && int(unix.Minor(st.Dev)) == wantMinor
}

func mountPointDetails(logger *slog.Logger) ([]filesystemLabels, error) {
	fs, err := procfs.NewFS(*procPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open procfs: %w", err)
	}
	mountInfo, err := fs.GetProcMounts(1)
	if err != nil {
		// Fallback to `/proc/self/mountinfo` whenever `/proc/1/mountinfo`
		// cannot be read. Besides hidepid returning ENOENT, locked-down setups
		// may deny access with EACCES and containers may not share PID 1's
		// mount namespace; in all these cases our own mount table is the
		// meaningful one to collect.
		logger.Debug("Reading root (PID 1) mounts failed, falling back to self mounts", "err", err)
		mountInfo, err = fs.GetMounts()
	}
	if err != nil {
		return nil, err
	}

	return parseFilesystemLabels(mountInfo)
}

func parseFilesystemLabels(mountInfo []*procfs.MountInfo) ([]filesystemLabels, error) {
	var filesystems []filesystemLabels

	for _, mount := range mountInfo {
		major, minor := 0, 0
		_, err := fmt.Sscanf(mount.MajorMinorVer, "%d:%d", &major, &minor)
		if err != nil {
			return nil, fmt.Errorf("malformed mount point MajorMinorVer: %q", mount.MajorMinorVer)
		}

		// Ensure we handle the translation of \040 and \011
		// as per fstab(5).
		mount.MountPoint = strings.ReplaceAll(mount.MountPoint, "\\040", " ")
		mount.MountPoint = strings.ReplaceAll(mount.MountPoint, "\\011", "\t")

		filesystems = append(filesystems, filesystemLabels{
			device:       canonicalizeDevice(strings.ToValidUTF8(mount.Source, "�"), *rootfsPath),
			mountPoint:   strings.ToValidUTF8(rootfsStripPrefix(mount.MountPoint), "�"),
			fsType:       strings.ToValidUTF8(mount.FSType, "�"),
			mountOptions: mountOptionsString(mount.Options),
			superOptions: mountOptionsString(mount.SuperOptions),
			major:        strconv.Itoa(major),
			minor:        strconv.Itoa(minor),
			deviceError:  "",
		})
	}

	return filesystems, nil
}

// canonicalizeDevice resolves the symlinks of a mount source relative to the
// configured host rootfs so that aliases for the same block device -- such as
// /dev/root, /dev/disk/by-uuid/<uuid> or /dev/mapper/<logical-volume> -- are
// reported under one stable device label. Non-absolute sources (e.g.
// "overlay", "tmpfs"), sources that do not resolve to a /dev node (e.g. plain
// bind mounts) and unresolvable paths (common in containers that do not
// bind-mount the host /dev) are returned unchanged.
func canonicalizeDevice(source, rootfs string) string {
	if !strings.HasPrefix(source, "/") {
		return source
	}

	hostPath := filepath.Clean(source)
	if rootfs != "" && rootfs != "/" {
		hostPath = filepath.Join(rootfs, source)
	}

	resolved, err := filepath.EvalSymlinks(hostPath)
	if err != nil {
		return source
	}
	resolved = filepath.ToSlash(resolved)

	if rootfs != "" && rootfs != "/" {
		rel, err := filepath.Rel(filepath.Clean(rootfs), resolved)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return source
		}
		resolved = "/" + filepath.ToSlash(rel)
	}

	// Only collapse aliases of real device nodes. Mount sources can also be
	// arbitrary host directories (bind mounts) whose name must be preserved.
	if !strings.HasPrefix(resolved, "/dev/") {
		return source
	}
	return resolved
}

// see https://github.com/prometheus/node_exporter/issues/3157#issuecomment-2422761187
// if either mount or super options contain "ro" or the superblock contains "emergency_ro",
// the filesystem is read-only
func isFilesystemReadOnly(labels filesystemLabels) bool {
	mountOptions := strings.Split(labels.mountOptions, ",")
	superOptions := strings.Split(labels.superOptions, ",")

	if slices.Contains(mountOptions, "ro") || slices.Contains(superOptions, "ro") || slices.Contains(superOptions, "emergency_ro") {
		return true
	}

	return false
}

func mountOptionsString(m map[string]string) string {
	parts := make([]string, 0, len(m))
	for key, value := range m {
		if value == "" {
			parts = append(parts, key)
		} else {
			parts = append(parts, key+"="+value)
		}
	}
	return strings.Join(parts, ",")
}
