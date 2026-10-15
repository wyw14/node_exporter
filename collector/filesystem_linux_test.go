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
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"

	"github.com/prometheus/procfs"
)

func Test_parseFilesystemLabelsError(t *testing.T) {
	tests := []struct {
		name string
		in   []*procfs.MountInfo
	}{
		{
			name: "malformed Major:Minor",
			in: []*procfs.MountInfo{
				{
					MajorMinorVer: "nope",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseFilesystemLabels(tt.in); err == nil {
				t.Fatal("expected an error, but none occurred")
			}
		})
	}
}

func Test_parseFilesystemLabelsSanitizesInvalidUTF8(t *testing.T) {
	in := []*procfs.MountInfo{
		{
			MajorMinorVer: "0:0",
			Source:        "/dev/sd\xe9",
			MountPoint:    "/mnt/cass\xe9",
			FSType:        "ext\xe9",
		},
	}

	got, err := parseFilesystemLabels(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 filesystem, got %d", len(got))
	}

	for name, value := range map[string]string{
		"device":     got[0].device,
		"mountPoint": got[0].mountPoint,
		"fsType":     got[0].fsType,
	} {
		if !utf8.ValidString(value) {
			t.Errorf("expected %s to be valid UTF-8, got %q", name, value)
		}
	}
}

func Test_isFilesystemReadOnly(t *testing.T) {
	tests := map[string]struct {
		labels   filesystemLabels
		expected bool
	}{
		"/media/volume1": {
			labels: filesystemLabels{
				mountOptions: "rw,nosuid,nodev,noexec,relatime",
				superOptions: "rw,devices",
			},
			expected: false,
		},
		"/media/volume2": {
			labels: filesystemLabels{
				mountOptions: "ro,relatime",
				superOptions: "rw,fd=22,pgrp=1,timeout=300,minproto=5,maxproto=5,direct",
			}, expected: true,
		},
		"/media/volume3": {
			labels: filesystemLabels{
				mountOptions: "rw,user_id=1000,group_id=1000",
				superOptions: "ro",
			}, expected: true,
		},
		"/media/volume4": {
			labels: filesystemLabels{
				mountOptions: "ro,nosuid,noexec",
				superOptions: "ro,nodev",
			}, expected: true,
		},
		"/media/volume5": {
			labels: filesystemLabels{
				mountOptions: "rw,user_id=1000,group_id=1000",
				superOptions: "emergency_ro",
			}, expected: true,
		},
	}

	for _, tt := range tests {
		if got := isFilesystemReadOnly(tt.labels); got != tt.expected {
			t.Errorf("Expected %t, got %t", tt.expected, got)
		}
	}
}

func TestMountPointDetails(t *testing.T) {
	if _, err := kingpin.CommandLine.Parse([]string{"--path.procfs", "./fixtures/proc"}); err != nil {
		t.Fatal(err)
	}

	expected := map[string]string{
		"/":                               "",
		"/sys":                            "",
		"/proc":                           "",
		"/dev":                            "",
		"/dev/pts":                        "",
		"/run":                            "",
		"/sys/kernel/security":            "",
		"/dev/shm":                        "",
		"/run/lock":                       "",
		"/sys/fs/cgroup":                  "",
		"/sys/fs/cgroup/systemd":          "",
		"/sys/fs/pstore":                  "",
		"/sys/fs/cgroup/cpuset":           "",
		"/sys/fs/cgroup/cpu,cpuacct":      "",
		"/sys/fs/cgroup/devices":          "",
		"/sys/fs/cgroup/freezer":          "",
		"/sys/fs/cgroup/net_cls,net_prio": "",
		"/sys/fs/cgroup/blkio":            "",
		"/sys/fs/cgroup/perf_event":       "",
		"/proc/sys/fs/binfmt_misc":        "",
		"/dev/mqueue":                     "",
		"/sys/kernel/debug":               "",
		"/dev/hugepages":                  "",
		"/sys/fs/fuse/connections":        "",
		"/boot":                           "",
		"/run/rpc_pipefs":                 "",
		"/run/user/1000":                  "",
		"/run/user/1000/gvfs":             "",
		"/var/lib/kubelet/plugins/kubernetes.io/vsphere-volume/mounts/[vsanDatastore] bafb9e5a-8856-7e6c-699c-801844e77a4a/kubernetes-dynamic-pvc-3eba5bba-48a3-11e8-89ab-005056b92113.vmdk": "",
		"/var/lib/kubelet/plugins/kubernetes.io/vsphere-volume/mounts/[vsanDatastore]	bafb9e5a-8856-7e6c-699c-801844e77a4a/kubernetes-dynamic-pvc-3eba5bba-48a3-11e8-89ab-005056b92113.vmdk": "",
		"/var/lib/containers/storage/overlay": "",
	}

	filesystems, err := mountPointDetails(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Log(err)
	}

	foundSet := map[string]bool{}
	for _, fs := range filesystems {
		if _, ok := expected[fs.mountPoint]; !ok {
			t.Errorf("Got unexpected %s", fs.mountPoint)
		}
		foundSet[fs.mountPoint] = true
	}

	for mountPoint := range expected {
		if _, ok := foundSet[mountPoint]; !ok {
			t.Errorf("Expected %s, got nothing", mountPoint)
		}
	}
}

func TestMountsFallback(t *testing.T) {
	if _, err := kingpin.CommandLine.Parse([]string{"--path.procfs", "./fixtures_hidepid/proc"}); err != nil {
		t.Fatal(err)
	}

	expected := map[string]string{
		"/": "",
	}

	filesystems, err := mountPointDetails(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Log(err)
	}

	for _, fs := range filesystems {
		if _, ok := expected[fs.mountPoint]; !ok {
			t.Errorf("Got unexpected %s", fs.mountPoint)
		}
	}
}

func TestMountOptionsString(t *testing.T) {
	tests := []struct {
		name      string
		input     map[string]string
		wantParts []string
	}{
		{
			name:      "single flag option",
			input:     map[string]string{"ro": ""},
			wantParts: []string{"ro"},
		},
		{
			name:      "single key=value option",
			input:     map[string]string{"errors": "remount-ro"},
			wantParts: []string{"errors=remount-ro"},
		},
		{
			name:      "multiple options including ro",
			input:     map[string]string{"ro": "", "relatime": "", "errors": "remount-ro"},
			wantParts: []string{"errors=remount-ro", "relatime", "ro"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mountOptionsString(tt.input)
			parts := strings.Split(result, ",")
			sort.Strings(parts)
			sort.Strings(tt.wantParts)
			if len(parts) != len(tt.wantParts) {
				t.Fatalf("mountOptionsString(%v) = %q, got %d parts, want %d", tt.input, result, len(parts), len(tt.wantParts))
			}
			for i := range parts {
				if parts[i] != tt.wantParts[i] {
					t.Errorf("mountOptionsString(%v) = %q, sorted part[%d] = %q, want %q", tt.input, result, i, parts[i], tt.wantParts[i])
				}
			}
		})
	}
}

func TestMountOptionsStringReadOnlyDetection(t *testing.T) {
	tests := []struct {
		name         string
		mountOptions map[string]string
		superOptions map[string]string
		wantReadOnly bool
	}{
		{
			name:         "ro among multiple mount options (ZFS / remount-ro scenario)",
			mountOptions: map[string]string{"ro": "", "relatime": "", "errors": "remount-ro"},
			superOptions: map[string]string{"rw": ""},
			wantReadOnly: true,
		},
		{
			name:         "ro in super options only",
			mountOptions: map[string]string{"rw": "", "relatime": ""},
			superOptions: map[string]string{"ro": "", "user_id": "1000"},
			wantReadOnly: true,
		},
		{
			name:         "no ro anywhere",
			mountOptions: map[string]string{"rw": "", "nosuid": "", "nodev": ""},
			superOptions: map[string]string{"rw": ""},
			wantReadOnly: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels := filesystemLabels{
				mountOptions: mountOptionsString(tt.mountOptions),
				superOptions: mountOptionsString(tt.superOptions),
			}
			if got := isFilesystemReadOnly(labels); got != tt.wantReadOnly {
				t.Errorf("isFilesystemReadOnly(%+v) = %v, want %v (mountOptions=%q superOptions=%q)",
					tt, got, tt.wantReadOnly, labels.mountOptions, labels.superOptions)
			}
		})
	}
}

func TestPathRootfs(t *testing.T) {
	if _, err := kingpin.CommandLine.Parse([]string{"--path.procfs", "./fixtures_bindmount/proc", "--path.rootfs", "/host"}); err != nil {
		t.Fatal(err)
	}

	expected := map[string]string{
		// should modify these mountpoints (removes /host, see fixture proc file)
		"/":              "",
		"/media/volume1": "",
		"/media/volume2": "",
		// should not modify these mountpoints
		"/dev/shm":       "",
		"/run/lock":      "",
		"/sys/fs/cgroup": "",
	}

	filesystems, err := mountPointDetails(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Log(err)
	}

	for _, fs := range filesystems {
		if _, ok := expected[fs.mountPoint]; !ok {
			t.Errorf("Got unexpected %s", fs.mountPoint)
		}
	}
}

func TestCanonicalizeDevice(t *testing.T) {
	rootfs := t.TempDir()

	mustMkdirAll(t, filepath.Join(rootfs, "dev", "disk", "by-uuid"))
	mustMkdirAll(t, filepath.Join(rootfs, "etc"))
	mustMkdirAll(t, filepath.Join(rootfs, "data"))

	// Stand-in for a real block device node.
	if err := os.WriteFile(filepath.Join(rootfs, "dev", "sda1"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// Stable alias commonly used by udev.
	if err := os.Symlink(filepath.Join("..", "..", "sda1"), filepath.Join(rootfs, "dev", "disk", "by-uuid", "abc")); err != nil {
		t.Fatal(err)
	}
	// Symlink that escapes /dev must not be rewritten into an arbitrary path.
	if err := os.WriteFile(filepath.Join(rootfs, "etc", "passwd"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "etc", "passwd"), filepath.Join(rootfs, "dev", "escape")); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		source string
		rootfs string
		want   string
	}{
		{name: "by-uuid symlink resolves to device node", source: "/dev/disk/by-uuid/abc", rootfs: rootfs, want: "/dev/sda1"},
		{name: "device node stays unchanged", source: "/dev/sda1", rootfs: rootfs, want: "/dev/sda1"},
		{name: "symlink escaping /dev is kept", source: "/dev/escape", rootfs: rootfs, want: "/dev/escape"},
		{name: "bind mount directory is kept", source: "/data", rootfs: rootfs, want: "/data"},
		{name: "dangling device path is kept", source: "/dev/does-not-exist", rootfs: rootfs, want: "/dev/does-not-exist"},
		{name: "pseudo fs source stays unchanged", source: "overlay", rootfs: rootfs, want: "overlay"},
		{name: "tmpfs source stays unchanged", source: "tmpfs", rootfs: rootfs, want: "tmpfs"},
		{name: "unresolvable under default rootfs is kept", source: "/dev/disk/by-uuid/abc", rootfs: "/", want: "/dev/disk/by-uuid/abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := canonicalizeDevice(tt.source, tt.rootfs); got != tt.want {
				t.Errorf("canonicalizeDevice(%q, %q) = %q, want %q", tt.source, tt.rootfs, got, tt.want)
			}
		})
	}
}

func TestMountDeviceStillMatches(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()

	var st unix.Stat_t
	if err := unix.Stat(dir, &st); err != nil {
		t.Fatalf("stat %s: %v", dir, err)
	}
	major := strconv.Itoa(int(unix.Major(st.Dev)))
	minor := strconv.Itoa(int(unix.Minor(st.Dev)))

	if !mountDeviceStillMatches(logger, dir, major, minor) {
		t.Errorf("mount point %s with major:minor %s:%s expected to match", dir, major, minor)
	}
	if mountDeviceStillMatches(logger, dir, "999", "999") {
		t.Error("mount point with wrong major:minor expected to be reported as detached")
	}
	if mountDeviceStillMatches(logger, filepath.Join(dir, "missing"), major, minor) {
		t.Error("vanished mount point expected to be reported as detached")
	}
	if !mountDeviceStillMatches(logger, dir, "invalid", "invalid") {
		t.Error("unknown major:minor must not cause metrics to be suppressed")
	}
}

func TestProcessStatMountLifecycle(t *testing.T) {
	previousRootfs := *rootfsPath
	previousTimeout := *mountTimeout
	t.Cleanup(func() {
		*rootfsPath = previousRootfs
		*mountTimeout = previousTimeout
	})
	*rootfsPath = t.TempDir()
	*mountTimeout = defaultMountTimeout

	c := &filesystemCollector{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	// A mount that disappeared before statfs() must be skipped entirely.
	if _, ok := c.processStat(filesystemLabels{mountPoint: "/mnt/vanished", major: "0", minor: "0"}); ok {
		t.Error("vanished mount point must produce no metrics")
	}

	mountDir := "/mnt/present"
	if err := os.MkdirAll(rootfsFilePath(mountDir), 0o755); err != nil {
		t.Fatal(err)
	}

	// The directory exists, but mountinfo's device numbers no longer match:
	// the mount was detached and statfs would report the parent filesystem.
	if stat, ok := c.processStat(filesystemLabels{mountPoint: mountDir, major: "998", minor: "997"}); ok {
		t.Errorf("detached mount point must produce no metrics, got %+v", stat)
	}

	var st unix.Stat_t
	if err := unix.Stat(rootfsFilePath(mountDir), &st); err != nil {
		t.Fatal(err)
	}
	labels := filesystemLabels{
		device:       "/dev/sda1",
		mountPoint:   mountDir,
		fsType:       "ext4",
		mountOptions: "rw,relatime",
		superOptions: "rw,data=ordered",
		major:        strconv.Itoa(int(unix.Major(st.Dev))),
		minor:        strconv.Itoa(int(unix.Minor(st.Dev))),
	}
	stat, ok := c.processStat(labels)
	if !ok {
		t.Fatal("present mount point with matching device numbers must produce metrics")
	}
	if stat.deviceError != 0 || stat.labels.deviceError != "" {
		t.Errorf("healthy mount must not be flagged with an error, got %q", stat.labels.deviceError)
	}
	// Options must be stripped from labels so repeated mountinfo entries
	// collapse into the same stable label set.
	if stat.labels.mountOptions != "" || stat.labels.superOptions != "" {
		t.Errorf("mount options must be cleared from labels, got %q %q", stat.labels.mountOptions, stat.labels.superOptions)
	}

	// Repeated collection must produce identical, stable labels and state.
	statAgain, ok := c.processStat(labels)
	if !ok {
		t.Fatal("present mount point must still produce metrics")
	}
	if stat.labels != statAgain.labels {
		t.Errorf("labels are not stable across scrapes:\n%+v\n%+v", stat.labels, statAgain.labels)
	}
	if stat.ro != statAgain.ro || stat.deviceError != statAgain.deviceError {
		t.Errorf("read-only/error state is not stable across scrapes: %+v vs %+v", stat, statAgain)
	}
}

func TestProcessStatUsesStableErrorLabels(t *testing.T) {
	previousRootfs := *rootfsPath
	t.Cleanup(func() { *rootfsPath = previousRootfs })
	*rootfsPath = t.TempDir()

	// EACCES is turned into a stable token instead of the raw OS error text.
	if err := os.MkdirAll(rootfsFilePath("/mnt"), 0o755); err != nil {
		t.Fatal(err)
	}
	denied := rootfsFilePath("/mnt/denied")
	if err := os.Mkdir(denied, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(denied, 0o755) })

	c := &filesystemCollector{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	stat, ok := c.processStat(filesystemLabels{mountPoint: "/mnt/denied", major: "0", minor: "0"})
	if !ok {
		t.Skip("statfs() did not report an error for the unreadable directory (likely running as root)")
	}
	if stat.deviceError != 1 || stat.labels.deviceError != deviceErrorStatfsFailed {
		t.Errorf("device_error label = %q, want stable token %q", stat.labels.deviceError, deviceErrorStatfsFailed)
	}
}

func TestNewFilesystemCollectorInvalidFilter(t *testing.T) {
	previousExclude := *mountPointsExclude
	previousSet := mountPointsExcludeSet
	t.Cleanup(func() {
		*mountPointsExclude = previousExclude
		mountPointsExcludeSet = previousSet
	})

	*mountPointsExclude = "["
	mountPointsExcludeSet = true

	if _, err := NewFilesystemCollector(slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("an invalid mount-points-exclude regexp must be reported as an error instead of panicking")
	}
}

func TestGetStatsConcurrent(t *testing.T) {
	previousProc := *procPath
	previousRootfs := *rootfsPath
	t.Cleanup(func() {
		*procPath = previousProc
		*rootfsPath = previousRootfs
	})
	if _, err := kingpin.CommandLine.Parse([]string{"--path.procfs", "./fixtures/proc", "--path.rootfs", "/"}); err != nil {
		t.Fatal(err)
	}

	collector, err := NewFilesystemCollector(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	c := collector.(*filesystemCollector)

	stuckMountsMtx.Lock()
	clear(stuckMounts)
	stuckMountsMtx.Unlock()

	// Run the full collection pipeline from multiple goroutines to exercise
	// concurrent scrapes; run with -race to detect shared-state races.
	const goroutines, iterations = 8, 3
	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				if _, err := c.GetStats(); err != nil {
					t.Errorf("GetStats returned an error: %v", err)
				}
				ch := make(chan prometheus.Metric, 1<<16)
				done := make(chan struct{})
				go func() {
					for range ch {
					}
					close(done)
				}()
				if err := c.Update(ch); err != nil {
					t.Errorf("Update returned an error: %v", err)
				}
				close(ch)
				<-done
			}
		}()
	}
	wg.Wait()
}

func TestStuckMountLifecycle(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mp := t.Name()
	stuckMountsMtx.Lock()
	delete(stuckMounts, mp)
	stuckMountsMtx.Unlock()
	t.Cleanup(func() {
		stuckMountsMtx.Lock()
		delete(stuckMounts, mp)
		stuckMountsMtx.Unlock()
	})

	if mountPointIsStuck(mp) {
		t.Fatal("mount must not be stuck initially")
	}
	markStuckMount(mp, logger)
	if !mountPointIsStuck(mp) {
		t.Fatal("mount must be stuck after markStuckMount")
	}
	// Marking again must be idempotent.
	markStuckMount(mp, logger)
	clearStuckMount(mp, logger)
	if mountPointIsStuck(mp) {
		t.Fatal("mount must not be stuck after clearStuckMount")
	}
}

func TestProcessStatStuckTimeout(t *testing.T) {
	previousRootfs := *rootfsPath
	previousTimeout := *mountTimeout
	t.Cleanup(func() {
		*rootfsPath = previousRootfs
		*mountTimeout = previousTimeout
		stuckMountsMtx.Lock()
		clear(stuckMounts)
		stuckMountsMtx.Unlock()
	})
	*rootfsPath = t.TempDir()
	*mountTimeout = time.Nanosecond

	mountDir := "/mnt/fast"
	if err := os.MkdirAll(rootfsFilePath(mountDir), 0o755); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(rootfsFilePath(mountDir), &st); err != nil {
		t.Fatal(err)
	}

	c := &filesystemCollector{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	stat, ok := c.processStat(filesystemLabels{
		mountPoint: mountDir,
		major:      strconv.Itoa(int(unix.Major(st.Dev))),
		minor:      strconv.Itoa(int(unix.Minor(st.Dev))),
	})
	if !ok {
		t.Fatal("a timed out mount must still be reported via device_error")
	}
	if stat.deviceError != 1 || stat.labels.deviceError != deviceErrorMountTimeout {
		t.Errorf("device_error = %q, want %q", stat.labels.deviceError, deviceErrorMountTimeout)
	}
}

func TestGetStatsStuckMountFastPath(t *testing.T) {
	previousProc := *procPath
	t.Cleanup(func() { *procPath = previousProc })
	if _, err := kingpin.CommandLine.Parse([]string{"--path.procfs", "./fixtures/proc"}); err != nil {
		t.Fatal(err)
	}

	collector, err := NewFilesystemCollector(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	c := collector.(*filesystemCollector)

	stuckMountsMtx.Lock()
	clear(stuckMounts)
	stuckMountsMtx.Unlock()
	// /boot is present in the fixtures and would otherwise be skipped because
	// the directory does not exist on the test host; the stuck fast-path must
	// report it without calling statfs.
	markStuckMount("/boot", c.logger)
	t.Cleanup(func() {
		stuckMountsMtx.Lock()
		delete(stuckMounts, "/boot")
		stuckMountsMtx.Unlock()
	})

	stats, err := c.GetStats()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, stat := range stats {
		if stat.labels.mountPoint != "/boot" {
			continue
		}
		found = true
		if stat.deviceError != 1 || stat.labels.deviceError != deviceErrorMountTimeout {
			t.Errorf("device_error = %q, want %q", stat.labels.deviceError, deviceErrorMountTimeout)
		}
		// Options must be cleared on the fast path too so duplicate
		// mountinfo entries collapse into one label set.
		if stat.labels.mountOptions != "" || stat.labels.superOptions != "" {
			t.Errorf("mount options leaked into labels: %q %q", stat.labels.mountOptions, stat.labels.superOptions)
		}
	}
	if !found {
		t.Fatal("stuck mount /boot was not reported")
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}
