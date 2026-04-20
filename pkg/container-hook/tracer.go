// Copyright 2023 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package containerhook detects when a container is created or terminated.
//
// It uses two mechanisms to detect new containers:
//  1. fanotify with FAN_OPEN_EXEC_PERM.
//  2. ebpf on the sys_enter_execve tracepoint to get the execve arguments.
//
// Using fanotify with FAN_OPEN_EXEC_PERM allows to call a callback function
// while the container is being created. The container is paused until the
// callback function returns.
//
// Using ebpf on the sys_enter_execve tracepoint allows to get the execve
// arguments without the need to read /proc/$pid/cmdline or /proc/$pid/comm.
// Reading /proc/$pid/cmdline is not possible using only fanotify when the
// tracer is not in the same pidns as the process being traced. This is the
// case when Inspektor Gadget is started with hostPID=false.
//
// https://github.com/inspektor-gadget/inspektor-gadget/blob/main/docs/devel/fanotify-ebpf.png
package containerhook

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/s3rj1k/go-fanotify/fanotify"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfgen"
	runtimefinder "github.com/inspektor-gadget/inspektor-gadget/pkg/container-hook/runtime-finder"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/kallsyms/symscache"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/kfilefields"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -cflags ${CFLAGS} -no-global-types -type record execruntime ./bpf/execruntime.bpf.c -- -I./bpf/

func init() {
	spec, err := loadExecruntime()
	if err != nil {
		panic(err)
	}
	symscache.RegisterSymbolsFromSpec(spec)
}

type EventType int

const (
	EventTypeAddContainer EventType = iota
	EventTypeRemoveContainer
	EventTypePreCreateContainer
)

const (
	defaultContainerPendingTimeout = 15 * time.Second
	defaultContainerCheckInterval  = 10 * time.Second
)

const (
	// config.json is typically less than 100 KiB.
	// 16 MiB should be enough.
	configJsonMaxSize = int64(16 * 1024 * 1024)

	// pid files store a string with a int32 value, so 11 characters.
	// Keep a larger buffer to be able to notice errors with strconv.Atoi.
	pidFileMaxSize = int64(32)
)

var (
	// How long to wait for a container after a "conmon" or a "runc start" command
	// The values can be overridden by tests.
	containerPendingTimeout = defaultContainerPendingTimeout
	containerCheckInterval  = defaultContainerCheckInterval
)

// ContainerEvent is the notification for container creation or termination
type ContainerEvent struct {
	// Type is whether the container was added or removed
	Type EventType

	// ContainerID is the container id, typically a 64 hexadecimal string
	ContainerID string

	// ContainerName is the container name, typically two words with an underscore
	ContainerName string

	// ContainerPID is the process id of the container
	ContainerPID uint32

	// Container's configuration is the config.json from the OCI runtime
	// spec
	ContainerConfig string

	// Bundle is the directory containing the config.json from the OCI
	// runtime spec
	// See https://github.com/opencontainers/runtime-spec/blob/main/bundle.md
	Bundle string
}

type ContainerNotifyFunc func(notif ContainerEvent)

type watchedContainer struct {
	id  string
	pid int
}

type pendingContainer struct {
	id             string
	bundleDir      string
	configJSONPath string
	pidFile        string
	pidFileDir     string
	mntnsId        uint64
	timestamp      time.Time
	removeMarks    []func()
}

type futureContainer struct {
	id        string
	name      string
	bundleDir string
	pidFile   string
	timestamp time.Time
}

type ContainerNotifier struct {
	runtimeBinaryNotify *fanotify.NotifyFD
	pidFileDirNotify    *fanotify.NotifyFD
	callback            ContainerNotifyFunc

	// containers is the set of containers that are being watched for
	// termination. This prevents duplicate calls to
	// AddWatchContainerTermination.
	//
	// Keys: Container ID
	containers   map[string]*watchedContainer
	containersMu sync.Mutex

	// futureContainers is the set of containers that are detected before
	// oci-runtime (runc/crun) creates the container e.g. detected via conmon
	//
	// Keys: Container ID
	futureContainers map[string]*futureContainer
	futureMu         sync.Mutex

	// pendingContainers is the set of containers that are created but not yet
	// started (e.g. 'runc create' executed but not yet 'runc start').
	//
	// Keys: pid file
	pendingContainers map[string]*pendingContainer
	pendingMu         sync.Mutex

	objs  execruntimeObjects
	links []link.Link

	// set to true when the notifier is closed is closed
	closed atomic.Bool
	// this channel is used in watchContainersTermination() to avoid having to wait for the
	// ticker to trigger before returning
	done chan bool

	wg sync.WaitGroup
}

var runtimePaths []string = append(
	runtimefinder.RuntimePaths,
	"/usr/bin/conmon",
)

// initFanotify initializes the fanotify API with the flags we need
func initFanotify() (*fanotify.NotifyFD, error) {
	// Flags for the fanotify fd
	var fanotifyFlags uint
	// FAN_REPORT_TID is required so that kretprobe/fsnotify_remove_first_event can report the tid
	fanotifyFlags |= uint(unix.FAN_REPORT_TID)
	// FAN_CLOEXEC is required to avoid leaking the fd to child processes
	fanotifyFlags |= uint(unix.FAN_CLOEXEC)
	// FAN_CLASS_CONTENT is required for perm events such as FAN_OPEN_EXEC_PERM
	fanotifyFlags |= uint(unix.FAN_CLASS_CONTENT)
	// FAN_UNLIMITED_QUEUE is required so we don't miss any events
	fanotifyFlags |= uint(unix.FAN_UNLIMITED_QUEUE)
	// FAN_UNLIMITED_MARKS is required so we can monitor as many pid files as
	// necessary without being restricted by:
	//     sysctl fs.fanotify.max_user_marks
	// With this flag, we don't influence other applications using fanotify
	// (kernel accounting is per-uid),
	fanotifyFlags |= uint(unix.FAN_UNLIMITED_MARKS)
	// FAN_NONBLOCK is required so GetEvent can be interrupted by Close()
	fanotifyFlags |= uint(unix.FAN_NONBLOCK)

	// Flags for the fd installed when reading a fanotify event (e.g. flag for
	// the runc fd or the pid file fd).
	openFlags := os.O_RDONLY | unix.O_LARGEFILE | unix.O_CLOEXEC
	return fanotify.Initialize(fanotifyFlags, openFlags)
}

// Supported detects if RuncNotifier is supported in the current environment
func Supported() bool {
	notifier, err := NewContainerNotifier(func(notif ContainerEvent) {})
	if notifier != nil {
		notifier.Close()
	}
	if err != nil {
		log.Warnf("ContainerNotifier: not supported: %s", err)
	}
	return err == nil
}

// NewContainerNotifier uses fanotify and ebpf to detect when a container is
// created or terminated, and call the callback on such event.
//
// Limitations:
// - the container runtime must be installed in one of the paths listed by runtimePaths
func NewContainerNotifier(callback ContainerNotifyFunc) (*ContainerNotifier, error) {
	n := &ContainerNotifier{
		callback:          callback,
		containers:        make(map[string]*watchedContainer),
		futureContainers:  make(map[string]*futureContainer),
		pendingContainers: make(map[string]*pendingContainer),
		done:              make(chan bool),
	}

	if err := n.install(); err != nil {
		n.Close()
		return nil, err
	}

	return n, nil
}

func (n *ContainerNotifier) installEbpf(fanotifyFd int) error {
	symscache.PopulateKallsymsCache()
	spec, err := loadExecruntime()
	if err != nil {
		return fmt.Errorf("load ebpf program for container-hook: %w", err)
	}

	fanotifyPrivateData, err := kfilefields.ReadPrivateDataFromFd(fanotifyFd)
	if err != nil {
		return fmt.Errorf("reading private data from fanotify fd: %w", err)
	}

	execSpec := &execruntimeSpecs{}
	if err := spec.Assign(execSpec); err != nil {
		return err
	}

	if err := execSpec.TracerGroup.Set(fanotifyPrivateData); err != nil {
		return err
	}

	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes: btfgen.GetBTFSpec(),
		},
	}

	if err := spec.LoadAndAssign(&n.objs, &opts); err != nil {
		return fmt.Errorf("loading maps and programs: %w", err)
	}

	// Attach ebpf programs
	l, err := link.Kprobe("fsnotify_remove_first_event", n.objs.IgFaPickE, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe fsnotify_remove_first_event: %w", err)
	}
	n.links = append(n.links, l)

	l, err = link.Kretprobe("fsnotify_remove_first_event", n.objs.IgFaPickX, nil)
	if err != nil {
		return fmt.Errorf("attaching kretprobe fsnotify_remove_first_event: %w", err)
	}
	n.links = append(n.links, l)

	l, err = link.Tracepoint("syscalls", "sys_enter_execve", n.objs.IgExecveE, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	n.links = append(n.links, l)

	l, err = link.Tracepoint("sched", "sched_process_exec", n.objs.IgSchedExec, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	n.links = append(n.links, l)

	l, err = link.Tracepoint("syscalls", "sys_exit_execve", n.objs.IgExecveX, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	n.links = append(n.links, l)

	return nil
}

func (n *ContainerNotifier) install() error {
	// Start fanotify
	runtimeBinaryNotify, err := initFanotify()
	if err != nil {
		return err
	}
	n.runtimeBinaryNotify = runtimeBinaryNotify

	pidFileDirNotify, err := initFanotify()
	if err != nil {
		return err
	}
	n.pidFileDirNotify = pidFileDirNotify

	// Load, initialize and attach ebpf program
	err = n.installEbpf(runtimeBinaryNotify.Fd)
	if err != nil {
		return err
	}

	// Attach fanotify to various runtime binaries
	runtimeFound := false

	runtimePath := os.Getenv("RUNTIME_PATH")
	if runtimePath != "" {
		log.Debugf("container-hook: trying runtime from RUNTIME_PATH env variable at %s", runtimePath)

		notifiedPath, err := runtimefinder.Notify(runtimePath, host.HostRoot, runtimeBinaryNotify)
		if err != nil {
			return fmt.Errorf("container-hook: notifying %s: %w", runtimePath, err)
		}

		log.Debugf("container-hook: monitoring runtime at %s (originally %s)", notifiedPath, runtimePath)
		runtimeFound = true
	} else {
		for _, r := range runtimePaths {
			log.Debugf("container-hook: trying runtime at %s", r)

			notifiedPath, err := runtimefinder.Notify(r, host.HostRoot, runtimeBinaryNotify)
			if err != nil {
				log.Debugf("container-hook: notifying %s: %v", runtimePath, err)
				continue
			}

			log.Debugf("container-hook: monitoring runtime at %s (originally %s)", notifiedPath, r)
			runtimeFound = true
		}
	}

	if !runtimeFound {
		return fmt.Errorf("no container runtime can be monitored with fanotify. The following paths were tested: %s. You can use the RUNTIME_PATH env variable to specify a custom path. If you are successful doing so, please open a PR to add your custom path to runtimePaths", strings.Join(runtimePaths, ", "))
	}

	n.wg.Add(4)
	go n.watchContainersTermination()
	go n.watchRuntimeBinary()
	go n.watchPendingContainers()
	go n.checkTimeout()

	return nil
}

// AddWatchContainerTermination watches a container for termination and
// generates an event on the notifier. This is automatically called for new
// containers detected by ContainerNotifier, but it can also be called for
// containers detected externally such as initial containers.
func (n *ContainerNotifier) AddWatchContainerTermination(containerID string, containerPID int) error {
	n.containersMu.Lock()
	defer n.containersMu.Unlock()

	if _, ok := n.containers[containerID]; ok {
		// This container is already being watched for termination
		return nil
	}

	n.containers[containerID] = &watchedContainer{
		id:  containerID,
		pid: containerPID,
	}

	return nil
}

// watchContainerTermination waits until the container terminates
func (n *ContainerNotifier) watchContainersTermination() {
	defer n.wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-n.done:
			return
		case <-ticker.C:
			if n.closed.Load() {
				return
			}

			dirEntries, err := os.ReadDir(host.HostProcFs)
			if err != nil {
				log.Errorf("reading /proc: %s", err)
				return
			}
			pids := make(map[int]bool)
			for _, entry := range dirEntries {
				pid, err := strconv.Atoi(entry.Name())
				if err != nil {
					// entry is not a process directory. Ignore.
					continue
				}
				pids[pid] = true
			}

			n.containersMu.Lock()
			for _, c := range n.containers {
				if pids[c.pid] {
					// container still running
					continue
				}

				if c.pid > math.MaxUint32 {
					log.Errorf("container PID (%d) exceeds math.MaxUint32 (%d)", c.pid, math.MaxUint32)
					return
				}

				go n.callback(ContainerEvent{
					Type:         EventTypeRemoveContainer,
					ContainerID:  c.id,
					ContainerPID: uint32(c.pid),
				})

				delete(n.containers, c.id)
			}
			n.containersMu.Unlock()
		}
	}
}

func (n *ContainerNotifier) watchPidFileIterate() error {
	// Get the next event from fanotify.
	// Even though the API allows to pass skipPIDs, we cannot use
	// it here because ResponseAllow would not be called.
	data, err := n.pidFileDirNotify.GetEvent()
	if err != nil {
		return err
	}

	// data can be nil if the event received is from a process in skipPIDs.
	// In that case, skip and get the next event.
	if data == nil {
		return nil
	}

	// Don't leak the fd received by GetEvent
	defer data.Close()
	dataFile := data.File()
	defer dataFile.Close()

	if !data.MatchMask(unix.FAN_ACCESS_PERM) {
		// This should not happen: FAN_ACCESS_PERM is the only mask Marked
		log.Errorf("fanotify: unknown event on pid file: mask=%d pid=%d", data.Mask, data.Pid)
		return nil
	}

	// This unblocks whoever is accessing the pidfile
	defer n.pidFileDirNotify.ResponseAllow(data)

	pathFromProcfs, err := data.GetPath()
	if err != nil {
		log.Errorf("fanotify: could not get path for pid file")
		return nil
	}

	// Coherence check: the pid file should be a small regular file
	var stat unix.Stat_t
	err = unix.Fstat(int(dataFile.Fd()), &stat)
	if err != nil {
		log.Errorf("fanotify: could not stat received fd (%q): %s", pathFromProcfs, err)
		return nil
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		log.Debugf("fanotify: received fd (%q) is not a regular file: expected %d, got %d",
			pathFromProcfs, unix.S_IFREG, stat.Mode&unix.S_IFMT)
		return nil
	}
	if stat.Size > pidFileMaxSize {
		log.Debugf("fanotify: received fd (%q) refers to a large file: %d bytes",
			pathFromProcfs, stat.Size)
		return nil
	}

	path := filepath.Join(host.HostRoot, pathFromProcfs)
	n.pendingMu.Lock()
	var pc *pendingContainer
	for pidFile := range n.pendingContainers {
		// Consider files identical if they have the same device/inode,
		// even if the paths differ due to symlinks (for example,
		// the event's path is /run/... but the runc --pid-file argument
		// uses /var/run/..., where /var/run is a symlink to /run).
		filesAreIdentical, err := checkFilesAreIdentical(path, pidFile)
		if err == nil && filesAreIdentical {
			pc = n.pendingContainers[pidFile]
			delete(n.pendingContainers, pidFile)
			for _, remove := range pc.removeMarks {
				remove()
			}
			break
		}
	}
	n.pendingMu.Unlock()

	if pc == nil {
		return nil
	}

	pidFileContent, err := io.ReadAll(io.LimitReader(dataFile, pidFileMaxSize))
	if err != nil {
		log.Errorf("fanotify: error reading pid file (%q): %s", pathFromProcfs, err)
		return nil
	}
	if len(pidFileContent) == 0 {
		log.Errorf("fanotify: empty pid file (%q)", pathFromProcfs)
		return nil
	}
	containerPID, err := strconv.Atoi(string(pidFileContent))
	if err != nil {
		log.Errorf("fanotify: pid file (%q) cannot be parsed: %s", pathFromProcfs, err)
		return nil
	}

	if containerPID > math.MaxUint32 {
		log.Errorf("fanotify: Container PID (%d) from pid file (%q) exceeds math.MaxUint32 (%d)", containerPID, pathFromProcfs, math.MaxUint32)
		return nil
	}

	// Coherence check: mntns changed
	newMntNs, err := containerutils.GetMntNs(containerPID)
	if err != nil {
		log.Errorf("fanotify: checking mnt namespace of pid %d (%q): %s", containerPID, pathFromProcfs, err)
		return nil
	}
	if pc.mntnsId == newMntNs {
		log.Errorf("fanotify: new container does not have a new mnt namespace: pid %d (%q) mntns %d", containerPID, pathFromProcfs, newMntNs)
		return nil
	}

	bundleConfigJSONFile, err := os.Open(pc.configJSONPath)
	if err != nil {
		log.Errorf("fanotify: could not open config.json (%q): %s", pc.configJSONPath, err)
		return nil
	}
	defer bundleConfigJSONFile.Close()

	bundleConfigJSON, err := io.ReadAll(io.LimitReader(bundleConfigJSONFile, configJsonMaxSize))
	if err != nil {
		log.Errorf("fanotify: could not read config.json (%q): %s", pc.configJSONPath, err)
		return nil
	}

	err = n.AddWatchContainerTermination(pc.id, containerPID)
	if err != nil {
		log.Errorf("fanotify: container %s with pid %d terminated before we could watch it: %s", pc.id, containerPID, err)
		return nil
	}

	var containerName string
	n.futureMu.Lock()
	fc, ok := n.futureContainers[pc.id]
	if ok {
		containerName = fc.name
	}
	delete(n.futureContainers, pc.id)
	n.futureMu.Unlock()

	n.callback(ContainerEvent{
		Type:            EventTypeAddContainer,
		ContainerID:     pc.id,
		ContainerPID:    uint32(containerPID),
		ContainerConfig: string(bundleConfigJSON),
		Bundle:          pc.bundleDir,
		ContainerName:   containerName,
	})

	return nil
}

func checkFilesAreIdentical(path1, path2 string) (bool, error) {
	// Since fanotify masks don't work on Linux 5.4, we could get a
	// notification for an unrelated file before the pid file is created
	// See fix in Linux 5.9:
	// https://github.com/torvalds/linux/commit/497b0c5a7c0688c1b100a9c2e267337f677c198e
	// In this case we should not return an error.
	if filepath.Base(path1) != filepath.Base(path2) {
		return false, nil
	}

	f1, err := os.Stat(path1)
	if err != nil {
		return false, err
	}

	f2, err := os.Stat(path2)
	if err != nil {
		return false, err
	}

	return os.SameFile(f1, f2), nil
}

func (n *ContainerNotifier) monitorRuntimeInstance(mntnsId uint64, bundleDir string, pidFile string, overrideContainerID string) error {
	removeMarks := []func(){}

	// The pidfile does not exist yet, so we cannot monitor it directly.
	// Instead we monitor its parent directory with FAN_EVENT_ON_CHILD to
	// get events on the directory's children.

	// Coherence check: the pidfile does not exist yet.
	if _, err := os.Stat(pidFile); err == nil {
		return fmt.Errorf("pidfile already exists: %s", pidFile)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("checking pidfile existence: %s: %w", pidFile, err)
	}

	pidFileDir := filepath.Dir(pidFile)
	err := n.pidFileDirNotify.Mark(unix.FAN_MARK_ADD, unix.FAN_ACCESS_PERM|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, pidFileDir)
	if err != nil {
		return fmt.Errorf("marking %s: %w", pidFileDir, err)
	}

	removeMarks = append(removeMarks, func() {
		_ = n.pidFileDirNotify.Mark(unix.FAN_MARK_REMOVE, unix.FAN_ACCESS_PERM|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, pidFileDir)
	})

	// watchPidFileIterate() will read config.json and it might be in the
	// same directory as the pid file. To avoid getting events unrelated to
	// the pidfile, add an ignore mask.
	//
	// This is best-effort to reduce noise: Linux < 5.9 doesn't respect ignore
	// masks on files when the parent directory is the object being watched:
	// https://github.com/torvalds/linux/commit/497b0c5a7c0688c1b100a9c2e267337f677c198e
	configJSONPath := filepath.Join(bundleDir, "config.json")
	if _, err := os.Stat(configJSONPath); errors.Is(err, os.ErrNotExist) {
		// podman might install config.json in the userdata directory
		configJSONPath = filepath.Join(bundleDir, "userdata", "config.json")
		if _, err := os.Stat(configJSONPath); errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("config not found at %s", configJSONPath)
		}
	}
	err = n.pidFileDirNotify.Mark(unix.FAN_MARK_ADD|unix.FAN_MARK_IGNORED_MASK, unix.FAN_ACCESS_PERM, unix.AT_FDCWD, configJSONPath)
	if err != nil {
		return fmt.Errorf("marking %s: %w", configJSONPath, err)
	}

	removeMarks = append(removeMarks, func() {
		_ = n.pidFileDirNotify.Mark(unix.FAN_MARK_REMOVE|unix.FAN_MARK_IGNORED_MASK, unix.FAN_ACCESS_PERM, unix.AT_FDCWD, configJSONPath)
	})

	// This is best-effort to reduce noise: Linux < 5.9 doesn't respect ignore
	// masks on files when the parent directory is the object being watched:
	// https://github.com/torvalds/linux/commit/497b0c5a7c0688c1b100a9c2e267337f677c198e
	ignoreFileList := []string{
		"passwd",
		"log.json",
		"runtime",
	}
	for _, ignoreFile := range ignoreFileList {
		ignoreFilePath := filepath.Join(bundleDir, ignoreFile)
		// No need to os.Stat() before: this is best-effort and we ignore the
		// errors. Not all files are guaranteed to exist depending on the
		// container runtime.
		err := n.pidFileDirNotify.Mark(unix.FAN_MARK_ADD|unix.FAN_MARK_IGNORED_MASK, unix.FAN_ACCESS_PERM, unix.AT_FDCWD, ignoreFilePath)
		if err == nil {
			removeMarks = append(removeMarks, func() {
				_ = n.pidFileDirNotify.Mark(unix.FAN_MARK_REMOVE|unix.FAN_MARK_IGNORED_MASK, unix.FAN_ACCESS_PERM, unix.AT_FDCWD, ignoreFilePath)
			})
		} else if !errors.Is(err, fs.ErrNotExist) {
			// Don't log if the error is "NotExist": this is normal
			// depending on the container runtime.
			log.Debugf("fanotify: marking %s: %v", ignoreFilePath, err)
		}
	}

	// cri-o appends userdata to bundleDir,
	// so we trim it here to get the correct containerID
	containerID := filepath.Base(filepath.Clean(strings.TrimSuffix(bundleDir, "userdata")))
	if overrideContainerID != "" {
		containerID = overrideContainerID
	}

	n.pendingMu.Lock()
	defer n.pendingMu.Unlock()

	// Insert new entry
	now := time.Now()
	pc := &pendingContainer{
		id:             containerID,
		bundleDir:      bundleDir,
		configJSONPath: configJSONPath,
		pidFile:        pidFile,
		pidFileDir:     pidFileDir,
		mntnsId:        mntnsId,
		timestamp:      now,
		removeMarks:    removeMarks,
	}
	n.pendingContainers[pidFile] = pc

	n.callPreCreateContainerCallback(pc)

	return nil
}

func (n *ContainerNotifier) callPreCreateContainerCallback(pc *pendingContainer) {
	bundleConfigJSONFile, err := os.Open(pc.configJSONPath)
	if err != nil {
		log.Errorf("fanotify: could not open config.json (%q): %s", pc.configJSONPath, err)
		return
	}
	defer bundleConfigJSONFile.Close()
	bundleConfigJSON, err := io.ReadAll(io.LimitReader(bundleConfigJSONFile, configJsonMaxSize))
	if err != nil {
		log.Errorf("fanotify: could not read config.json (%q): %s", pc.configJSONPath, err)
		return
	}

	containerConfig := string(bundleConfigJSON)
	n.callback(ContainerEvent{
		Type:            EventTypePreCreateContainer,
		ContainerID:     pc.id,
		ContainerConfig: containerConfig,
		Bundle:          pc.bundleDir,
	})
}

func (n *ContainerNotifier) watchRuntimeBinary() {
	defer n.wg.Done()

	for {
		err := n.watchRuntimeIterate()
		if n.closed.Load() {
			return
		}
		if err != nil {
			log.Errorf("error watching runtime binary: %v\n", err)
			return
		}
	}
}

func (n *ContainerNotifier) watchPendingContainers() {
	defer n.wg.Done()

	for {
		err := n.watchPidFileIterate()
		if n.closed.Load() {
			return
		}
		if err != nil {
			log.Errorf("error watching pid file directories: %v\n", err)
			return
		}
	}
}

func (n *ContainerNotifier) checkTimeout() {
	defer n.wg.Done()

	ticker := time.NewTicker(containerCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-n.done:
			return
		case <-ticker.C:
			now := time.Now()

			n.futureMu.Lock()
			for id, fc := range n.futureContainers {
				if now.Sub(fc.timestamp) > containerPendingTimeout {
					delete(n.futureContainers, id)
				}
			}
			n.futureMu.Unlock()

			n.pendingMu.Lock()
			for id, pc := range n.pendingContainers {
				if now.Sub(pc.timestamp) > containerPendingTimeout {
					for _, remove := range pc.removeMarks {
						remove()
					}
					delete(n.pendingContainers, id)
				}
			}
			n.pendingMu.Unlock()
		}
	}
}

func (n *ContainerNotifier) parseConmonCmdline(cmdlineArr []string) {
	containerName := ""
	containerID := ""
	bundleDir := ""
	pidFile := ""

	for i := 0; i < len(cmdlineArr); i++ {
		verb := cmdlineArr[i]
		arg := ""
		if i+1 < len(cmdlineArr) {
			arg = cmdlineArr[i+1]
		}
		switch verb {
		case "-n", "--name":
			containerName = arg
			i++
		case "-c", "--cid":
			containerID = arg
			i++
		case "-b", "--bundle":
			bundleDir = arg
			i++
		case "-p", "--container-pidfile":
			pidFile = arg
			i++
		}
	}

	if containerName == "" || containerID == "" || bundleDir == "" || pidFile == "" {
		return
	}

	n.futureMu.Lock()
	n.futureContainers[containerID] = &futureContainer{
		id:        containerID,
		pidFile:   pidFile,
		bundleDir: bundleDir,
		name:      containerName,
		timestamp: time.Now(),
	}
	n.futureMu.Unlock()
}

// readConfigJSON opens config.json with a size limit so that a pathological
// config can't exhaust memory (mirrors callPreCreateContainerCallback).
func readConfigJSON(configJSONPath string) ([]byte, error) {
	f, err := os.Open(configJSONPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, configJsonMaxSize))
}

// monitorRuntimeState polls runc's state directory for state.json to get the
// container PID. This is used when --pid-file is not specified on the runc
// command line (common for direct runc usage).
//
// runcPid is the PID of the runc process that was intercepted by fanotify and
// is currently blocked on the ACCESS_PERM response. We use it to distinguish
// runc itself from the container init (which is especially important for
// containers sharing the host mount namespace, where the mntns coherence
// check alone is insufficient).
func (n *ContainerNotifier) monitorRuntimeState(bundleDir string, stateDir string, containerID string, runcPid int) error {
	configJSONPath := filepath.Join(bundleDir, "config.json")
	if _, err := os.Stat(configJSONPath); errors.Is(err, os.ErrNotExist) {
		configJSONPath = filepath.Join(bundleDir, "userdata", "config.json")
		if _, err := os.Stat(configJSONPath); errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("config not found at %s", configJSONPath)
		}
	}

	// Deduplicate: if we're already polling for this containerID, don't
	// start a second goroutine. We use the pending map with a synthetic
	// key (stateDir is unique per (runc-root, container-id)).
	pendingKey := "runcstate:" + stateDir
	n.pendingMu.Lock()
	if _, alreadyPending := n.pendingContainers[pendingKey]; alreadyPending {
		n.pendingMu.Unlock()
		log.Debugf("monitorRuntimeState: already monitoring %s", stateDir)
		return nil
	}
	n.pendingContainers[pendingKey] = &pendingContainer{
		id:             containerID,
		bundleDir:      bundleDir,
		configJSONPath: configJSONPath,
		timestamp:      time.Now(),
	}
	n.pendingMu.Unlock()

	cleanup := func() {
		n.pendingMu.Lock()
		delete(n.pendingContainers, pendingKey)
		n.pendingMu.Unlock()
	}

	// Emit pre-create callback with config.json (with size limit).
	bundleConfigJSON, err := readConfigJSON(configJSONPath)
	if err != nil {
		log.Debugf("monitorRuntimeState: could not read config.json (%q): %s", configJSONPath, err)
	} else {
		n.callback(ContainerEvent{
			Type:            EventTypePreCreateContainer,
			ContainerID:     containerID,
			ContainerConfig: string(bundleConfigJSON),
			Bundle:          bundleDir,
		})
	}

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer cleanup()

		stateFile := filepath.Join(stateDir, "state.json")
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		timeout := time.After(containerPendingTimeout)

		for {
			select {
			case <-n.done:
				return
			case <-timeout:
				log.Debugf("monitorRuntimeState: timeout waiting for state file %s", stateFile)
				return
			case <-ticker.C:
				data, err := os.ReadFile(stateFile)
				if err != nil {
					continue
				}

				// runc's internal state.json uses "init_process_pid",
				// NOT the OCI spec "pid" field. This is an internal
				// runc/libcontainer format and is not covered by any
				// stability guarantee.
				var runcState struct {
					InitProcessPid int `json:"init_process_pid"`
				}
				if err := json.Unmarshal(data, &runcState); err != nil {
					continue
				}
				if runcState.InitProcessPid <= 0 {
					continue
				}

				containerPID := runcState.InitProcessPid

				// Coherence check: the init PID must be distinct from
				// the intercepted runc process. This handles containers
				// that share the host mount namespace (where checking
				// mntns alone is not enough).
				if runcPid > 0 && containerPID == runcPid {
					continue
				}

				// Verify the init process is actually alive (not a stale
				// state.json pointing at a recycled PID).
				if err := syscall.Kill(containerPID, 0); err != nil && !errors.Is(err, syscall.EPERM) {
					continue
				}

				if containerPID > math.MaxUint32 {
					log.Errorf("monitorRuntimeState: PID %d exceeds MaxUint32", containerPID)
					return
				}

				err = n.AddWatchContainerTermination(containerID, containerPID)
				if err != nil {
					log.Errorf("monitorRuntimeState: container %s terminated before watch: %s", containerID, err)
					return
				}

				// Check for future container info (name from conmon)
				var containerName string
				n.futureMu.Lock()
				fc, ok := n.futureContainers[containerID]
				if ok {
					containerName = fc.name
				}
				delete(n.futureContainers, containerID)
				n.futureMu.Unlock()

				// Re-read config.json for the callback (with size limit).
				configJSON, err := readConfigJSON(configJSONPath)
				if err != nil {
					log.Errorf("monitorRuntimeState: could not read config.json: %s", err)
					return
				}

				n.callback(ContainerEvent{
					Type:            EventTypeAddContainer,
					ContainerID:     containerID,
					ContainerPID:    uint32(containerPID),
					ContainerConfig: string(configJSON),
					Bundle:          bundleDir,
					ContainerName:   containerName,
				})
				return
			}
		}
	}()

	return nil
}

// runcValueFlags lists runc/crun flags that take a separate value argument.
// Knowing these is essential to parse the cmdline without mistaking flag
// values (e.g. --console-socket /path) for the container-id positional.
// Source: runc's urfave/cli flag definitions (global flags and the
// create/run subcommand flags). Keep this list in sync with the runc docs.
var runcValueFlags = map[string]bool{
	// Global flags
	"--log":        true,
	"--log-format": true,
	"--log-level":  true,
	"--root":       true,
	"--criu":       true,
	"--rootless":   true,
	// create / run flags
	"--bundle":         true,
	"-b":               true,
	"--console-socket": true,
	"--pid-file":       true,
	"--preserve-fds":   true,
}

func splitFlag(arg string) (name, value string, hasValue bool) {
	if eq := strings.IndexByte(arg, '='); eq != -1 {
		return arg[:eq], arg[eq+1:], true
	}
	return arg, "", false
}

// ociRuntimeCmd holds the fields parsed from a runc/crun command line.
type ociRuntimeCmd struct {
	command     string // "create" or "run"; empty if neither found
	bundleDir   string
	pidFile     string
	runcRoot    string
	containerID string
}

// parseOCIRuntimeCmdline parses a runc/crun command line. This is a pure
// function extracted from parseOCIRuntime so it can be unit-tested without
// needing a live ContainerNotifier, fanotify, or filesystem state.
//
// Grammar:
//
//	runc [global-options] <command> [command-options] [--] <container-id>
//
// Value-taking flags (separate or = form) are recognized via runcValueFlags;
// unknown flags are ignored to avoid misinterpreting their values as
// positional arguments (e.g. `--console-socket /tmp/s.sock`).
func parseOCIRuntimeCmdline(cmdlineArr []string) ociRuntimeCmd {
	var p ociRuntimeCmd
	commandFound := false

	for i := 0; i < len(cmdlineArr); i++ {
		arg := cmdlineArr[i]

		if !commandFound {
			if arg == "create" || arg == "run" {
				p.command = arg
				commandFound = true
				continue
			}
			if runcValueFlags[arg] && i+1 < len(cmdlineArr) {
				if arg == "--root" {
					p.runcRoot = cmdlineArr[i+1]
				}
				i++
				continue
			}
			if name, value, hasValue := splitFlag(arg); hasValue {
				if name == "--root" {
					p.runcRoot = value
				}
			}
			continue
		}

		if arg == "--" {
			if i+1 < len(cmdlineArr) {
				p.containerID = cmdlineArr[i+1]
			}
			break
		}

		if runcValueFlags[arg] && i+1 < len(cmdlineArr) {
			switch arg {
			case "--bundle", "-b":
				p.bundleDir = cmdlineArr[i+1]
			case "--pid-file":
				p.pidFile = cmdlineArr[i+1]
			case "--root":
				p.runcRoot = cmdlineArr[i+1]
			}
			i++
			continue
		}

		if strings.HasPrefix(arg, "-") {
			if name, value, hasValue := splitFlag(arg); hasValue {
				switch name {
				case "--bundle", "-b":
					p.bundleDir = value
				case "--pid-file":
					p.pidFile = value
				case "--root":
					p.runcRoot = value
				}
			}
			continue
		}

		p.containerID = arg
		break
	}

	return p
}

func (n *ContainerNotifier) parseOCIRuntime(mntnsId uint64, runcPid int, cmdlineArr []string) {
	// Parse oci-runtime (runc/crun) command line:
	//   runc [global-options] <command> [command-options] [--] <container-id>
	//
	// Examples that must parse correctly:
	//   runc create --bundle /b --pid-file /p myctr
	//   runc --root /run/user/1000/runc run --console-socket /tmp/s.sock myctr
	//   runc run --preserve-fds 3 --detach -- myctr
	p := parseOCIRuntimeCmdline(cmdlineArr)
	if p.command == "" {
		return
	}
	bundleDir := p.bundleDir
	pidFile := p.pidFile
	runcRoot := p.runcRoot
	containerID := p.containerID

	// If --bundle was not specified, runc uses its CWD.
	// Since the runc process is blocked by fanotify, we can read /proc/<pid>/cwd.
	// NOTE: readlink returns the path as-is in the runc process's mount
	// namespace. This is correct for host-resident runc; nested-runc
	// scenarios may not resolve under host.HostRoot.
	if bundleDir == "" && runcPid > 0 {
		cwd, err := os.Readlink(filepath.Join(host.HostProcFs, fmt.Sprint(runcPid), "cwd"))
		if err != nil {
			log.Debugf("fanotify: could not read cwd for runc pid %d: %s", runcPid, err)
			return
		}
		bundleDir = cwd
	}

	if bundleDir == "" {
		return
	}

	bundleDir = filepath.Join(host.HostRoot, bundleDir)
	if _, err := os.Stat(bundleDir); err != nil {
		log.Debugf("fanotify: bundle dir %q not accessible: %s", bundleDir, err)
		return
	}

	if pidFile != "" {
		pidFile = filepath.Join(host.HostRoot, pidFile)
		// Only override the bundle-derived containerID when we have a
		// positional container-id from the cmdline AND the bundle
		// basename disagrees (avoids disturbing the cri-o / podman-conmon
		// correlation which relies on bundle-base == container-id).
		override := ""
		if containerID != "" {
			bundleBase := filepath.Base(filepath.Clean(strings.TrimSuffix(bundleDir, "userdata")))
			if bundleBase != containerID {
				override = containerID
			}
		}
		err := n.monitorRuntimeInstance(mntnsId, bundleDir, pidFile, override)
		if err != nil {
			log.Errorf("error monitoring runtime instance: %v\n", err)
		}
		return
	}

	// No --pid-file: poll runc state directory for state.json to get PID.
	if containerID == "" {
		log.Debugf("fanotify: runc/crun command without --pid-file and no container ID")
		return
	}

	stateDir := resolveRuncStateDir(runcRoot, containerID)
	if stateDir == "" {
		log.Debugf("fanotify: could not locate runc state dir for %s", containerID)
		return
	}
	err := n.monitorRuntimeState(bundleDir, stateDir, containerID, runcPid)
	if err != nil {
		log.Errorf("error monitoring runtime state: %v\n", err)
	}
}

// resolveRuncStateDir picks the first existing state directory. If --root
// was explicitly set, it is used unconditionally. Otherwise we probe the
// common defaults for runc (/run/runc) and crun (/run/crun).
func resolveRuncStateDir(runcRoot, containerID string) string {
	if runcRoot != "" {
		return filepath.Join(host.HostRoot, runcRoot, containerID)
	}
	for _, candidate := range []string{"/run/runc", "/run/crun"} {
		dir := filepath.Join(host.HostRoot, candidate, containerID)
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
	}
	// Fall back to /run/runc (the goroutine will time out if it doesn't appear).
	return filepath.Join(host.HostRoot, "/run/runc", containerID)
}

func (n *ContainerNotifier) watchRuntimeIterate() error {
	// Get the next event from fanotify.
	// Even though the API allows to pass skipPIDs, we cannot use it here
	// because ResponseAllow would not be called.
	data, err := n.runtimeBinaryNotify.GetEvent()
	if err != nil {
		return err
	}

	// data can be nil if the event received is from a process in skipPIDs.
	// In that case, skip and get the next event.
	if data == nil {
		return nil
	}

	// Don't leak the fd received by GetEvent
	defer data.Close()

	if !data.MatchMask(unix.FAN_OPEN_EXEC_PERM) {
		// This should not happen: FAN_OPEN_EXEC_PERM is the only mask Marked
		log.Errorf("fanotify: unknown event on runtime: mask=%d pid=%d", data.Mask, data.Pid)
		return nil
	}

	// This unblocks the execution
	defer n.runtimeBinaryNotify.ResponseAllow(data)

	// Lookup entry in ebpf map ig_fa_records
	var record execruntimeRecord
	err = n.objs.IgFaRecords.LookupAndDelete(nil, &record)
	if err != nil {
		log.Errorf("fanotify: lookup record: %s", err)
		return nil
	}

	pathFromProcfs, err := data.GetPath()
	if err != nil {
		log.Errorf("fanotify: could not get path for runtime pid=%d", data.Pid)
		return nil
	}
	basename := filepath.Base(pathFromProcfs)
	if basename != "conmon" && basename != "runc" && basename != "crun" {
		// When runc re-executes itself with memfd, basename is empty ("/")
		// Ignore this event
		return nil
	}

	// Skip empty record
	// This can happen when the ebpf code didn't find the exec args
	// This happens when using execveat instead of execve
	if record.MntnsId == 0 {
		log.Debugf("fanotify: skip event from %q (pid %d) without args (mntns=0)", pathFromProcfs, data.Pid)
		return nil
	}
	if record.Pid == 0 {
		log.Debugf("fanotify: skip event from %q (pid %d) without args (pid=0)", pathFromProcfs, data.Pid)
		return nil
	}
	if record.ArgsSize == 0 {
		log.Debugf("fanotify: skip event from %q (pid %d) without args", pathFromProcfs, data.Pid)
		return nil
	}

	callerComm := strings.TrimRight(string(record.CallerComm[:]), "\x00")

	cmdlineArr := []string{}
	calleeComm := ""
	for _, arg := range strings.Split(string(record.Args[0:record.ArgsSize]), "\x00") {
		if arg != "" {
			cmdlineArr = append(cmdlineArr, arg)
		}
	}
	if len(cmdlineArr) == 0 {
		log.Debugf("fanotify: cannot get cmdline for %q (pid %d)", pathFromProcfs, record.Pid)
		return nil
	}
	if cmdlineArr[0] == "/proc/self/exe" {
		// runc re-executes itself: "/proc/self/exe init"
		// Ignore this event
		return nil
	}
	if len(cmdlineArr) > 0 {
		calleeComm = filepath.Base(cmdlineArr[0])
	}

	log.Debugf("fanotify: got event with mntns=%d pid=%d caller=%q callee=%q path=%v args=%v",
		record.MntnsId, record.Pid,
		callerComm, calleeComm,
		pathFromProcfs, cmdlineArr)

	// runc is executing itself with unix.Exec(), so fanotify receives two
	// FAN_OPEN_EXEC_PERM events:
	//   1. from containerd-shim (or similar)
	//   2. from runc, by this re-execution.
	// This filter takes the first one.

	switch calleeComm {
	case "conmon":
		// Calling sequence: crio/podman -> conmon -> runc/crun
		n.parseConmonCmdline(cmdlineArr)
	case "runc", "crun":
		n.parseOCIRuntime(record.MntnsId, int(record.Pid), cmdlineArr)
	default:
		return nil
	}

	return nil
}

func (n *ContainerNotifier) Close() {
	n.closed.Store(true)
	close(n.done)
	if n.runtimeBinaryNotify != nil {
		n.runtimeBinaryNotify.File.Close()
	}
	if n.pidFileDirNotify != nil {
		n.pidFileDirNotify.File.Close()
	}
	n.wg.Wait()

	for _, l := range n.links {
		gadgets.CloseLink(l)
	}
	n.links = nil
	n.objs.Close()
}
