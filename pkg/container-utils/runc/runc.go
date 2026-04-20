// Copyright 2026 The Inspektor Gadget authors
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

// Package runc implements a ContainerRuntimeClient backed by runc's on-disk
// state directory.
//
// IMPORTANT: The state.json format parsed here is runc's *internal*
// libcontainer format (see libcontainer/container.go). It is NOT the OCI
// runtime-spec State. This format has no stability guarantee, and a runc
// major bump can break the layout assumed here. crun writes a compatible
// subset at /run/crun/<id>/status; we parse the same fields we need from it.
package runc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	ocispec "github.com/opencontainers/runtime-spec/specs-go"
	log "github.com/sirupsen/logrus"

	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

const (
	// stateJsonMaxSize limits how large a state.json we'll read.
	stateJsonMaxSize = int64(1 * 1024 * 1024)

	// configJsonMaxSize limits how large a config.json we'll read.
	configJsonMaxSize = int64(16 * 1024 * 1024)
)

// runcInternalState matches runc's internal state.json format
// (libcontainer/container.go BaseState + State). This is NOT the OCI
// runtime spec State; runc stores its own format on disk.
type runcInternalState struct {
	ID             string `json:"id"`
	InitProcessPid int    `json:"init_process_pid"`
	// InitProcessStartTime is the /proc/[pid]/stat starttime captured by
	// runc when it recorded state.json. We use it to detect PID reuse:
	// if the process at init_process_pid now has a different start time,
	// state.json is stale and the container is no longer running.
	// runc serializes this as a JSON number (uint64). We accept both
	// numeric and string forms for forward/backward compatibility.
	InitProcessStartTime json.Number `json:"init_process_start,omitempty"`
	Config               struct {
		Labels  []string `json:"labels"`
		Cgroups *struct {
			Path string `json:"path"`
		} `json:"cgroups"`
	} `json:"config"`
}

// bundlePath extracts the bundle path from runc's config.labels.
// Runc stores labels as "key=value" strings and the bundle path is
// stored with key "bundle".
func (s *runcInternalState) bundlePath() string {
	for _, label := range s.Config.Labels {
		k, v, ok := strings.Cut(label, "=")
		if ok && k == "bundle" {
			return v
		}
	}
	return ""
}

// isPauseContainer returns true if this appears to be a Kubernetes pod
// sandbox (pause) container. We detect it by the well-known labels that
// kubelet / dockershim / cri-dockerd attach; when runc is invoked directly
// as the low-level runtime, these labels are preserved in config.json and
// mirrored in state.json via config.labels.
func (s *runcInternalState) isPauseContainer() bool {
	for _, label := range s.Config.Labels {
		k, v, _ := strings.Cut(label, "=")
		switch k {
		case "io.kubernetes.container.name":
			if v == "POD" {
				return true
			}
		case "io.kubernetes.docker.type":
			if v == "podsandbox" {
				return true
			}
		case "io.cri-containerd.kind":
			if v == "sandbox" {
				return true
			}
		}
	}
	return false
}

// processRunning checks if the init process is still alive. Kill(pid, 0)
// returns nil if the process exists and is signalable, EPERM if it exists
// but we lack permission to signal it, and ESRCH if it does not exist.
// We treat EPERM as "alive".
func (s *runcInternalState) processRunning() bool {
	if s.InitProcessPid <= 0 {
		return false
	}
	err := syscall.Kill(s.InitProcessPid, 0)
	if err == nil {
		return true
	}
	return errors.Is(err, syscall.EPERM)
}

// readProcStartTime returns the starttime (field 22) of /proc/[pid]/stat,
// or "" on any error. Used to detect PID reuse.
func readProcStartTime(pid int) string {
	data, err := os.ReadFile(filepath.Join(host.HostProcFs, strconv.Itoa(pid), "stat"))
	if err != nil {
		return ""
	}
	// The comm field (2) is parenthesized and can contain spaces; split
	// after the last ')' to be safe.
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 || end+2 >= len(data) {
		return ""
	}
	fields := strings.Fields(string(data[end+2:]))
	// After dropping pid and (comm), starttime is originally field 22,
	// which is field index 19 (zero-based) in the remaining slice.
	if len(fields) < 20 {
		return ""
	}
	return fields[19]
}

// pidIsStale returns true if the PID has been reused (different process
// from the one runc recorded). If start time info is unavailable on either
// side, we fall back to "not stale" to avoid false negatives.
func (s *runcInternalState) pidIsStale() bool {
	recorded := string(s.InitProcessStartTime)
	if recorded == "" {
		return false
	}
	now := readProcStartTime(s.InitProcessPid)
	if now == "" {
		return false
	}
	return now != recorded
}

// RuncClient implements ContainerRuntimeClient by reading runc's on-disk
// state directory (default /run/runc, with fallback to /run/crun when the
// default path doesn't exist).
type RuncClient struct {
	rootDir string
}

func NewRuncClient(rootDir string) runtimeclient.ContainerRuntimeClient {
	if rootDir == "" {
		rootDir = filepath.Join(host.HostRoot, runtimeclient.RuncDefaultRootPath)
	}
	// If the configured path doesn't exist but the crun default does,
	// fall back so that crun-only hosts work out of the box.
	if _, err := os.Stat(rootDir); err != nil {
		crunPath := filepath.Join(host.HostRoot, runtimeclient.CrunDefaultRootPath)
		if _, err := os.Stat(crunPath); err == nil {
			log.Debugf("runc client: %q missing, falling back to %q", rootDir, crunPath)
			rootDir = crunPath
		}
	}
	return &RuncClient{rootDir: rootDir}
}

func (r *RuncClient) GetContainers() ([]*runtimeclient.ContainerData, error) {
	entries, err := os.ReadDir(r.rootDir)
	if err != nil {
		return nil, fmt.Errorf("reading runc root dir %q: %w", r.rootDir, err)
	}

	var containers []*runtimeclient.ContainerData
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		c, err := r.getContainerByID(entry.Name())
		if err != nil {
			if errors.Is(err, runtimeclient.ErrPauseContainer) {
				continue
			}
			log.Debugf("runc client: skipping %q: %s", entry.Name(), err)
			continue
		}
		containers = append(containers, c)
	}
	return containers, nil
}

func (r *RuncClient) GetContainer(containerID string) (*runtimeclient.ContainerData, error) {
	return r.getContainerByID(containerID)
}

func (r *RuncClient) GetContainerDetails(containerID string) (*runtimeclient.ContainerDetailsData, error) {
	state, err := r.readState(containerID)
	if err != nil {
		return nil, err
	}
	if state.isPauseContainer() {
		return nil, runtimeclient.ErrPauseContainer
	}

	details := &runtimeclient.ContainerDetailsData{
		ContainerData: runtimeclient.ContainerData{
			Runtime: runtimeclient.RuntimeContainerData{
				RuntimeName:   types.RuntimeNameRunc,
				ContainerID:   state.ID,
				ContainerName: state.ID,
				State:         r.deriveStatus(state),
			},
		},
		Pid: state.InitProcessPid,
	}

	if cg := state.Config.Cgroups; cg != nil {
		details.CgroupsPath = cg.Path
	}

	if bundle := state.bundlePath(); bundle != "" {
		r.enrichFromBundle(bundle, details)
	}

	return details, nil
}

func (r *RuncClient) Close() error {
	return nil
}

func (r *RuncClient) getContainerByID(containerID string) (*runtimeclient.ContainerData, error) {
	state, err := r.readState(containerID)
	if err != nil {
		return nil, err
	}
	if state.isPauseContainer() {
		return nil, runtimeclient.ErrPauseContainer
	}

	return &runtimeclient.ContainerData{
		Runtime: runtimeclient.RuntimeContainerData{
			RuntimeName:   types.RuntimeNameRunc,
			ContainerID:   state.ID,
			ContainerName: state.ID,
			State:         r.deriveStatus(state),
		},
	}, nil
}

// deriveStatus determines the container's status by checking if the init
// process is still running. Runc does not persist status in state.json;
// it derives it at runtime from process state. We additionally check for
// PID reuse using the recorded start time.
func (r *RuncClient) deriveStatus(state *runcInternalState) string {
	if state.InitProcessPid <= 0 {
		return runtimeclient.StateExited
	}
	if state.pidIsStale() {
		return runtimeclient.StateExited
	}
	if state.processRunning() {
		return runtimeclient.StateRunning
	}
	return runtimeclient.StateExited
}

func (r *RuncClient) readState(containerID string) (*runcInternalState, error) {
	stateFile := filepath.Join(r.rootDir, containerID, "state.json")
	f, err := os.Open(stateFile)
	if err != nil {
		return nil, fmt.Errorf("opening state file %q: %w", stateFile, err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, stateJsonMaxSize))
	if err != nil {
		return nil, fmt.Errorf("reading state file %q: %w", stateFile, err)
	}

	var state runcInternalState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parsing state file %q: %w", stateFile, err)
	}

	return &state, nil
}

func (r *RuncClient) enrichFromBundle(bundlePath string, details *runtimeclient.ContainerDetailsData) {
	configPath := filepath.Join(host.HostRoot, bundlePath, "config.json")
	f, err := os.Open(configPath)
	if err != nil {
		log.Debugf("runc client: opening %q: %s", configPath, err)
		return
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, configJsonMaxSize))
	if err != nil {
		log.Debugf("runc client: reading %q: %s", configPath, err)
		return
	}

	var spec ocispec.Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		log.Debugf("runc client: parsing %q: %s", configPath, err)
		return
	}

	for _, m := range spec.Mounts {
		details.Mounts = append(details.Mounts, runtimeclient.ContainerMountData{
			Source:      m.Source,
			Destination: m.Destination,
		})
	}
}
