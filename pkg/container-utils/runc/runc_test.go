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

package runc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// TestStateJsonInitProcessStartFormats guards against the regression where
// runc serializes "init_process_start" as a JSON number but the struct field
// was typed as string, which made every pre-existing container unparseable.
func TestStateJsonInitProcessStartFormats(t *testing.T) {
	cases := map[string]string{
		"numeric":       `{"id":"c1","init_process_pid":42,"init_process_start":12345678}`,
		"quoted-string": `{"id":"c2","init_process_pid":42,"init_process_start":"12345678"}`,
		"absent":        `{"id":"c3","init_process_pid":42}`,
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			var s runcInternalState
			err := json.Unmarshal([]byte(payload), &s)
			require.NoError(t, err)
			require.Equal(t, 42, s.InitProcessPid)
		})
	}
}

func TestBundlePath(t *testing.T) {
	s := runcInternalState{}
	s.Config.Labels = []string{"foo=bar", "bundle=/var/lib/runc/demo", "other=x"}
	require.Equal(t, "/var/lib/runc/demo", s.bundlePath())

	s.Config.Labels = []string{"foo=bar"}
	require.Equal(t, "", s.bundlePath())
}

func TestIsPauseContainer(t *testing.T) {
	tests := []struct {
		name   string
		labels []string
		want   bool
	}{
		{"kubelet POD", []string{"io.kubernetes.container.name=POD"}, true},
		{"kubelet app", []string{"io.kubernetes.container.name=myapp"}, false},
		{"dockershim sandbox", []string{"io.kubernetes.docker.type=podsandbox"}, true},
		{"cri-containerd sandbox", []string{"io.cri-containerd.kind=sandbox"}, true},
		{"cri-containerd container", []string{"io.cri-containerd.kind=container"}, false},
		{"no labels", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := runcInternalState{}
			s.Config.Labels = tc.labels
			require.Equal(t, tc.want, s.isPauseContainer())
		})
	}
}

// TestGetContainerByID_ParsesNumericStart is a small end-to-end sanity check
// that GetContainer() works when state.json has a numeric init_process_start
// (the exact shape runc writes).
func TestGetContainerByID_ParsesNumericStart(t *testing.T) {
	tmp := t.TempDir()
	ctrDir := filepath.Join(tmp, "demo-container")
	require.NoError(t, os.MkdirAll(ctrDir, 0o755))

	// Use the current process's PID so the liveness check finds it alive.
	pid := os.Getpid()
	payload := `{
		"id": "demo-container",
		"init_process_pid": ` + itoa(pid) + `,
		"config": {
			"labels": ["bundle=/does/not/matter"]
		}
	}`
	require.NoError(t, os.WriteFile(filepath.Join(ctrDir, "state.json"), []byte(payload), 0o644))

	client := &RuncClient{rootDir: tmp}
	c, err := client.GetContainer("demo-container")
	require.NoError(t, err)
	require.Equal(t, types.RuntimeNameRunc, c.Runtime.RuntimeName)
	require.Equal(t, "demo-container", c.Runtime.ContainerID)
	require.Equal(t, "demo-container", c.Runtime.ContainerName)
	require.Equal(t, runtimeclient.StateRunning, c.Runtime.State)
}

// TestPidIsStale exercises the PID-reuse detection. When the recorded
// starttime matches the live /proc/[pid]/stat starttime, the container is
// "fresh"; when it differs, it is considered stale. This also indirectly
// exercises parsing init_process_start as a JSON number (the exact format
// runc writes on disk).
func TestPidIsStale(t *testing.T) {
	pid := os.Getpid()
	realStart := readProcStartTime(pid)
	require.NotEmpty(t, realStart, "could not read /proc/self/stat starttime")

	// Fresh: numeric init_process_start matching live starttime.
	freshJSON := `{"id":"a","init_process_pid":` + itoa(pid) + `,"init_process_start":` + realStart + `}`
	var fresh runcInternalState
	require.NoError(t, json.Unmarshal([]byte(freshJSON), &fresh))
	require.False(t, fresh.pidIsStale())

	// Stale: numeric init_process_start that cannot match (arbitrarily high).
	staleJSON := `{"id":"a","init_process_pid":` + itoa(pid) + `,"init_process_start":99999999999999}`
	var stale runcInternalState
	require.NoError(t, json.Unmarshal([]byte(staleJSON), &stale))
	require.True(t, stale.pidIsStale())

	// Absent init_process_start: do not declare stale (backward-compat
	// with runc versions that didn't serialize it or with crun).
	noStartJSON := `{"id":"a","init_process_pid":` + itoa(pid) + `}`
	var noStart runcInternalState
	require.NoError(t, json.Unmarshal([]byte(noStartJSON), &noStart))
	require.False(t, noStart.pidIsStale())
}

// TestGetContainerByID_PauseSkipped verifies that pause containers surface
// as ErrPauseContainer (consistent with the other runtime clients).
func TestGetContainerByID_PauseSkipped(t *testing.T) {
	tmp := t.TempDir()
	ctrDir := filepath.Join(tmp, "pause1")
	require.NoError(t, os.MkdirAll(ctrDir, 0o755))

	payload := `{
		"id": "pause1",
		"init_process_pid": ` + itoa(os.Getpid()) + `,
		"config": {
			"labels": ["io.kubernetes.container.name=POD"]
		}
	}`
	require.NoError(t, os.WriteFile(filepath.Join(ctrDir, "state.json"), []byte(payload), 0o644))

	client := &RuncClient{rootDir: tmp}
	_, err := client.GetContainer("pause1")
	require.ErrorIs(t, err, runtimeclient.ErrPauseContainer)
}

// TestGetContainers_SkipsUnparsable makes sure one bad entry doesn't fail
// the whole enumeration.
func TestGetContainers_SkipsUnparsable(t *testing.T) {
	tmp := t.TempDir()
	// Good entry.
	good := filepath.Join(tmp, "good")
	require.NoError(t, os.MkdirAll(good, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(good, "state.json"),
		[]byte(`{"id":"good","init_process_pid":`+itoa(os.Getpid())+`}`), 0o644))
	// Bad entry (empty file).
	bad := filepath.Join(tmp, "bad")
	require.NoError(t, os.MkdirAll(bad, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(bad, "state.json"), []byte(``), 0o644))

	client := &RuncClient{rootDir: tmp}
	cs, err := client.GetContainers()
	require.NoError(t, err)
	require.Len(t, cs, 1)
	require.Equal(t, "good", cs[0].Runtime.ContainerID)
}

// small itoa to avoid importing strconv only for tests
func itoa(i int) string {
	// positive int, small: ok for test fixtures
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
