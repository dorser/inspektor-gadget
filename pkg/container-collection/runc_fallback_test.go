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

package containercollection

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// TestWithRuncFallbackContainerEnrichment guards the conditions under which
// the runc fallback claims a container. It is a regression guard for the
// cross-runtime mis-labeling bug where a real runtime client (docker,
// containerd, etc.) briefly misses a container and the fallback permanently
// stamps it as RuntimeNameRunc.
func TestWithRuncFallbackContainerEnrichment(t *testing.T) {
	tests := []struct {
		name        string
		input       types.BasicRuntimeMetadata
		wantName    string
		wantRuntime types.RuntimeName
	}{
		{
			name: "unknown runtime + no name + id present => claimed by runc fallback",
			input: types.BasicRuntimeMetadata{
				ContainerID:   "abcdef",
				RuntimeName:   types.RuntimeNameUnknown,
				ContainerName: "",
			},
			wantName:    "abcdef",
			wantRuntime: types.RuntimeNameRunc,
		},
		{
			name: "empty runtime + no name => claimed by runc fallback",
			input: types.BasicRuntimeMetadata{
				ContainerID:   "id1",
				RuntimeName:   "",
				ContainerName: "",
			},
			wantName:    "id1",
			wantRuntime: types.RuntimeNameRunc,
		},
		{
			name: "docker runtime already set => fallback is a no-op",
			input: types.BasicRuntimeMetadata{
				ContainerID:   "id2",
				RuntimeName:   types.RuntimeNameDocker,
				ContainerName: "",
			},
			wantName:    "",
			wantRuntime: types.RuntimeNameDocker,
		},
		{
			name: "containerd runtime set, name set => no change",
			input: types.BasicRuntimeMetadata{
				ContainerID:   "id3",
				RuntimeName:   types.RuntimeNameContainerd,
				ContainerName: "nginx",
			},
			wantName:    "nginx",
			wantRuntime: types.RuntimeNameContainerd,
		},
		{
			name: "unknown runtime but name already set => no change",
			input: types.BasicRuntimeMetadata{
				ContainerID:   "id4",
				RuntimeName:   types.RuntimeNameUnknown,
				ContainerName: "alreadyset",
			},
			wantName:    "alreadyset",
			wantRuntime: types.RuntimeNameUnknown,
		},
		{
			name: "no container ID => fallback cannot claim",
			input: types.BasicRuntimeMetadata{
				ContainerID:   "",
				RuntimeName:   "",
				ContainerName: "",
			},
			wantName:    "",
			wantRuntime: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var cc ContainerCollection
			require.NoError(t, WithRuncFallbackContainerEnrichment()(&cc))
			require.Len(t, cc.containerEnrichers, 1)

			c := &Container{
				Runtime: RuntimeMetadata{BasicRuntimeMetadata: tc.input},
			}
			ok := cc.containerEnrichers[0](c)
			require.True(t, ok)
			require.Equal(t, tc.wantName, c.Runtime.ContainerName)
			require.Equal(t, tc.wantRuntime, c.Runtime.RuntimeName)
		})
	}
}
