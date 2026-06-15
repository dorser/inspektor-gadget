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

package ebpfoperator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
)

func TestPerfReaderTuning(t *testing.T) {
	tests := []struct {
		name       string
		env        map[string]string
		wantPages  int
		wantWakeup int
		wantFlush  time.Duration
	}{
		{
			name:       "defaults preserve historical behaviour",
			env:        nil,
			wantPages:  gadgets.PerfBufferPages,
			wantWakeup: 0,
			wantFlush:  0,
		},
		{
			name:       "buffer pages override",
			env:        map[string]string{envPerfBufferPages: "256"},
			wantPages:  256,
			wantWakeup: 0,
			wantFlush:  0,
		},
		{
			name:       "wakeup batching enables default flush",
			env:        map[string]string{envPerfWakeupEvents: "64"},
			wantPages:  gadgets.PerfBufferPages,
			wantWakeup: 64,
			wantFlush:  defaultPerfFlush,
		},
		{
			name:       "flush interval override",
			env:        map[string]string{envPerfWakeupEvents: "64", envPerfFlushMillis: "200"},
			wantPages:  gadgets.PerfBufferPages,
			wantWakeup: 64,
			wantFlush:  200 * time.Millisecond,
		},
		{
			name:       "flush can be disabled while batching",
			env:        map[string]string{envPerfWakeupEvents: "64", envPerfFlushMillis: "0"},
			wantPages:  gadgets.PerfBufferPages,
			wantWakeup: 64,
			wantFlush:  0,
		},
		{
			name:       "flush is ignored without batching",
			env:        map[string]string{envPerfFlushMillis: "200"},
			wantPages:  gadgets.PerfBufferPages,
			wantWakeup: 0,
			wantFlush:  0,
		},
		{
			name:       "invalid and non-positive values fall back to defaults",
			env:        map[string]string{envPerfBufferPages: "-5", envPerfWakeupEvents: "abc"},
			wantPages:  gadgets.PerfBufferPages,
			wantWakeup: 0,
			wantFlush:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			got := perfReaderTuning()
			require.Equal(t, tt.wantPages, got.pages)
			require.Equal(t, tt.wantWakeup, got.options.WakeupEvents)
			require.Equal(t, tt.wantFlush, got.flush)
		})
	}
}
