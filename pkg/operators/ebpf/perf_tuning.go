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
	"os"
	"strconv"
	"time"

	"github.com/cilium/ebpf/perf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
)

// On kernels without BPF ring buffer support (< 5.8, e.g. RHEL/Ubuntu FIPS 5.4
// nodes) tracers fall back to a perf event array. By default the cilium/ebpf
// perf reader is configured with a wakeup watermark of a single event, so the
// kernel wakes the userspace consumer on *every* event. Under high event rates
// (for example trace_exec on an exec-heavy node) this per-event wakeup is the
// dominant source of CPU overhead.
//
// The following environment variables allow tuning the perf reader without
// changing the default behaviour:
//
//   - IG_PERF_BUFFER_PAGES: per-CPU perf buffer size in pages (default 64).
//     Larger buffers tolerate bigger bursts before dropping events; they do
//     not by themselves reduce CPU usage.
//
//   - IG_PERF_WAKEUP_EVENTS: number of events the kernel buffers per CPU before
//     waking the consumer (default 0, i.e. wake on every event). Setting this
//     to e.g. 64 amortizes the wakeup cost across many events and markedly
//     reduces consumer CPU at high event rates.
//
//   - IG_PERF_FLUSH_MS: when wakeup batching is enabled, the maximum time a
//     buffered event waits before the consumer is woken to drain it (default
//     100ms). This bounds the latency that batching would otherwise add when a
//     node is quiet, which matters for latency-sensitive consumers. Set to 0 to
//     disable the periodic flush (pure batching; not recommended when event
//     timeliness matters).
const (
	envPerfBufferPages  = "IG_PERF_BUFFER_PAGES"
	envPerfWakeupEvents = "IG_PERF_WAKEUP_EVENTS"
	envPerfFlushMillis  = "IG_PERF_FLUSH_MS"

	defaultPerfFlush = 100 * time.Millisecond
)

// perfTuning holds the resolved configuration for a perf event array reader.
type perfTuning struct {
	pages   int
	options perf.ReaderOptions
	flush   time.Duration // 0 = wake on every event (no batching, no flush)
}

// perfReaderTuning resolves the perf reader configuration from the environment.
// The defaults preserve the historical behaviour (64 pages, wake on every
// event), so the reader is only tuned when explicitly requested.
func perfReaderTuning() perfTuning {
	t := perfTuning{pages: gadgets.PerfBufferPages}

	if v := os.Getenv(envPerfBufferPages); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			t.pages = p
		}
	}

	if v := os.Getenv(envPerfWakeupEvents); v != "" {
		if w, err := strconv.Atoi(v); err == nil && w > 0 {
			t.options.WakeupEvents = w
			// Bound the latency batching adds; can be overridden below.
			t.flush = defaultPerfFlush
		}
	}

	// The flush interval is only meaningful when batching wakeups.
	if t.options.WakeupEvents > 0 {
		if v := os.Getenv(envPerfFlushMillis); v != "" {
			if ms, err := strconv.Atoi(v); err == nil && ms >= 0 {
				t.flush = time.Duration(ms) * time.Millisecond
			}
		}
	}

	return t
}
