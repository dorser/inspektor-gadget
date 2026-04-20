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

package containerhook

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestParseOCIRuntimeCmdline covers the runc/crun command-line parser. These
// cases are the regression guards for the rewrite of parseOCIRuntime that
// replaced the "last non-flag arg" heuristic with an explicit value-flag
// whitelist: prior to the rewrite, flag values like `--console-socket <path>`
// or `--preserve-fds <n>` were misinterpreted as the container-id positional.
func TestParseOCIRuntimeCmdline(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want ociRuntimeCmd
	}{
		{
			name: "create with separate bundle and pid-file",
			argv: []string{"runc", "create", "--bundle", "/b", "--pid-file", "/p", "myctr"},
			want: ociRuntimeCmd{command: "create", bundleDir: "/b", pidFile: "/p", containerID: "myctr"},
		},
		{
			name: "run with console-socket must not eat the socket path",
			argv: []string{"runc", "run", "--bundle", "/b", "--console-socket", "/tmp/s.sock", "myctr"},
			want: ociRuntimeCmd{command: "run", bundleDir: "/b", containerID: "myctr"},
		},
		{
			name: "run with preserve-fds number must not eat the number",
			argv: []string{"runc", "run", "--preserve-fds", "3", "--bundle", "/b", "myctr"},
			want: ociRuntimeCmd{command: "run", bundleDir: "/b", containerID: "myctr"},
		},
		{
			name: "global --root before subcommand",
			argv: []string{"runc", "--root", "/run/user/1000/runc", "run", "--bundle", "/b", "myctr"},
			want: ociRuntimeCmd{command: "run", runcRoot: "/run/user/1000/runc", bundleDir: "/b", containerID: "myctr"},
		},
		{
			name: "global --root=/path form",
			argv: []string{"runc", "--root=/custom", "create", "--bundle", "/b", "--pid-file", "/p", "myctr"},
			want: ociRuntimeCmd{command: "create", runcRoot: "/custom", bundleDir: "/b", pidFile: "/p", containerID: "myctr"},
		},
		{
			name: "short -b form",
			argv: []string{"runc", "create", "-b", "/b", "--pid-file", "/p", "myctr"},
			want: ociRuntimeCmd{command: "create", bundleDir: "/b", pidFile: "/p", containerID: "myctr"},
		},
		{
			name: "equals form --bundle=/b",
			argv: []string{"runc", "create", "--bundle=/b", "--pid-file=/p", "myctr"},
			want: ociRuntimeCmd{command: "create", bundleDir: "/b", pidFile: "/p", containerID: "myctr"},
		},
		{
			name: "boolean flags do not consume next arg",
			argv: []string{"runc", "run", "--detach", "--no-new-keyring", "--bundle", "/b", "myctr"},
			want: ociRuntimeCmd{command: "run", bundleDir: "/b", containerID: "myctr"},
		},
		{
			name: "double-dash ends flag parsing",
			argv: []string{"runc", "run", "--bundle", "/b", "--", "-weird-id"},
			want: ociRuntimeCmd{command: "run", bundleDir: "/b", containerID: "-weird-id"},
		},
		{
			name: "no subcommand found (kill, delete, exec are not handled here)",
			argv: []string{"runc", "kill", "myctr", "KILL"},
			want: ociRuntimeCmd{},
		},
		{
			name: "empty argv",
			argv: []string{},
			want: ociRuntimeCmd{},
		},
		{
			name: "create without pid-file but with explicit containerID (no-pid-file path)",
			argv: []string{"runc", "run", "--bundle", "/b", "myctr"},
			want: ociRuntimeCmd{command: "run", bundleDir: "/b", containerID: "myctr"},
		},
		{
			name: "global --log + --log-format before subcommand must not consume run",
			argv: []string{"runc", "--log", "/tmp/r.log", "--log-format", "json", "run", "--bundle", "/b", "myctr"},
			want: ociRuntimeCmd{command: "run", bundleDir: "/b", containerID: "myctr"},
		},
		{
			name: "container-id only (no --bundle, no --pid-file)",
			argv: []string{"runc", "run", "myctr"},
			want: ociRuntimeCmd{command: "run", containerID: "myctr"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseOCIRuntimeCmdline(tc.argv)
			require.Equal(t, tc.want, got)
		})
	}
}
