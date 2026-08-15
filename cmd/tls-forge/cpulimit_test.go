package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A test cannot put its own process into a cgroup, so it writes the files the
// kernel would have written and points the reader at them.
func fakeCgroup(t *testing.T, files map[string]string) {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	original := cgroupRoot
	t.Cleanup(func() { cgroupRoot = original })
	cgroupRoot = root
}

func fakeCores(t *testing.T, n int) {
	t.Helper()
	original := numCPU
	t.Cleanup(func() { numCPU = original })
	numCPU = func() int { return n }
}

func TestCPULimit(t *testing.T) {
	for _, tc := range []struct {
		name        string
		cores       int
		files       map[string]string
		wantCPUs    int
		wantLimited bool
	}{
		{
			// Nothing to read: not Linux, or a kernel without either layout.
			name: "no cgroup at all", cores: 8,
			wantCPUs: 8, wantLimited: false,
		},
		{
			// cgroup v2 spells "no limit" as the word max, which does not parse
			// as a number, and that is the whole of the check.
			name: "v2 with no limit", cores: 8,
			files:    map[string]string{"cpu.max": "max 100000\n"},
			wantCPUs: 8, wantLimited: false,
		},
		{
			name: "v2 limited to two", cores: 64,
			files:    map[string]string{"cpu.max": "200000 100000\n"},
			wantCPUs: 2, wantLimited: true,
		},
		{
			// Rounded up: one and a half CPUs is nearer to room for two workers
			// than for one, and this only decides whether to print a warning.
			name: "v2 limited to one and a half", cores: 64,
			files:    map[string]string{"cpu.max": "150000 100000\n"},
			wantCPUs: 2, wantLimited: true,
		},
		{
			name: "v2 limited below one", cores: 64,
			files:    map[string]string{"cpu.max": "10000 100000\n"},
			wantCPUs: 1, wantLimited: true,
		},
		{
			// A quota above the machine's cores is not a limit worth reporting.
			name: "v2 limit above the hardware", cores: 2,
			files:    map[string]string{"cpu.max": "800000 100000\n"},
			wantCPUs: 2, wantLimited: false,
		},
		{
			name: "v2 with a malformed line", cores: 8,
			files:    map[string]string{"cpu.max": "200000\n"},
			wantCPUs: 8, wantLimited: false,
		},
		{
			name: "v2 with a period that is not a number", cores: 8,
			files:    map[string]string{"cpu.max": "200000 nonsense\n"},
			wantCPUs: 8, wantLimited: false,
		},
		{
			name: "v2 with a period of zero", cores: 8,
			files:    map[string]string{"cpu.max": "200000 0\n"},
			wantCPUs: 8, wantLimited: false,
		},
		{
			name: "v1 limited to three", cores: 64,
			files: map[string]string{
				"cpu/cpu.cfs_quota_us":  "300000\n",
				"cpu/cpu.cfs_period_us": "100000\n",
			},
			wantCPUs: 3, wantLimited: true,
		},
		{
			// -1 is how v1 spells no limit.
			name: "v1 with no limit", cores: 8,
			files: map[string]string{
				"cpu/cpu.cfs_quota_us":  "-1\n",
				"cpu/cpu.cfs_period_us": "100000\n",
			},
			wantCPUs: 8, wantLimited: false,
		},
		{
			name: "v1 missing its period", cores: 8,
			files:    map[string]string{"cpu/cpu.cfs_quota_us": "300000\n"},
			wantCPUs: 8, wantLimited: false,
		},
		{
			name: "v1 with a quota that is not a number", cores: 8,
			files: map[string]string{
				"cpu/cpu.cfs_quota_us":  "unlimited\n",
				"cpu/cpu.cfs_period_us": "100000\n",
			},
			wantCPUs: 8, wantLimited: false,
		},
		{
			// v2 is read first, so a machine carrying both follows v2.
			name: "both layouts present", cores: 64,
			files: map[string]string{
				"cpu.max":               "200000 100000\n",
				"cpu/cpu.cfs_quota_us":  "3200000\n",
				"cpu/cpu.cfs_period_us": "100000\n",
			},
			wantCPUs: 2, wantLimited: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeCores(t, tc.cores)
			fakeCgroup(t, tc.files)

			cpus, limited := cpuLimit()
			if cpus != tc.wantCPUs || limited != tc.wantLimited {
				t.Errorf("cpuLimit() = %d, %v; want %d, %v",
					cpus, limited, tc.wantCPUs, tc.wantLimited)
			}
		})
	}
}

func TestWarningNamesWhereTheNumberCameFrom(t *testing.T) {
	// "cores on this machine" would be a puzzle to read on a 64-core host
	// inside a container allowed two of them.
	fakeCores(t, 64)
	fakeCgroup(t, map[string]string{"cpu.max": "200000 100000\n"})

	server := batchServer(t)
	_, _, stderr := exec(t, "batch", "-c", "8", server.URL+"/one")

	if !strings.Contains(stderr, "the 2 CPUs this process is allowed") {
		t.Errorf("stderr = %q", stderr)
	}
	if strings.Contains(stderr, "on this machine") {
		t.Errorf("the warning claimed the machine's cores were the limit: %q", stderr)
	}
}
