package main

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// How many CPUs this process may actually use.
//
// runtime.NumCPU reports the machine's cores and knows nothing about cgroups,
// so inside a container started with --cpus=2 on a 64-core host it answers 64.
// That is exactly the case where a warning about too many workers is worth
// having, and the one it would otherwise miss.
//
// Read rather than imposed: nothing here changes GOMAXPROCS. The number decides
// whether to print a sentence, and a library that reconfigured the scheduler as
// a side effect of being imported would be a large change to make for that.

// cgroupRoot is where the kernel exposes the limits, named so a test can point
// it at a directory it wrote. There is no other way to reach this code: a test
// cannot put its own process into a cgroup.
var cgroupRoot = "/sys/fs/cgroup"

// cpuLimit returns how many CPUs are available to this process, and whether
// that number came from a cgroup rather than from the hardware.
func cpuLimit() (cpus int, limited bool) {
	cores := numCPU()
	quota, ok := cgroupCPUs()
	if !ok || quota >= cores {
		return cores, false
	}
	return quota, true
}

// cgroupCPUs reads the quota, trying cgroup v2 and then v1.
//
// Both, because which one a machine uses is not something the reader chooses:
// v2 is the default on current distributions and v1 is still what a good deal
// of running infrastructure has. Anywhere without either, including every
// machine that is not Linux, the files are simply absent.
func cgroupCPUs() (int, bool) {
	if quota, period, ok := readCgroupV2(); ok {
		return cpusFrom(quota, period)
	}
	if quota, period, ok := readCgroupV1(); ok {
		return cpusFrom(quota, period)
	}
	return 0, false
}

// cpusFrom turns a quota and a period into a whole number of CPUs.
//
// Rounded up. A limit of one and a half CPUs is nearer to room for two workers
// than for one, and this number only decides whether to print a warning:
// rounding down would have it cry wolf over a fraction.
func cpusFrom(quota, period int64) (int, bool) {
	// A quota of -1 is how cgroup v1 spells "no limit", and a period of zero
	// would be a division by it.
	if quota <= 0 || period <= 0 {
		return 0, false
	}
	return int(math.Ceil(float64(quota) / float64(period))), true
}

// readCgroupV2 reads cpu.max, which holds both numbers on one line as
// "$QUOTA $PERIOD". An unlimited cgroup spells the quota "max", which does not
// parse as a number, and that is the whole of the check it needs.
func readCgroupV2() (quota, period int64, ok bool) {
	data, err := os.ReadFile(filepath.Join(cgroupRoot, "cpu.max"))
	if err != nil {
		return 0, 0, false
	}
	fields := strings.Fields(string(data))
	if len(fields) != 2 {
		return 0, 0, false
	}
	quota, ok = parseInt(fields[0])
	if !ok {
		return 0, 0, false
	}
	period, ok = parseInt(fields[1])
	if !ok {
		return 0, 0, false
	}
	return quota, period, true
}

// readCgroupV1 reads the same two numbers from the two files v1 keeps them in.
func readCgroupV1() (quota, period int64, ok bool) {
	quota, ok = readIntFile(filepath.Join(cgroupRoot, "cpu", "cpu.cfs_quota_us"))
	if !ok {
		return 0, 0, false
	}
	period, ok = readIntFile(filepath.Join(cgroupRoot, "cpu", "cpu.cfs_period_us"))
	if !ok {
		return 0, 0, false
	}
	return quota, period, true
}

func readIntFile(path string) (int64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	return parseInt(strings.TrimSpace(string(data)))
}

func parseInt(value string) (int64, bool) {
	n, err := strconv.ParseInt(value, 10, 64)
	return n, err == nil
}
