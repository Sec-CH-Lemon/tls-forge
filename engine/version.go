// Package engine identifies the compiled profile execution contract.
package engine

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

//go:embed version.json
var metadata []byte
var current = parse(metadata)

type identity struct {
	version string
	major   int
}

func parse(data []byte) identity {
	var v struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		panic(err)
	}
	parts := strings.Split(v.Version, ".")
	if len(parts) != 3 {
		panic("invalid compiled engine version")
	}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || strconv.Itoa(n) != p {
			panic("invalid compiled engine version")
		}
		nums[i] = n
	}
	return identity{v.Version, nums[0]}
}

// Version is the compiled engine version, as engine/version.json says it.
func Version() string { return current.version }

// Major is the compiled engine major a profile's engine_major must equal.
func Major() int { return current.major }

// CheckBuildVersion rejects a misleading linker stamp; compatibility always uses
// the actual embedded major, never display text, environment or a git tag.
func CheckBuildVersion(v string) error {
	if strings.TrimPrefix(v, "v") != Version() {
		return fmt.Errorf("build version %q does not match compiled engine %s (major %d)", v, Version(), Major())
	}
	return nil
}
