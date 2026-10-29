package profile

import (
	"fmt"
	"io/fs"
	"strconv"
	"strings"
)

// CaptureBasis returns the newest shipped full profile for a measured family
// and platform. Local aliases and Go catalogue presets are not implicit bases.
// Browser identity selects explicit data here, never runtime engine behavior.
func CaptureBasis(family, platform string) (*Profile, error) {
	return captureBasisIn(embedded, family, platform)
}

func captureBasisIn(source fs.FS, family, platform string) (*Profile, error) {
	if !ValidName(family) || !ValidName(platform) {
		return nil, fmt.Errorf("profile: invalid capture family/platform %q/%q", family, platform)
	}
	groups := groupsIn(source, "data")
	best, major := "", -1
	for name, platforms := range groups {
		version, ok := strings.CutPrefix(name, family+"_")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(version)
		if err != nil || n <= major {
			continue
		}
		for _, candidate := range platforms {
			if candidate == platform {
				best, major = name, n
				break
			}
		}
	}
	if best == "" {
		return nil, fmt.Errorf("profile: no shipped policy basis for %s/%s; select one with --policy-from", family, platform)
	}
	data, _, ok, err := lookup(source, "data", best+"_"+platform)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("profile: capture policy basis %s/%s disappeared", best, platform)
	}
	return Load(data)
}
