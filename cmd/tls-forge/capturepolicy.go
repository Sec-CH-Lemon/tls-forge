package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Sec-CH-Lemon/tls-forge/capture"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
)

func capturePolicyBasis(measured *capture.Capture, explicit string) (*profile.Profile, error) {
	if explicit != "" {
		return profile.Get(explicit)
	}
	if measured == nil {
		return nil, fmt.Errorf("capture: nil measurement")
	}
	family, _ := capturedBrowser(measured)
	platform := ""
	if measured.Navigator != nil {
		// userAgentData.platform is measured identity for choosing explicit data.
		platform = map[string]string{"macOS": "macos", "Windows": "windows", "Linux": "linux", "Android": "android", "iOS": "ios"}[measured.Navigator.Platform]
	}
	if platform == "" {
		platform = platformFrom(measured.UserAgent())
	}
	if platform == "" {
		return nil, fmt.Errorf("capture: platform unmeasured; select an explicit --policy-from profile")
	}
	return profile.CaptureBasis(family, platform)
}

func captureProvenancePath(where, path string, p *profile.Profile, explicit string) string {
	version, platform := profile.Split(p.Name)
	if platform == "" {
		platform = platformFrom(p.UserAgent)
	}
	if platform == "" {
		platform = "unknown"
	}
	if explicit != "" {
		return filepath.Join(explicit, version, platform+".json")
	}
	root := filepath.Dir(path)
	if info, err := os.Stat(where); err == nil && info.IsDir() {
		return filepath.Join(where, "provenance", version, platform+".json")
	}
	// A nested subtree keeps metadata out of the registry's two-level JSON scan.
	return filepath.Join(root, "provenance", version, filepath.Base(path))
}
