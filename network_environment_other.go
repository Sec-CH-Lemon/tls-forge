//go:build !darwin && !linux && !windows

package tlsforge

import "fmt"

func systemNetworkRoute([]string) (networkRoute, error) {
	return networkRoute{}, fmt.Errorf("system network metadata unavailable on this platform")
}
