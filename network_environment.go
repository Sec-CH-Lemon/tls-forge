package tlsforge

import (
	"crypto/sha256"
	"fmt"
	"github.com/Sec-CH-Lemon/tls-forge/v2/networkquality"
	"net"
	"slices"
	"strconv"
	"strings"
)

// networkRoute is kernel metadata, not a synthetic network estimate.
type networkRoute struct {
	index   int
	gateway string
	kind    string
}

func systemNetworkContext(policy networkquality.EnvironmentPolicy) (NetworkContext, error) {
	return networkContextFromRoute(policy, systemNetworkRoute, net.InterfaceByIndex)
}

func networkContextFromRoute(policy networkquality.EnvironmentPolicy, routeOf func([]string) (networkRoute, error), interfaceOf func(int) (*net.Interface, error)) (NetworkContext, error) {
	route, err := routeOf(policy.Families)
	if err != nil {
		return NetworkContext{}, err
	}
	if policy.Identity == "connection-type" {
		return NetworkContext{Type: route.kind}, nil
	}
	iface, err := interfaceOf(route.index)
	if err != nil {
		return NetworkContext{}, err
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return NetworkContext{}, err
	}
	parts := []string{strconv.Itoa(iface.Index), iface.Name, route.gateway}
	for _, addr := range addresses {
		parts = append(parts, addr.String())
	}
	slices.Sort(parts[3:])
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return NetworkContext{Type: route.kind, ID: fmt.Sprintf("route:%x", digest)}, nil
}
func networkInput(policy networkquality.EnvironmentPolicy, input *NetworkContext) (NetworkContext, error) {
	return networkInputFrom(policy, input, systemNetworkContext)
}

func networkInputFrom(policy networkquality.EnvironmentPolicy, input *NetworkContext, system func(networkquality.EnvironmentPolicy) (NetworkContext, error)) (NetworkContext, error) {
	if input != nil {
		return input.Clone(), input.Validate()
	}
	if policy.Source == "system" {
		if current, err := system(policy); err == nil {
			return current, nil
		} else if policy.Missing == "reject" {
			return NetworkContext{}, fmt.Errorf("network metadata: %w", err)
		}
	}
	if policy.Missing == "reject" {
		return NetworkContext{}, fmt.Errorf("requires actual network context")
	}
	return policy.Fallback.Clone(), nil
}
