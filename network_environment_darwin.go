package tlsforge

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/ebitengine/purego"
)

type darwinConfiguration struct {
	copyValue        func(uintptr, uintptr) uintptr
	release          func(uintptr)
	newString        func(uintptr, string, uint32) uintptr
	dictionaryValue  func(uintptr, uintptr) uintptr
	typeID           func(uintptr) uintptr
	stringTypeID     func() uintptr
	dictionaryTypeID func() uintptr
	stringBytes      func(uintptr, *byte, int64, uint32) bool
}

var darwinConfigurationAPI = sync.OnceValues(loadDarwinConfiguration)

func loadDarwinConfiguration() (*darwinConfiguration, error) {
	return bindDarwinConfiguration(purego.Dlopen, purego.Dlsym, purego.RegisterFunc)
}

func bindDarwinConfiguration(open func(string, int) (uintptr, error), symbol func(uintptr, string) (uintptr, error), register func(any, uintptr)) (*darwinConfiguration, error) {
	cf, err := open("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, err
	}
	sc, err := open("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, err
	}
	api := new(darwinConfiguration)
	for _, entry := range []struct {
		library uintptr
		name    string
		target  any
	}{
		{sc, "SCDynamicStoreCopyValue", &api.copyValue},
		{cf, "CFRelease", &api.release},
		{cf, "CFStringCreateWithCString", &api.newString},
		{cf, "CFDictionaryGetValue", &api.dictionaryValue},
		{cf, "CFGetTypeID", &api.typeID},
		{cf, "CFStringGetTypeID", &api.stringTypeID},
		{cf, "CFDictionaryGetTypeID", &api.dictionaryTypeID},
		{cf, "CFStringGetCString", &api.stringBytes},
	} {
		address, err := symbol(entry.library, entry.name)
		if err != nil {
			return nil, err
		}
		register(entry.target, address)
	}
	return api, nil
}
func (c *darwinConfiguration) stringRef(value string) uintptr {
	return c.newString(0, value, 0x08000100)
}
func (c *darwinConfiguration) dictionary(path string) uintptr {
	key := c.stringRef(path)
	if key == 0 {
		return 0
	}
	defer c.release(key)
	result := c.copyValue(0, key)
	if result != 0 && c.typeID(result) != c.dictionaryTypeID() {
		c.release(result)
		return 0
	}
	return result
}
func (c *darwinConfiguration) field(dictionary uintptr, name string) string {
	key := c.stringRef(name)
	if key == 0 {
		return ""
	}
	defer c.release(key)
	value := c.dictionaryValue(dictionary, key)
	if value == 0 || c.typeID(value) != c.stringTypeID() {
		return ""
	}
	var bytes [8192]byte
	if !c.stringBytes(value, &bytes[0], int64(len(bytes)), 0x08000100) {
		return ""
	}
	for i, b := range bytes {
		if b == 0 {
			return string(bytes[:i])
		}
	}
	return ""
}
func systemNetworkRoute(families []string) (networkRoute, error) {
	return darwinNetworkRoute(families, darwinConfigurationAPI, net.InterfaceByName)
}

func darwinNetworkRoute(families []string, load func() (*darwinConfiguration, error), interfaceOf func(string) (*net.Interface, error)) (networkRoute, error) {
	api, err := load()
	if err != nil {
		return networkRoute{}, err
	}
	for _, family := range families {
		entity := "IPv4"
		if family == "ipv6" {
			entity = "IPv6"
		}
		global := api.dictionary("State:/Network/Global/" + entity)
		if global == 0 {
			continue
		}
		name, service, gateway := api.field(global, "PrimaryInterface"), api.field(global, "PrimaryService"), api.field(global, "Router")
		api.release(global)
		if name == "" {
			continue
		}
		iface, err := interfaceOf(name)
		if err != nil {
			return networkRoute{}, err
		}
		kind := "unknown"
		if service != "" && !strings.ContainsAny(service, "/\x00") {
			dictionary := api.dictionary("Setup:/Network/Service/" + service + "/Interface")
			if dictionary != 0 {
				switch api.field(dictionary, "Type") {
				case "IEEE80211":
					kind = "wifi"
				case "Ethernet":
					kind = "ethernet"
				}
				// SystemConfiguration exposes Wi-Fi services as Type=Ethernet,
				// Hardware=AirPort. Type alone would choose the wired seed.
				if api.field(dictionary, "Hardware") == "AirPort" {
					kind = "wifi"
				}
				api.release(dictionary)
			}
		}
		return networkRoute{index: iface.Index, gateway: gateway, kind: kind}, nil
	}
	return networkRoute{}, fmt.Errorf("no default network route")
}
