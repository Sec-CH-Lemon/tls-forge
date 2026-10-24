//go:build !windows

package tlsforge

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestTheMachinesDNSServersAreResolvConfs(t *testing.T) {
	dir := t.TempDir()
	defer func(was string) { resolvConf = was }(resolvConf)
	resolvConf = filepath.Join(dir, "resolv.conf")
	if got := machineDNSServers(); len(got) != 0 {
		t.Errorf("no file: %v", got)
	}
	conf := "# a comment\nsearch example.test\nnameserver 192.0.2.53\nnameserver\nnameserver not-an-address\n" +
		"sortlist 192.0.2.99\nnameserver 2001:db8::53\noptions ndots:2\n"
	if err := os.WriteFile(resolvConf, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := machineDNSServers(); !slices.Equal(got, []string{"192.0.2.53:53", "[2001:db8::53]:53"}) {
		t.Errorf("servers %v", got)
	}
	if err := os.WriteFile(resolvConf, []byte("search example.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := machineDNSServers(); len(got) != 0 {
		t.Errorf("none named: %v", got)
	}
}
