package daemon

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestAddrSetIgnoresLifetimeRefresh(t *testing.T) {
	_, ipn, _ := net.ParseCIDR("2a02:db8::1/64")
	ipn.IP = net.ParseIP("2a02:db8::1")
	s := addrSet{addrKey(3, ipn): true} // seeded from AddrList
	u := netlink.AddrUpdate{LinkAddress: *ipn, LinkIndex: 3, NewAddr: true}
	if s.changed(u) {
		t.Fatal("router advertisement refresh of a known address counted as a change")
	}
	u.NewAddr = false
	if !s.changed(u) {
		t.Fatal("removal not counted")
	}
	u.NewAddr = true
	if !s.changed(u) {
		t.Fatal("new address not counted")
	}
	if s.changed(u) {
		t.Fatal("second announcement counted")
	}
}
