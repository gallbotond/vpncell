package openvpn

import (
	"strings"
	"testing"
)

func envOf(kv ...string) (func(string) string, []string) {
	m := map[string]string{}
	for _, x := range kv {
		k, v, _ := strings.Cut(x, "=")
		m[k] = v
	}
	return func(k string) string { return m[k] }, kv
}

// Issue #15: the hook records the pushed routes and redirect-gateway.
func TestParseHookEnvRoutes(t *testing.T) {
	get, env := envOf("script_type=up", "dev=vpntun0",
		"ifconfig_local=10.0.70.4", "ifconfig_netmask=255.255.255.0",
		"route_network_1=172.30.0.0", "route_netmask_1=255.255.0.0", "route_gateway_1=10.0.70.1",
		"route_network_2=198.51.100.7", "route_netmask_2=255.255.255.255",
		"route_ipv6_network_1=2000::/3", "route_ipv6_gateway_1=fd00:70::1",
		"foreign_option_1=dhcp-option DNS 172.30.2.53")
	e, err := ParseHookEnv(get, env)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range e.Routes {
		got = append(got, r.String())
	}
	if strings.Join(got, " ") != "2000::/3 172.30.0.0/16 198.51.100.7/32" || e.RedirectGateway {
		t.Fatalf("routes %v redirect %v", got, e.RedirectGateway)
	}
	get, env = envOf("script_type=up", "dev=vpntun0", "redirect_gateway=2")
	if e, _ := ParseHookEnv(get, env); !e.RedirectGateway {
		t.Fatal("redirect_gateway not seen")
	}
}
