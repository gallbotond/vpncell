package profile

import "testing"

func TestParseDefaults(t *testing.T) {
	p, err := Parse("work", []byte("backend = \"wireguard\"\n[wireguard]\nconfig = \"/x\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Autostart != AutostartOnUse || !p.NftablesEnabled() || p.UsePushedDNS() || len(p.RoutesP) != 2 {
		t.Fatalf("defaults wrong: %+v", p)
	}
}

func TestParseRejects(t *testing.T) {
	for name, in := range map[string]string{
		"unknown key": "backend = \"wireguard\"\nfoo = 1\n[wireguard]\nconfig = \"/x\"\n",
		"no backend":  "[wireguard]\nconfig = \"/x\"\n",
		"bad dns":     "backend = \"wireguard\"\n[wireguard]\nconfig = \"/x\"\n[dns]\nservers=[\"x\"]\n",
		"bad route":   "backend = \"wireguard\"\n[wireguard]\nconfig = \"/x\"\n[routing]\nroutes=[\"10/8\"]\n",
	} {
		if _, err := Parse("work", []byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse("Bad_Name", []byte("")); err == nil {
		t.Error("bad name accepted")
	}
}

func TestAllowed(t *testing.T) {
	p, _ := Parse("work", []byte("backend = \"wireguard\"\n[wireguard]\nconfig = \"/x\"\n[access]\nusers=[\"1234\"]\ngroups=[\"777\"]\n"))
	if !p.Allowed(0, 0, nil) || !p.Allowed(1234, 1, nil) || !p.Allowed(5, 5, []uint32{777}) || !p.Allowed(5, 777, nil) {
		t.Fatal("allowed callers refused")
	}
	if p.Allowed(5, 5, []uint32{6}) {
		t.Fatal("stranger allowed")
	}
}
