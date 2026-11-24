package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// firefoxPolicyPath is the system policy file that Firefox on Linux reads
// (deb and tarball builds; the snap reads it too).
const firefoxPolicyPath = "/etc/firefox/policies/policies.json"

// With Firefox's defaults, an http:// navigation makes Firefox (HTTPS-First
// mode) look up the host's HTTPS (type 65) DNS record itself, through the
// host's resolver, even when the tab uses a SOCKS proxy with proxyDNS. For a
// mapped container this sends the hostname outside the profile (found by
// TestBrowserHTTPNameNoHostDNS on Firefox 161). No WebExtension API can
// change this, so vpncell offers an opt-in Firefox policy.
//
// Default: turn off native HTTPS-record queries (HTTPS-First stays on).
// --strict: also turn HTTPS-First off, which also covers users who enable
// DNS-over-HTTPS (the lookup would otherwise go to the DoH server).
var firefoxPolicyPrefs = map[string]any{
	"network.dns.native_https_query": false,
}

var firefoxPolicyStrictPrefs = map[string]any{
	"dom.security.https_first":            false,
	"dom.security.https_first_schemeless": false,
}

// cmdFirefoxPolicy merges vpncell's locked prefs into the system policy file
// (keeping everything else in it), or removes them again.
func cmdFirefoxPolicy(args []string) error {
	usage := fmt.Errorf("usage: sudo vpncell firefox-policy install [--strict] | remove | show")
	if len(args) < 1 {
		return usage
	}
	op := args[0]
	strict := len(args) > 1 && args[1] == "--strict"
	switch op {
	case "install", "remove", "show":
	default:
		return usage
	}
	path := firefoxPolicyPath
	if p := os.Getenv("VPNCELL_FIREFOX_POLICY"); p != "" {
		path = p
	}
	doc := map[string]any{}
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("%s is not valid JSON; not touching it: %v", path, err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if op == "show" {
		out, _ := json.MarshalIndent(doc, "", "  ")
		fmt.Println(string(out))
		return nil
	}
	if os.Geteuid() != 0 && os.Getenv("VPNCELL_FIREFOX_POLICY") == "" {
		return fmt.Errorf("firefox-policy %s needs root", op)
	}
	policies, _ := doc["policies"].(map[string]any)
	if policies == nil {
		policies = map[string]any{}
	}
	prefs, _ := policies["Preferences"].(map[string]any)
	if prefs == nil {
		prefs = map[string]any{}
	}
	all := map[string]any{}
	for k, v := range firefoxPolicyPrefs {
		all[k] = v
	}
	for k, v := range firefoxPolicyStrictPrefs {
		all[k] = v
	}
	for k, v := range all {
		_, isStrict := firefoxPolicyStrictPrefs[k]
		if op == "install" && (!isStrict || strict) {
			prefs[k] = map[string]any{"Value": v, "Status": "locked"}
		} else {
			delete(prefs, k)
		}
	}
	if len(prefs) > 0 {
		policies["Preferences"] = prefs
	} else {
		delete(policies, "Preferences")
	}
	if len(policies) > 0 {
		doc["policies"] = policies
	} else {
		delete(doc, "policies")
	}
	if op == "remove" && len(doc) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		os.Remove(filepath.Dir(path)) // only if empty
		fmt.Println("removed", path)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	out, _ := json.MarshalIndent(doc, "", "  ")
	tmp := path + ".vpncell-tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	fmt.Println("updated", path, "(restart Firefox to apply)")
	return nil
}
