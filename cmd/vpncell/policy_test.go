package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFirefoxPolicyMergeAndRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policies.json")
	t.Setenv("VPNCELL_FIREFOX_POLICY", path)
	os.WriteFile(path, []byte(`{"policies":{"DisableTelemetry":true,"Preferences":{"browser.foo":{"Value":1,"Status":"default"}}}}`), 0o644)
	if err := cmdFirefoxPolicy([]string{"install"}); err != nil {
		t.Fatal(err)
	}
	var doc map[string]map[string]any
	data, _ := os.ReadFile(path)
	json.Unmarshal(data, &doc)
	prefs := doc["policies"]["Preferences"].(map[string]any)
	if doc["policies"]["DisableTelemetry"] != true || prefs["browser.foo"] == nil || prefs["network.dns.native_https_query"] == nil || prefs["dom.security.https_first"] != nil {
		t.Fatalf("install: %s", data)
	}
	cmdFirefoxPolicy([]string{"install", "--strict"})
	data, _ = os.ReadFile(path)
	json.Unmarshal(data, &doc)
	if doc["policies"]["Preferences"].(map[string]any)["dom.security.https_first"] == nil {
		t.Fatalf("strict: %s", data)
	}
	cmdFirefoxPolicy([]string{"remove"})
	data, _ = os.ReadFile(path)
	doc = nil
	json.Unmarshal(data, &doc)
	prefs = doc["policies"]["Preferences"].(map[string]any)
	if len(prefs) != 1 || doc["policies"]["DisableTelemetry"] != true {
		t.Fatalf("remove kept/lost the wrong entries: %s", data)
	}
}
