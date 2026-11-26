package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStatePrune(t *testing.T) {
	st := &stateStore{path: filepath.Join(t.TempDir(), "state.json")}
	st.s.Ports = map[string]int{"a": 1080, "gone": 1081}
	st.s.Indexes = map[string]int{"a": 0, "gone": 1}
	st.prune(func(n string) bool { return n == "a" })
	if len(st.s.Ports) != 1 || st.s.Ports["a"] != 1080 || len(st.s.Indexes) != 1 || st.s.Indexes["a"] != 0 {
		t.Fatalf("after prune: %+v", st.s)
	}
	data, err := os.ReadFile(st.path)
	var saved persistent
	if err != nil || json.Unmarshal(data, &saved) != nil || len(saved.Ports) != 1 || len(saved.Indexes) != 1 {
		t.Fatalf("saved state: %s %v", data, err)
	}
}
