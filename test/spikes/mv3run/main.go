// Test-only: runs the MV3 spike (DESIGN.md §9.1) with the tarball Firefox.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/gallbotond/vpncell/test/webdriver"
)

func main() {
	root := os.Args[1] // repo root
	gd := exec.Command(root+"/test/firefox/geckodriver", "--port", "4455")
	gd.Start()
	defer gd.Process.Kill()
	time.Sleep(time.Second)
	s, err := webdriver.New("http://127.0.0.1:4455", map[string]any{
		"binary": root + "/test/firefox/firefox/firefox",
		"args":   []string{"-headless"},
		"prefs":  map[string]any{"extensions.background.idle.timeout": 30},
	})
	if err != nil {
		panic(err)
	}
	defer s.Close()
	id, err := s.InstallAddon(root + "/test/spikes/mv3/ext")
	fmt.Println("installed", id, err)
	wait := 100 * time.Second
	if len(os.Args) > 2 {
		wait, _ = time.ParseDuration(os.Args[2])
	}
	time.Sleep(wait)
	fmt.Println("navigate after idle:", s.Navigate("http://127.0.0.1:8099/after-idle"))
	time.Sleep(3 * time.Second)
}
