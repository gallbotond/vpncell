package main

import (
	"strings"
	"testing"

	"github.com/gallbotond/vpncell/internal/control"
)

func TestBanners(t *testing.T) {
	chain := []control.SessionRef{{ID: "aaaaaaaaaaaa", Profile: "a"}, {ID: "bbbbbbbbbbbb", Profile: "b"}}
	if got := enterBanner("b", "bbbbbbbbbbbb", chain); got != "vpncell: entering profile a → b (session bbbbbbbbbbbb; type exit to leave)" {
		t.Fatal(got)
	}
	if got := leaveBanner("b", chain); got != "vpncell: left profile b (back in profile a)" {
		t.Fatal(got)
	}
	if got := leaveBanner("a", chain[:1]); got != "vpncell: left profile a (back on the host network)" {
		t.Fatal(got)
	}
	if got := termTitle("x\x1b]0;evil\x07"); strings.ContainsAny(got, "\x1b\x07") {
		t.Fatalf("control characters in title: %q", got)
	}
}
