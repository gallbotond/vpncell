package daemon

import (
	"net/netip"
	"testing"

	"github.com/gallbotond/vpncell/internal/backend"
)

func TestNoteRoutes(t *testing.T) {
	rt := &rtProfile{}
	st := backend.Status{RoutesSource: "pushed", Routes: []netip.Prefix{netip.MustParsePrefix("172.30.0.0/16")}}
	if rt.noteRoutes(backend.Status{}) {
		t.Fatal("unknown routes counted")
	}
	if !rt.noteRoutes(st) {
		t.Fatal("first routes not counted")
	}
	if rt.noteRoutes(st) {
		t.Fatal("same routes counted twice")
	}
	st.RedirectGateway = true
	if !rt.noteRoutes(st) {
		t.Fatal("redirect-gateway change not counted")
	}
	// downLocked clears the key: the next connection logs its routes even
	// when they are the same.
	rt.routesKey = ""
	if !rt.noteRoutes(st) {
		t.Fatal("routes of a new connection not counted")
	}
}
