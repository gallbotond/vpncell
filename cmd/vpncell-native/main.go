// vpncell-native is the Firefox native messaging host. Firefox (or, for the
// snap, the xdg-desktop-portal) starts it as the user; it relays requests
// from the extension to vpncelld's control socket and pushes daemon events
// back. It holds no secrets itself and has no privileges.
//
// Extension → host: {"id": n, "type": "status"|"socks"|"up"|"down"|"list", "profile": "..."}
// Host → extension: {"id": n, "ok": true, "result": {...}} or {"id": n, "ok": false, "error": {...}}
// Host → extension events: {"event": {"kind": "profile_changed"|"credentials_changed"|"daemon_up"|"daemon_down", ...}}
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/gallbotond/vpncell/internal/brand"
	"github.com/gallbotond/vpncell/internal/client"
	"github.com/gallbotond/vpncell/internal/control"
)

var version = "dev"

const maxMsg = 1 << 20

type inMsg struct {
	ID      int64  `json:"id"`
	Type    string `json:"type"`
	Profile string `json:"profile,omitempty"`
}

type outMsg struct {
	ID     int64          `json:"id,omitempty"`
	OK     bool           `json:"ok"`
	Result any            `json:"result,omitempty"`
	Error  *control.Error `json:"error,omitempty"`
	Event  map[string]any `json:"event,omitempty"`
}

type writer struct {
	mu sync.Mutex
	w  *bufio.Writer
}

func (w *writer) send(m outMsg) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(b) > maxMsg {
		return fmt.Errorf("message too large")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(b)))
	w.w.Write(hdr[:])
	w.w.Write(b)
	return w.w.Flush()
}

func readMsg(r io.Reader) (*inMsg, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(hdr[:])
	if n > maxMsg {
		return nil, fmt.Errorf("message too large")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	var m inMsg
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println(version)
		return
	}
	// Firefox passes the manifest path and the calling extension's ID.
	if len(os.Args) > 2 && os.Args[2] != brand.ExtensionID {
		fmt.Fprintf(os.Stderr, "vpncell-native: refusing caller %q\n", os.Args[2])
		os.Exit(1)
	}
	w := &writer{w: bufio.NewWriter(os.Stdout)}
	go subscribeLoop(w)
	in := bufio.NewReader(os.Stdin)
	for {
		m, err := readMsg(in)
		if err != nil {
			// Firefox closed the port.
			return
		}
		go handle(w, m)
	}
}

func handle(w *writer, m *inMsg) {
	var req control.Request
	switch m.Type {
	case "list", "status":
		req = control.Request{Type: m.Type, Profile: m.Profile}
	case "socks", "up", "down":
		if m.Profile == "" {
			w.send(outMsg{ID: m.ID, Error: control.Errorf(control.ErrBadRequest, "profile missing")})
			return
		}
		req = control.Request{Type: m.Type, Profile: m.Profile}
	default:
		w.send(outMsg{ID: m.ID, Error: control.Errorf(control.ErrBadRequest, "unknown request %q", m.Type)})
		return
	}
	r, err := client.Call(req)
	if err != nil {
		var ce *control.Error
		if !errors.As(err, &ce) {
			ce = control.Errorf("daemon_unreachable", "%v", err)
		}
		w.send(outMsg{ID: m.ID, Error: ce})
		return
	}
	var result any
	switch m.Type {
	case "list":
		result = r.Profiles
	case "status":
		result = r.Status
	case "socks":
		result = r.Socks
	default:
		result = map[string]string{"message": r.Message}
	}
	w.send(outMsg{ID: m.ID, OK: true, Result: result})
}

// subscribeLoop keeps a subscription to daemon events and reports when the
// daemon becomes unreachable or reachable again.
func subscribeLoop(w *writer) {
	up := false
	first := true
	for {
		c, err := client.Dial()
		if err == nil {
			_, files, derr := c.Do(control.Request{Type: "subscribe"})
			control.CloseFiles(files)
			if derr == nil {
				if !up || first {
					w.send(outMsg{OK: true, Event: map[string]any{"kind": "daemon_up"}})
				}
				up, first = true, false
				for {
					var r control.Response
					fs, err := c.RecvInto(&r)
					control.CloseFiles(fs)
					if err != nil {
						break
					}
					if r.Type == "event" && r.Event != nil && r.Event.Kind != "ping" {
						w.send(outMsg{OK: true, Event: map[string]any{"kind": r.Event.Kind, "profile": r.Event.Profile, "state": r.Event.State}})
					}
				}
			}
			c.Close()
		}
		if up || first {
			w.send(outMsg{OK: true, Event: map[string]any{"kind": "daemon_down"}})
		}
		up, first = false, false
		time.Sleep(time.Second)
	}
}
