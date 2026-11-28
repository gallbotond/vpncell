package openvpn

import (
	"bufio"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeMgmt serves openvpn's management protocol on a unix socket: `state`
// answers with the given state line, other commands with SUCCESS. It
// records the commands it received.
func fakeMgmt(t *testing.T, stateLine string) (cmds func() []string) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "mgmt.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	old := mgmtPath
	mgmtPath = func(string) string { return sock }
	t.Cleanup(func() { mgmtPath = old; l.Close() })
	var mu sync.Mutex
	var got []string
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte(">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n"))
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					cmd := strings.TrimSpace(line)
					mu.Lock()
					got = append(got, cmd)
					mu.Unlock()
					if cmd == "state" {
						// An asynchronous notification first, as openvpn may send.
						c.Write([]byte(">STATE:1732800001,RECONNECTING,SIGUSR1,,,,,\r\n" + stateLine + "\r\nEND\r\n"))
					} else {
						c.Write([]byte("SUCCESS: " + cmd + "\r\n"))
					}
				}
			}(c)
		}
	}()
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
}

// Issue #31: only a connected openvpn is told to reconnect.
func TestReconnectOnlyWhenConnected(t *testing.T) {
	for _, c := range []struct {
		line  string
		state string
		sent  bool
	}{
		{"1732800000,CONNECTED,SUCCESS,10.0.70.4,203.0.113.1,1194,,", "CONNECTED", true},
		{"1732800000,WAIT,,,,,,", "WAIT", false},
		{"1732800000,RECONNECTING,ping-restart,,,,,", "RECONNECTING", false},
		{"1732800000,TCP_CONNECT,,,,,,", "TCP_CONNECT", false},
		{"1732800000,AUTH,,,,,,", "AUTH", false},
		{"1732800000,GET_CONFIG,,,,,,", "GET_CONFIG", false},
		{"1732800000,ASSIGN_IP,,10.0.70.4,,,,", "ASSIGN_IP", false},
		{"", "", false}, // no state yet
	} {
		cmds := fakeMgmt(t, c.line)
		state, sent, err := reconnectIfConnected("t-x")
		if err != nil {
			t.Fatalf("%s: %v", c.state, err)
		}
		if state != c.state || sent != c.sent {
			t.Errorf("%q: state %q sent %v, want %q %v", c.line, state, sent, c.state, c.sent)
		}
		signalled := false
		for _, x := range cmds() {
			if x == "signal SIGUSR1" {
				signalled = true
			}
		}
		if signalled != c.sent {
			t.Errorf("%q: SIGUSR1 sent = %v, want %v (commands %q)", c.line, signalled, c.sent, cmds())
		}
	}
}

func TestReconnectNoManagement(t *testing.T) {
	old := mgmtPath
	mgmtPath = func(string) string { return filepath.Join(t.TempDir(), "absent.sock") }
	defer func() { mgmtPath = old }()
	if _, sent, err := reconnectIfConnected("t-x"); err == nil || sent {
		t.Fatalf("sent %v err %v", sent, err)
	}
}
