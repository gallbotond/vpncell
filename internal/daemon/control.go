package daemon

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/gallbotond/vpncell/internal/backend"
	"github.com/gallbotond/vpncell/internal/control"
	"github.com/gallbotond/vpncell/internal/netns"
	"github.com/gallbotond/vpncell/internal/profile"
)

// caller is an authenticated client.
type caller struct {
	*control.PeerCred
	admin bool
}

func (c *caller) may(p *profile.Profile) bool {
	return p != nil && p.Allowed(c.UID, c.GID, c.Groups)
}

func (d *Daemon) serveControl(ln *net.UnixListener) {
	for {
		uc, err := ln.AcceptUnix()
		if err != nil {
			if d.ctx.Err() != nil {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			d.log.Error("accept", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go d.serveConn(uc)
	}
}

// errNoReply means the handler already took over the connection.
var errHandedOff = errors.New("handed off")

func (d *Daemon) serveConn(uc *net.UnixConn) {
	conn := control.NewConn(uc)
	// Closing our descriptor never affects a session helper that received a
	// duplicate of it (Close does not shut the socket down).
	defer conn.Close()
	cred, err := control.Peer(uc)
	if err != nil {
		return
	}
	c := &caller{PeerCred: cred, admin: cred.UID == 0}
	// hello first, within a short time.
	uc.SetReadDeadline(time.Now().Add(10 * time.Second))
	var hello control.Request
	files, err := conn.RecvInto(&hello)
	control.CloseFiles(files)
	if err != nil || hello.Type != "hello" {
		conn.Send(control.Response{Type: "error", Error: control.Errorf(control.ErrBadRequest, "expected hello")})
		return
	}
	if hello.Version != control.Version {
		conn.Send(control.Response{Type: "error", Error: control.Errorf(control.ErrUnsupported, "protocol version %d not supported (server speaks %d)", hello.Version, control.Version)})
		return
	}
	conn.Send(control.Response{Type: "hello", ServerVersion: control.Version, UID: c.UID, Admin: c.admin})
	for {
		uc.SetReadDeadline(time.Now().Add(10 * time.Minute))
		raw, files, err := conn.Recv()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				d.log.Debug("control read", "uid", c.UID, "err", err)
			}
			return
		}
		uc.SetReadDeadline(time.Time{})
		var req control.Request
		if err := json.Unmarshal(raw, &req); err != nil {
			control.CloseFiles(files)
			conn.Send(control.Response{Type: "error", Error: control.Errorf(control.ErrBadRequest, "bad request")})
			continue
		}
		resp, err := d.handle(c, conn, &req, files)
		if errors.Is(err, errHandedOff) {
			return
		}
		if err != nil {
			var ce *control.Error
			if !errors.As(err, &ce) {
				ce = control.Errorf(control.ErrInternal, "%v", err)
			}
			resp = &control.Response{Type: "error", Error: ce}
		}
		if resp != nil {
			if err := conn.Send(resp); err != nil {
				return
			}
		}
		if req.Type == "subscribe" {
			return
		}
	}
}

func (d *Daemon) handle(c *caller, conn *control.Conn, req *control.Request, files []*os.File) (*control.Response, error) {
	if req.Type != "exec" {
		control.CloseFiles(files)
	}
	switch req.Type {
	case "list":
		return d.handleList(c), nil
	case "status":
		return d.handleStatus(c, req.Profile)
	case "up":
		p, rt, err := d.allowedProfile(c, req.Profile)
		if err != nil {
			return nil, err
		}
		if err := d.up(p, rt); err != nil {
			return nil, control.Errorf(control.ErrInternal, "bring up %s: %v", p.Name, err)
		}
		return &control.Response{Type: "ok", Message: "profile " + p.Name + " is " + rt.getState()}, nil
	case "down":
		p, rt, err := d.allowedProfile(c, req.Profile)
		if err != nil {
			return nil, err
		}
		if !c.admin && (req.Force || req.Kill) {
			for _, s := range d.sessions.list(p.Name) {
				if s.UID != c.UID {
					return nil, control.Errorf(control.ErrDenied, "profile %q has sessions of other users; only root may use --force or --kill", p.Name)
				}
			}
		}
		if err := d.down(p, rt, req.Force, req.Kill); err != nil {
			var ce *control.Error
			if errors.As(err, &ce) {
				ce.Sessions = d.redactSessions(c, ce.Sessions)
				return nil, ce
			}
			return nil, control.Errorf(control.ErrInternal, "take down %s: %v", p.Name, err)
		}
		return &control.Response{Type: "ok", Message: "profile " + p.Name + " is down"}, nil
	case "exec":
		return d.handleExec(c, conn, req, files)
	case "socks":
		return d.handleSocks(c, req.Profile)
	case "subscribe":
		d.handleSubscribe(c, conn)
		return nil, nil
	case "import":
		if !c.admin {
			return nil, control.Errorf(control.ErrDenied, "import is for root only (use sudo)")
		}
		return d.handleImport(req.Import)
	case "debug":
		if !c.admin {
			return nil, control.Errorf(control.ErrDenied, "debug is for root only")
		}
		return &control.Response{Type: "ok", Debug: map[string]uint64{
			"socket_namespace_mismatches": netns.MismatchCount.Load(),
			"sockets_created":             netns.SocketsCreated.Load(),
		}}, nil
	case "reload":
		if !c.admin {
			return nil, control.Errorf(control.ErrDenied, "reload is for root only")
		}
		d.loadProfiles()
		return &control.Response{Type: "ok", Message: "profiles reloaded"}, nil
	default:
		return nil, control.Errorf(control.ErrBadRequest, "unknown request %q", req.Type)
	}
}

func (d *Daemon) allowedProfile(c *caller, name string) (*profile.Profile, *rtProfile, error) {
	p, rt := d.getProfile(name)
	// Do not reveal whether a profile exists to users who may not use it.
	if p == nil || !c.may(p) {
		return nil, nil, control.Errorf(control.ErrNotFound, "no profile %q (or you may not use it)", name)
	}
	return p, rt, nil
}

func (d *Daemon) visibleProfiles(c *caller) []*profile.Profile {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []*profile.Profile
	for _, n := range profile.Names(d.profiles) {
		if p := d.profiles[n]; c.may(p) {
			out = append(out, p)
		}
	}
	return out
}

func (d *Daemon) handleList(c *caller) *control.Response {
	resp := &control.Response{Type: "ok", Profiles: []control.ProfileInfo{}}
	for _, p := range d.visibleProfiles(c) {
		_, rt := d.getProfile(p.Name)
		resp.Profiles = append(resp.Profiles, control.ProfileInfo{Name: p.Name, Backend: p.Backend, State: rt.getState()})
	}
	return resp
}

func (d *Daemon) redactSessions(c *caller, in []control.SessionInfo) []control.SessionInfo {
	out := make([]control.SessionInfo, 0, len(in))
	for _, s := range in {
		if !c.admin && s.UID != c.UID {
			s.Command = []string{"(session of another user)"}
			s.PID = 0
		}
		out = append(out, s)
	}
	return out
}

func (d *Daemon) handleStatus(c *caller, only string) (*control.Response, error) {
	var ps []*profile.Profile
	if only != "" {
		p, _, err := d.allowedProfile(c, only)
		if err != nil {
			return nil, err
		}
		ps = []*profile.Profile{p}
	} else {
		ps = d.visibleProfiles(c)
	}
	resp := &control.Response{Type: "ok", Status: []control.ProfileStatus{}}
	var wg sync.WaitGroup
	out := make([]control.ProfileStatus, len(ps))
	for i, p := range ps {
		wg.Add(1)
		go func(i int, p *profile.Profile) {
			defer wg.Done()
			out[i] = d.profileStatus(c, p)
		}(i, p)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	resp.Status = out
	return resp, nil
}

func (d *Daemon) profileStatus(c *caller, p *profile.Profile) control.ProfileStatus {
	_, rt := d.getProfile(p.Name)
	if isDesired(p.Name) && rt.op.TryLock() {
		d.refreshStatus(p, rt)
		rt.op.Unlock()
	}
	rt.mu.Lock()
	st := rt.status
	ps := control.ProfileStatus{
		Name: p.Name, Backend: p.Backend, Autostart: p.Autostart,
		State: rt.state, ExitIP: rt.exitIP, Interface: rt.ifname,
	}
	if !rt.upSince.IsZero() {
		ps.ConnectedAt = rt.upSince.Unix()
	}
	rt.mu.Unlock()
	if ps.State == "" {
		ps.State = backend.StateDown
	}
	if ps.State == backend.StateDown {
		ps.Interface = ""
	}
	if !st.LastHandshake.IsZero() {
		ps.LastHandshake = st.LastHandshake.Unix()
	}
	if !st.ConnectedAt.IsZero() {
		ps.ConnectedAt = st.ConnectedAt.Unix()
	}
	ps.RxBytes, ps.TxBytes = st.RxBytes, st.TxBytes
	for _, a := range st.Addresses {
		ps.Addresses = append(ps.Addresses, a.String())
	}
	servers, _ := d.dnsFor(p, st.PushedDNS, st.PushedSearch)
	for _, s := range servers {
		ps.DNS = append(ps.DNS, s.String())
	}
	ps.SocksPort = d.socksPort(p)
	ps.Sessions = d.redactSessions(c, d.sessions.list(p.Name))
	if ps.Sessions == nil {
		ps.Sessions = []control.SessionInfo{}
	}
	return ps
}

func (d *Daemon) handleSubscribe(c *caller, conn *control.Conn) {
	ch := d.events.subscribe()
	defer d.events.unsubscribe(ch)
	if err := conn.Send(control.Response{Type: "ok"}); err != nil {
		return
	}
	// Detect the client closing the connection.
	closed := make(chan struct{})
	go func() {
		for {
			_, files, err := conn.Recv()
			control.CloseFiles(files)
			if err != nil {
				close(closed)
				return
			}
		}
	}()
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-closed:
			return
		case <-ping.C:
			if conn.Send(control.Response{Type: "event", Event: &control.Event{Kind: "ping"}}) != nil {
				return
			}
		case e := <-ch:
			p, _ := d.getProfile(e.Profile)
			if p == nil || !c.may(p) {
				continue
			}
			ev := e
			if conn.Send(control.Response{Type: "event", Event: &ev}) != nil {
				return
			}
		}
	}
}
