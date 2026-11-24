package daemon

import (
	"sync"

	"github.com/gallbotond/vpncell/internal/control"
	"github.com/godbus/dbus/v5"
)

type broker struct {
	mu   sync.Mutex
	subs map[chan control.Event]struct{}
}

func newBroker() *broker { return &broker{subs: map[chan control.Event]struct{}{}} }

func (b *broker) subscribe() chan control.Event {
	ch := make(chan control.Event, 64)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *broker) unsubscribe(ch chan control.Event) {
	b.mu.Lock()
	delete(b.subs, ch)
	b.mu.Unlock()
}

func (b *broker) publish(e control.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- e:
		default: // slow subscriber: drop; it refreshes on its timer
		}
	}
}

// watchSleep calls notify after resume from suspend (logind PrepareForSleep
// with false).
func (d *Daemon) watchSleep(notify func()) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		d.log.Warn("suspend watch unavailable", "err", err)
		return
	}
	defer conn.Close()
	if err := conn.AddMatchSignal(dbus.WithMatchInterface("org.freedesktop.login1.Manager"),
		dbus.WithMatchMember("PrepareForSleep")); err != nil {
		d.log.Warn("suspend watch unavailable", "err", err)
		return
	}
	ch := make(chan *dbus.Signal, 8)
	conn.Signal(ch)
	for {
		select {
		case <-d.ctx.Done():
			return
		case s := <-ch:
			if s == nil {
				return
			}
			if len(s.Body) == 1 {
				if sleeping, ok := s.Body[0].(bool); ok && !sleeping {
					d.log.Info("resumed from suspend")
					notify()
				}
			}
		}
	}
}
