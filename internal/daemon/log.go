package daemon

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
)

// JournalHandler writes one line per record with an sd-daemon priority
// prefix ("<3>" error … "<7>" debug), which journald turns into the record's
// priority.
type JournalHandler struct {
	mu    *sync.Mutex
	w     io.Writer
	level slog.Level
	inner slog.Handler
	buf   *strings.Builder
}

func NewJournalHandler(w io.Writer, level slog.Level) *JournalHandler {
	b := &strings.Builder{}
	return &JournalHandler{
		mu: &sync.Mutex{}, w: w, level: level, buf: b,
		inner: slog.NewTextHandler(b, &slog.HandlerOptions{Level: level, ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && (a.Key == slog.TimeKey || a.Key == slog.LevelKey) {
				return slog.Attr{}
			}
			return a
		}}),
	}
}

func (h *JournalHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func prio(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "<3>"
	case l >= slog.LevelWarn:
		return "<4>"
	case l >= slog.LevelInfo:
		return "<6>"
	default:
		return "<7>"
	}
}

func (h *JournalHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.buf.Reset()
	if err := h.inner.Handle(ctx, r); err != nil {
		return err
	}
	_, err := io.WriteString(h.w, prio(r.Level)+h.buf.String())
	return err
}

func (h *JournalHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &JournalHandler{mu: h.mu, w: h.w, level: h.level, buf: h.buf, inner: h.inner.WithAttrs(as)}
}

func (h *JournalHandler) WithGroup(n string) slog.Handler {
	return &JournalHandler{mu: h.mu, w: h.w, level: h.level, buf: h.buf, inner: h.inner.WithGroup(n)}
}
