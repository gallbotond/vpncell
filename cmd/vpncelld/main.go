// vpncelld is the privileged vpncell daemon. The same binary has internal
// modes for work that must happen between fork and exec or outside the
// daemon process: session-helper, session-exec and ovpn-hook.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/gallbotond/vpncell/internal/daemon"
	"github.com/gallbotond/vpncell/internal/session"
)

var version = "dev"

func init() {
	// Keep the main goroutine on the main thread for the whole life of the
	// process. No other goroutine can then run on the main thread, so it is
	// never used for namespace work (a locked goroutine that exits without
	// unlocking on the main thread would wedge it in a profile namespace).
	runtime.LockOSThread()
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "session-helper":
			os.Exit(session.RunHelper())
		case "session-exec":
			os.Exit(session.RunExec(os.Args[2:]))
		case "ovpn-hook":
			os.Exit(runOVPNHook(os.Args[2:]))
		case "teardown":
			// Used by the package's prerm on removal.
			log := slog.New(daemon.NewJournalHandler(os.Stderr, slog.LevelInfo))
			if err := daemon.Teardown(log); err != nil {
				fmt.Fprintln(os.Stderr, "vpncelld teardown:", err)
				os.Exit(1)
			}
			return
		case "version", "--version":
			fmt.Println(version)
			return
		case "run":
		default:
			fmt.Fprintf(os.Stderr, "usage: vpncelld [run]\n")
			os.Exit(2)
		}
	}
	level := slog.LevelInfo
	if os.Getenv("VPNCELL_DEBUG") != "" {
		level = slog.LevelDebug
	}
	log := slog.New(daemon.NewJournalHandler(os.Stderr, level))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	// Never signal.Ignore here: ignored signals are inherited across exec, so
	// sessions would start with SIGHUP ignored. Handled signals are reset to
	// the default in every child.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	opt := daemon.Options{Log: log, Reload: hup}
	log.Info("starting", "version", version)
	if err := daemon.Run(ctx, opt); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}
