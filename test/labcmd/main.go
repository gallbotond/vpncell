// vpncell-lab runs the local test lab in the foreground (test-only tool).
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/gallbotond/vpncell/test/lab"
)

func main() {
	dir := flag.String("dir", "/run/vpncell-lab", "directory for generated client configs")
	nwg := flag.Int("wg", 2, "number of WireGuard servers")
	novpn := flag.Int("ovpn", 0, "number of OpenVPN servers")
	cleanup := flag.Bool("cleanup", false, "only remove leftovers")
	flag.Parse()
	lab.Cleanup()
	if *cleanup {
		return
	}
	l := lab.New(*dir)
	defer l.Close()
	for i := 1; i <= *nwg; i++ {
		s, err := l.AddWireGuard(fmt.Sprintf("wg%d", i), i)
		if err != nil {
			fmt.Fprintln(os.Stderr, "lab:", err)
			l.Close()
			os.Exit(1)
		}
		fmt.Println("wireguard", s.Name, s.ClientConfig)
	}
	for i := 1; i <= *novpn; i++ {
		s, err := l.AddOpenVPN(fmt.Sprintf("ovpn%d", i), 10+i)
		if err != nil {
			fmt.Fprintln(os.Stderr, "lab:", err)
			l.Close()
			os.Exit(1)
		}
		fmt.Println("openvpn", s.Name, s.ClientConfig)
	}
	fmt.Println("lab ready")
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
}
