package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/chzyer/readline"

	"valky/internal/netutil"
)

// clientState is the snapshot the client console reports on.
type clientState struct {
	server   string
	agentID  string
	assigned string
	dev      string
	tunMode  bool
	segs     []string
	fm       *forwardManager
	sm       *socksManager
	nm       *natManager // egress NAT manager (nil in proxy mode)
}

func clientHelp() string {
	return "" +
		paint(cBold+cYellow, "COMMANDS") + "\n" +
		"  " + paint(cCyan, "status") + "           show connection, mode, routes and proxies\n" +
		"  " + paint(cCyan, "detach | bg") + "      close the console; client keeps running in the background\n" +
		"  " + paint(cCyan, "stop") + "             stop the client (disconnect)\n" +
		"  " + paint(cCyan, "help") + "             this help\n" +
		"  " + paint(cCyan, "quit | exit") + "      same as 'detach'\n"
}

func clientBanner(ctrlAddr string) string {
	art := "" +
		"╔══════════════════════════════════════════════════╗\n" +
		"║  " + cBold + cYellow + "V A L K Y" + cReset + cCyan + "  ::  agent link  ::  " + cMagenta + "night city" + cReset + cCyan + "     ║\n" +
		"╚══════════════════════════════════════════════════╝"
	tip := paint(cGray, "Tab = autocomplete   ↑/↓ = history   'status' = info   'detach' = leave running")
	return "\n" + cCyan + art + cReset + "\n" +
		paint(cGray, "control "+ctrlAddr) + authorTag() + "\n" + tip + "\n"
}

func clientPrompt() string {
	return cCyan + "agent" + cMagenta + "❯ " + cReset
}

func clientCompleter() *readline.PrefixCompleter {
	return readline.NewPrefixCompleter(
		readline.PcItem("status"),
		readline.PcItem("detach"),
		readline.PcItem("bg"),
		readline.PcItem("stop"),
		readline.PcItem("help"),
		readline.PcItem("exit"),
		readline.PcItem("quit"),
	)
}

// writeStatus renders the client status to w (used over the control channel).
func (cs *clientState) writeStatus(w io.Writer) {
	mode := paint(cGreen, "tunnel (L3 routing + forwards + socks)")
	if !cs.tunMode {
		mode = paint(cYellow, "proxy (TCP forwards + socks, no TUN)")
	}
	kv := func(k, v string) { fmt.Fprintf(w, "  %s %s\n", paint(cGray, pad(k, 12)), v) }
	fmt.Fprintln(w, paint(cBold+cYellow, "STATUS"))
	kv("server:", paint(cCyan, cs.server))
	kv("agent:", paint(cCyan, cs.agentID))
	kv("mode:", mode)
	kv("overlay:", paint(cGreen, cs.assigned))
	if cs.tunMode {
		kv("tun dev:", paint(cCyan, cs.dev))
	}
	// Scan live so the status reflects the host's current networks.
	segStr := strings.Join(cs.segs, ", ")
	if segs, err := netutil.LocalSegments(); err == nil {
		parts := make([]string, len(segs))
		for i, s := range segs {
			parts[i] = s.String()
		}
		segStr = strings.Join(parts, ", ")
	}
	kv("segments:", paint(cYellow, segStr))

	fwds := cs.fm.list()
	fmt.Fprintln(w, paint(cGray, "  port-forwards:"))
	if len(fwds) == 0 {
		fmt.Fprintln(w, paint(cGray, "    (none)"))
	}
	for _, f := range fwds {
		fmt.Fprintf(w, "    %s\n", paint(cCyan, f))
	}
	socks := cs.sm.list()
	fmt.Fprintln(w, paint(cGray, "  socks proxies:"))
	if len(socks) == 0 {
		fmt.Fprintln(w, paint(cGray, "    (none)"))
	}
	for _, s := range socks {
		fmt.Fprintf(w, "    %s\n", paint(cCyan, s))
	}
}
