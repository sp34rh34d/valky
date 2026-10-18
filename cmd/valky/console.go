package main

import (
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"strings"

	"valky/internal/protocol"
	"valky/internal/uuid"
)

func consoleHelp() string {
	return "" +
		paint(cBold+cYellow, "COMMANDS") + "\n" +
		"  " + paint(cCyan, "ls | list") + "                                list connected agents (uuid, overlay, segments)\n" +
		"  " + paint(cCyan, "show <agent-uuid>") + "                        details of an agent, its rules and forwards\n" +
		"  " + paint(cCyan, "kick <agent-uuid>") + "                        disconnect an agent (it re-registers segments on reconnect)\n" +
		"  " + paint(cMagenta, "destroy <agent-uuid> <config-key>") + "        self-destruct a compromised agent (wipes identity +\n" +
		"  " + paint(cGray, "                                           ") + "binary); requires the config.ini key\n" +
		"  " + paint(cCyan, "route --add <CIDR> --id <agent-uuid> [--random] [--no-nat]") + "\n" +
		"  " + paint(cGray, "                                           ") + "allow an agent to reach a network (--random load-balances\n" +
		"  " + paint(cGray, "                                           ") + "across all agents that deliver it, pinning each flow;\n" +
		"  " + paint(cGray, "                                           ") + "egress NAT is on by default so LAN hosts can reply —\n" +
		"  " + paint(cGray, "                                           ") + "--no-nat keeps the real overlay source instead)\n" +
		"  " + paint(cCyan, "route --del <route-uuid>") + "                 remove the rule with that uuid\n" +
		"  " + paint(cCyan, "route --list | route -l") + "                  list rules (route-uuid, agent, network)\n" +
		"  " + paint(cCyan, "route --via <agent-uuid> <CIDR>") + "          publish a subnet route: agent delivers a network\n" +
		"  " + paint(cGray, "                                           ") + "it did not auto-advertise (reachable behind it)\n" +
		"  " + paint(cCyan, "route --via-del <uuid> | --via-list") + "      remove / list published subnet routes\n" +
		"  " + paint(cCyan, "forward --add --id <agent-uuid> --listen <ip:port> --to <ip:port>") + "\n" +
		"  " + paint(cGray, "                                           ") + "create a TCP port-forward on the agent\n" +
		"  " + paint(cCyan, "forward --del <forward-uuid>") + "             remove the port-forward with that uuid\n" +
		"  " + paint(cCyan, "forward --list | forward -l") + "              list port-forwards\n" +
		"  " + paint(cCyan, "socks --add --id <agent-uuid> --listen <ip:port>") + "\n" +
		"  " + paint(cGray, "                                           ") + "run a SOCKS5 proxy on the agent (no admin needed;\n" +
		"  " + paint(cGray, "                                           ") + "reaches whatever its 'route' rules allow)\n" +
		"  " + paint(cCyan, "socks --del <socks-uuid>") + "                 remove the SOCKS5 proxy with that uuid\n" +
		"  " + paint(cCyan, "socks --list | socks -l") + "                  list SOCKS5 proxies\n" +
		"  " + paint(cCyan, "detach | bg") + "                              leave the console; server keeps running\n" +
		"  " + paint(cCyan, "stop | shutdown") + "                          stop the server (disconnects clients)\n" +
		"  " + paint(cCyan, "help") + "                                     this help\n" +
		"  " + paint(cCyan, "quit | exit") + "                              same as 'detach'\n" +
		paint(cGray, "  uuid prefixes are accepted as long as they are unique.") + "\n"
}

// exec runs a single console command line, writing its output to w. It returns
// stop=true when the command asks the daemon to shut down.
func (h *hub) exec(line string, w io.Writer) (stop bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 {
		return false
	}
	switch fields[0] {
	case "ls", "list":
		h.cmdList(w)
	case "show":
		h.cmdShow(w, fields[1:])
	case "route":
		h.cmdRoute(w, fields[1:])
	case "forward", "fwd":
		h.cmdForward(w, fields[1:])
	case "socks":
		h.cmdSocks(w, fields[1:])
	case "kick", "rm":
		h.cmdKick(w, fields[1:])
	case "destroy":
		h.cmdDestroy(w, fields[1:])
	case "help", "?":
		fmt.Fprint(w, consoleHelp())
	case "stop", "shutdown":
		fmt.Fprintln(w, paint(cMagenta, "stopping server..."))
		return true
	default:
		fmt.Fprintf(w, "%s %q (try 'help')\n", paint(cMagenta, "unknown command"), fields[0])
	}
	return false
}

func (h *hub) cmdList(w io.Writer) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if len(h.byUUID) == 0 {
		fmt.Fprintln(w, paint(cGray, "(no agents connected)"))
		return
	}
	var rows [][]string
	for _, s := range h.byUUID {
		rows = append(rows, []string{s.uuid, modeLabel(s.mode), s.virtIP.String(), s.remote, cidrs(s.segs)})
	}
	base := []string{cCyan, "", cGreen, cGray, cYellow}
	renderTable(w, []string{"AGENT-UUID", "MODE", "OVERLAY", "REMOTE", "SEGMENTS"}, rows,
		func(col int, val string) string {
			if col == 1 {
				return modeColor(val)
			}
			return base[col]
		})
}

func (h *hub) cmdShow(w io.Writer, args []string) {
	if len(args) != 1 {
		fmt.Fprintln(w, "usage: show <agent-uuid>")
		return
	}
	agentID, _, err := h.resolveAgent(args[0])
	if err != nil {
		fmt.Fprintln(w, paint(cMagenta, err.Error()))
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	s := h.byUUID[agentID]
	fmt.Fprintf(w, "%s %s\n", paint(cBold+cYellow, "agent"), paint(cCyan, agentID))
	if s != nil {
		fmt.Fprintf(w, "  %s   %s\n  %s     %s\n  %s  %s\n  %s %s\n",
			paint(cGray, "status: "), paint(cGreen, "connected ("+s.remote+")"),
			paint(cGray, "mode: "), paint(modeColor(modeLabel(s.mode)), modeLabel(s.mode)),
			paint(cGray, "overlay:"), paint(cGreen, s.virtIP.String()),
			paint(cGray, "segments:"), paint(cYellow, cidrs(s.segs)))
	} else {
		fmt.Fprintf(w, "  %s   %s\n", paint(cGray, "status: "), paint(cGray, "disconnected"))
	}
	fmt.Fprintln(w, paint(cGray, "  rules:"))
	found := false
	for _, r := range h.rules {
		if r.agentID == agentID {
			fmt.Fprintf(w, "    %s %s %s\n", paint(cMagenta, r.id), paint(cGray, "->"), paint(cYellow, r.network.String()))
			found = true
		}
	}
	if !found {
		fmt.Fprintln(w, paint(cGray, "    (none)"))
	}
	fmt.Fprintln(w, paint(cGray, "  port-forwards:"))
	foundF := false
	for _, f := range h.forwards {
		if f.agentID == agentID {
			fmt.Fprintf(w, "    %s  %s %s %s\n", paint(cMagenta, f.id), paint(cCyan, f.listen), paint(cGray, "->"), paint(cYellow, f.target))
			foundF = true
		}
	}
	if !foundF {
		fmt.Fprintln(w, paint(cGray, "    (none)"))
	}
	fmt.Fprintln(w, paint(cGray, "  socks proxies:"))
	foundS := false
	for _, sp := range h.socks {
		if sp.agentID == agentID {
			fmt.Fprintf(w, "    %s  %s\n", paint(cMagenta, sp.id), paint(cCyan, sp.listen))
			foundS = true
		}
	}
	if !foundS {
		fmt.Fprintln(w, paint(cGray, "    (none)"))
	}
	fmt.Fprintln(w, paint(cGray, "  published subnet routes:"))
	foundP := false
	for _, p := range h.published {
		if p.agentID == agentID {
			fmt.Fprintf(w, "    %s  %s\n", paint(cMagenta, p.id), paint(cYellow, p.network.String()))
			foundP = true
		}
	}
	if !foundP {
		fmt.Fprintln(w, paint(cGray, "    (none)"))
	}
}

// cmdKick disconnects a connected agent. Its rules, forwards, socks and
// published routes persist (keyed by the agent's stable uuid), so when the agent
// reconnects it re-registers with its current segments and the config reapplies.
func (h *hub) cmdKick(w io.Writer, args []string) {
	if len(args) != 1 {
		fmt.Fprintln(w, "usage: kick <agent-uuid>")
		return
	}
	agentID, connected, err := h.resolveAgent(args[0])
	if err != nil {
		fmt.Fprintln(w, paint(cMagenta, err.Error()))
		return
	}
	if !connected {
		fmt.Fprintf(w, "%s\n", paint(cGray, "agent "+short(agentID)+" is already offline"))
		return
	}
	h.mu.RLock()
	s := h.byUUID[agentID]
	h.mu.RUnlock()
	if s != nil {
		s.conn.Close() // unblocks its read loop -> session cleanup runs
	}
	fmt.Fprintf(w, "%s %s %s\n", paint(cGreen, "agent kicked:"), paint(cCyan, short(agentID)),
		paint(cGray, "(it will re-register its current segments if it reconnects)"))
}

// cmdDestroy orders a connected agent to self-destruct (wipe its identity and
// binary, exit). It requires the config.ini key as confirmation, and purges the
// agent's rules/forwards/socks/published routes since it will not return.
func (h *hub) cmdDestroy(w io.Writer, args []string) {
	if len(args) != 2 {
		fmt.Fprintln(w, "usage: destroy <agent-uuid> <config-key>")
		fmt.Fprintln(w, paint(cGray, "       the second argument must be the server's config.ini key"))
		return
	}
	if subtle.ConstantTimeCompare([]byte(args[1]), []byte(h.cfg.Key)) != 1 {
		fmt.Fprintln(w, paint(cMagenta, "denied: destroy requires the config.ini key"))
		return
	}
	agentID, connected, err := h.resolveAgent(args[0])
	if err != nil {
		fmt.Fprintln(w, paint(cMagenta, err.Error()))
		return
	}
	if !connected {
		fmt.Fprintln(w, paint(cGray, "agent is offline; connect-time destroy is not possible (a destroyed agent never reconnects)"))
		return
	}

	h.mu.RLock()
	s := h.byUUID[agentID]
	h.mu.RUnlock()
	if s != nil {
		_ = s.send(protocol.TypeDestroy, nil)
	}

	// Purge the destroyed agent's configuration.
	h.mu.Lock()
	purgedNAT := false
	for id, r := range h.rules {
		if r.agentID == agentID {
			if r.nat {
				purgedNAT = true
			}
			delete(h.rules, id)
		}
	}
	for id, f := range h.forwards {
		if f.agentID == agentID {
			delete(h.forwards, id)
		}
	}
	for id, sp := range h.socks {
		if sp.agentID == agentID {
			delete(h.socks, id)
		}
	}
	for id, p := range h.published {
		if p.agentID == agentID {
			delete(h.published, id)
		}
	}
	h.mu.Unlock()
	if purgedNAT {
		h.pushNATAll()
	}
	h.saveState()

	fmt.Fprintf(w, "%s %s %s\n",
		paint(cMagenta, "self-destruct sent to"), paint(cCyan, short(agentID)),
		paint(cGray, "(agent wiping its identity + binary; its rules/forwards/socks/routes purged)"))
}

func (h *hub) cmdRoute(w io.Writer, args []string) {
	add, del, cidr, agentTok := "", "", "", ""
	viaAgent, viaCidr, viaDel := "", "", ""
	list, viaList, random := false, false, false
	nat := true // egress NAT is on by default; --no-nat opts out
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--add", "-a":
			if i+1 < len(args) {
				i++
				add = args[i]
				cidr = add
			}
		case "--random":
			random = true
		case "--no-nat", "--nonat":
			nat = false
		case "--id", "-i":
			if i+1 < len(args) {
				i++
				agentTok = args[i]
			}
		case "--del", "--rm", "-d":
			if i+1 < len(args) {
				i++
				del = args[i]
			}
		case "--list", "-l":
			list = true
		case "--via":
			// consumes two values: <agent-uuid> <CIDR>
			if i+1 < len(args) {
				i++
				viaAgent = args[i]
			}
			if i+1 < len(args) {
				i++
				viaCidr = args[i]
			}
		case "--via-del":
			if i+1 < len(args) {
				i++
				viaDel = args[i]
			}
		case "--via-list":
			viaList = true
		default:
			fmt.Fprintf(w, "unknown argument %q\n", args[i])
			return
		}
	}

	switch {
	case viaList:
		h.cmdViaList(w)
	case viaDel != "":
		h.cmdViaDel(w, viaDel)
	case viaAgent != "" || viaCidr != "":
		h.cmdViaAdd(w, viaAgent, viaCidr)
	case list:
		h.cmdRouteList(w)
	case add != "":
		h.cmdRouteAdd(w, cidr, agentTok, random, nat)
	case del != "":
		h.cmdRouteDel(w, del)
	default:
		fmt.Fprintln(w, "usage: route --add <CIDR> --id <agent-uuid> [--random] [--no-nat] | route --del <route-uuid> | route --list")
		fmt.Fprintln(w, "       route --via <agent-uuid> <CIDR> | route --via-del <uuid> | route --via-list")
	}
}

// cmdViaAdd publishes a destination-side subnet route: the given agent will
// deliver traffic for the network even if it did not auto-advertise it.
func (h *hub) cmdViaAdd(w io.Writer, agentTok, cidr string) {
	if agentTok == "" || cidr == "" {
		fmt.Fprintln(w, "usage: route --via <agent-uuid> <CIDR>")
		return
	}
	_, nd, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Fprintf(w, "invalid CIDR %q: %v\n", cidr, err)
		return
	}
	agentID, connected, err := h.resolveAgent(agentTok)
	if err != nil {
		fmt.Fprintln(w, paint(cMagenta, err.Error()))
		return
	}
	h.mu.Lock()
	p := &publishedNet{id: uuid.New(), agentID: agentID, network: nd}
	h.published[p.id] = p
	h.mu.Unlock()
	h.saveState()

	state := "agent offline; delivery resumes when it reconnects"
	if connected {
		state = "deliverable now"
	}
	fmt.Fprintf(w, "%s %s\n  agent %s delivers %s %s\n",
		paint(cGreen, "subnet route published:"), paint(cMagenta, p.id),
		paint(cCyan, short(agentID)), paint(cYellow, nd.String()), paint(cGray, "("+state+")"))
	fmt.Fprintf(w, "  %s\n", paint(cGray, "remember to allow a source with: route --add "+nd.String()+" --id <source-agent>"))
}

func (h *hub) cmdViaDel(w io.Writer, tok string) {
	h.mu.Lock()
	p, err := h.findPublishedLocked(tok)
	if err != nil {
		h.mu.Unlock()
		fmt.Fprintln(w, paint(cMagenta, err.Error()))
		return
	}
	delete(h.published, p.id)
	h.mu.Unlock()
	h.saveState()
	fmt.Fprintf(w, "%s %s (agent %s no longer delivers %s)\n",
		paint(cGreen, "subnet route removed:"), paint(cMagenta, p.id), paint(cCyan, short(p.agentID)), paint(cYellow, p.network.String()))
}

func (h *hub) cmdViaList(w io.Writer) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if len(h.published) == 0 {
		fmt.Fprintln(w, paint(cGray, "(no published subnet routes)"))
		return
	}
	var rows [][]string
	for _, p := range h.published {
		state := "offline"
		if h.byUUID[p.agentID] != nil {
			state = "online"
		}
		rows = append(rows, []string{p.id, p.agentID, p.network.String(), state})
	}
	base := []string{cMagenta, cCyan, cYellow, ""}
	renderTable(w, []string{"VIA-UUID", "AGENT-UUID", "NETWORK", "AGENT"}, rows,
		func(col int, val string) string {
			if col == 3 {
				return statusColor(val)
			}
			return base[col]
		})
}

func (h *hub) findPublishedLocked(tok string) (*publishedNet, error) {
	if p, ok := h.published[tok]; ok {
		return p, nil
	}
	var match *publishedNet
	for id, p := range h.published {
		if strings.HasPrefix(id, tok) {
			if match != nil {
				return nil, fmt.Errorf("prefix %q is ambiguous", tok)
			}
			match = p
		}
	}
	if match == nil {
		return nil, fmt.Errorf("no published subnet route matches %q", tok)
	}
	return match, nil
}

func (h *hub) cmdRouteAdd(w io.Writer, cidr, agentTok string, random, nat bool) {
	if cidr == "" || agentTok == "" {
		fmt.Fprintln(w, "usage: route --add <CIDR> --id <agent-uuid> [--random] [--no-nat]")
		return
	}
	_, nd, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Fprintf(w, "invalid CIDR %q: %v\n", cidr, err)
		return
	}
	agentID, connected, err := h.resolveAgent(agentTok)
	if err != nil {
		fmt.Fprintln(w, paint(cMagenta, err.Error()))
		return
	}

	h.mu.Lock()
	r := &rule{id: uuid.New(), agentID: agentID, network: nd, random: random, nat: nat}
	h.rules[r.id] = r
	s := h.byUUID[agentID]
	mode := ""
	hasSocks := false
	if s != nil {
		mode = s.mode
		for _, sp := range h.socks {
			if sp.agentID == agentID {
				hasSocks = true
				break
			}
		}
	}
	h.mu.Unlock()

	if s != nil {
		h.pushRoutes(s)
	}
	if nat {
		// NAT is applied by whichever agent delivers this network, not by the
		// authorized agent, so recompute for everyone connected.
		h.pushNATAll()
	}
	h.saveState()
	state := "agent offline; will apply on reconnect"
	if connected {
		state = "route pushed to agent"
	}
	fmt.Fprintf(w, "%s %s\n  agent %s can reach %s %s\n",
		paint(cGreen, "rule created:"), paint(cMagenta, r.id),
		paint(cCyan, short(agentID)), paint(cYellow, nd.String()), paint(cGray, "("+state+")"))
	if random {
		fmt.Fprintf(w, "  %s\n", paint(cBlue,
			"load-balancing (--random): flows to this network spread across all agents that deliver it, each flow pinned to one agent"))
	}
	if nat {
		fmt.Fprintf(w, "  %s\n", paint(cBlue,
			"egress NAT on (default): the delivering agent masquerades overlay traffic into this network so hosts can reply (Linux agents); use --no-nat to keep the real source"))
	} else {
		fmt.Fprintf(w, "  %s\n", paint(cYellow,
			"egress NAT off (--no-nat): hosts see the real overlay source — make sure the LAN routes "+h.cfg.Overlay.String()+" back to the delivering agent, or replies are lost"))
	}

	// In proxy mode there is no TUN, but the agent still routes L3 traffic for
	// this network through its userspace stack (TCP/UDP), so the rule is a real
	// route for another agent's TUN traffic as well as a local ACL. A SOCKS5
	// proxy remains an option for driving traffic from the operator host directly.
	if mode == "proxy" && !hasSocks {
		fmt.Fprintf(w, "  %s\n", paint(cYellow,
			"note: agent is in PROXY mode (no TUN) — L3 is delivered in userspace (TCP/UDP; no ICMP)."))
		fmt.Fprintf(w, "  %s\n", paint(cYellow,
			"        to drive traffic from this host directly you can also add SOCKS5: socks --add --id "+short(agentID)+" --listen 127.0.0.1:1080"))
	}
}

func (h *hub) cmdRouteDel(w io.Writer, routeTok string) {
	h.mu.Lock()
	r, err := h.findRuleLocked(routeTok)
	if err != nil {
		h.mu.Unlock()
		fmt.Fprintln(w, paint(cMagenta, err.Error()))
		return
	}
	delete(h.rules, r.id)
	s := h.byUUID[r.agentID]
	wasNAT := r.nat
	h.mu.Unlock()

	if s != nil {
		h.pushRoutes(s)
	}
	if wasNAT {
		h.pushNATAll()
	}
	h.saveState()
	fmt.Fprintf(w, "%s %s (agent %s no longer reaches %s)\n",
		paint(cGreen, "rule removed:"), paint(cMagenta, r.id), paint(cCyan, short(r.agentID)), paint(cYellow, r.network.String()))
}

func (h *hub) cmdRouteList(w io.Writer) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if len(h.rules) == 0 {
		fmt.Fprintln(w, paint(cGray, "(no rules)"))
		return
	}
	var rows [][]string
	for _, r := range h.rules {
		state := "offline"
		if h.byUUID[r.agentID] != nil {
			state = "online"
		}
		lb := "-"
		if r.random {
			lb = "random"
		}
		natCol := "-"
		if r.nat {
			natCol = "yes"
		}
		rows = append(rows, []string{r.id, r.agentID, r.network.String(), lb, natCol, state})
	}
	base := []string{cMagenta, cCyan, cYellow, cBlue, cGreen, ""}
	renderTable(w, []string{"ROUTE-UUID", "AGENT-UUID", "NETWORK", "LB", "NAT", "AGENT"}, rows,
		func(col int, val string) string {
			if col == 5 {
				return statusColor(val)
			}
			return base[col]
		})
}

func (h *hub) cmdForward(w io.Writer, args []string) {
	var agentTok, listen, target, del string
	list := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--add", "-a":
			// valueless flag; an add is inferred from --listen/--to/--id
		case "--id", "-i":
			if i+1 < len(args) {
				i++
				agentTok = args[i]
			}
		case "--listen", "-L":
			if i+1 < len(args) {
				i++
				listen = args[i]
			}
		case "--to", "--target", "-t":
			if i+1 < len(args) {
				i++
				target = args[i]
			}
		case "--del", "--rm", "-d":
			if i+1 < len(args) {
				i++
				del = args[i]
			}
		case "--list", "-l":
			list = true
		default:
			fmt.Fprintf(w, "unknown argument %q\n", args[i])
			return
		}
	}

	switch {
	case list:
		h.cmdForwardList(w)
	case del != "":
		h.cmdForwardDel(w, del)
	case agentTok != "" || listen != "" || target != "":
		h.cmdForwardAdd(w, agentTok, listen, target)
	default:
		fmt.Fprintln(w, "usage: forward --add --id <agent-uuid> --listen <ip:port> --to <ip:port> | forward --del <uuid> | forward --list")
	}
}

func (h *hub) cmdForwardAdd(w io.Writer, agentTok, listen, target string) {
	if agentTok == "" || listen == "" || target == "" {
		fmt.Fprintln(w, "usage: forward --add --id <agent-uuid> --listen <ip:port> --to <ip:port>")
		return
	}
	if _, _, err := net.SplitHostPort(listen); err != nil {
		fmt.Fprintf(w, "invalid --listen %q (use ip:port): %v\n", listen, err)
		return
	}
	thost, _, err := net.SplitHostPort(target)
	if err != nil {
		fmt.Fprintf(w, "invalid --to %q (use ip:port): %v\n", target, err)
		return
	}
	agentID, connected, err := h.resolveAgent(agentTok)
	if err != nil {
		fmt.Fprintln(w, paint(cMagenta, err.Error()))
		return
	}
	var tnet *net.IPNet
	if ip := net.ParseIP(thost); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			tnet = &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
		} else {
			tnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
		}
	}

	h.mu.Lock()
	f := &forward{id: uuid.New(), agentID: agentID, listen: listen, target: target, targetNet: tnet}
	h.forwards[f.id] = f
	s := h.byUUID[agentID]
	h.mu.Unlock()

	if s != nil {
		h.pushRoutes(s)
		h.pushForwards(s)
	}
	h.saveState()
	state := "agent offline; will apply on reconnect"
	if connected {
		state = "forward active on agent"
	}
	fmt.Fprintf(w, "%s %s\n  agent %s: %s %s %s %s\n",
		paint(cGreen, "port-forward created:"), paint(cMagenta, f.id),
		paint(cCyan, short(agentID)), paint(cCyan, listen), paint(cGray, "->"), paint(cYellow, target), paint(cGray, "("+state+")"))
	if tnet == nil {
		fmt.Fprintf(w, "  %s\n", paint(cMagenta, "warning: target is not an IP; no automatic route added. Add a manual rule if needed."))
	}
}

func (h *hub) cmdForwardDel(w io.Writer, tok string) {
	h.mu.Lock()
	f, err := h.findForwardLocked(tok)
	if err != nil {
		h.mu.Unlock()
		fmt.Fprintln(w, paint(cMagenta, err.Error()))
		return
	}
	delete(h.forwards, f.id)
	s := h.byUUID[f.agentID]
	h.mu.Unlock()

	if s != nil {
		h.pushRoutes(s)
		h.pushForwards(s)
	}
	h.saveState()
	fmt.Fprintf(w, "%s %s (%s %s %s)\n",
		paint(cGreen, "port-forward removed:"), paint(cMagenta, f.id), paint(cCyan, f.listen), paint(cGray, "->"), paint(cYellow, f.target))
}

func (h *hub) cmdForwardList(w io.Writer) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if len(h.forwards) == 0 {
		fmt.Fprintln(w, paint(cGray, "(no port-forwards)"))
		return
	}
	var rows [][]string
	for _, f := range h.forwards {
		state := "offline"
		if h.byUUID[f.agentID] != nil {
			state = "online"
		}
		rows = append(rows, []string{f.id, f.agentID, f.listen, f.target, state})
	}
	base := []string{cMagenta, cCyan, cCyan, cYellow, ""}
	renderTable(w, []string{"FORWARD-UUID", "AGENT-UUID", "LISTEN", "TARGET", "AGENT"}, rows,
		func(col int, val string) string {
			if col == 4 {
				return statusColor(val)
			}
			return base[col]
		})
}

func (h *hub) cmdSocks(w io.Writer, args []string) {
	var agentTok, listen, del string
	list := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--add", "-a":
			// valueless flag; an add is inferred from --listen/--id
		case "--id", "-i":
			if i+1 < len(args) {
				i++
				agentTok = args[i]
			}
		case "--listen", "-L":
			if i+1 < len(args) {
				i++
				listen = args[i]
			}
		case "--del", "--rm", "-d":
			if i+1 < len(args) {
				i++
				del = args[i]
			}
		case "--list", "-l":
			list = true
		default:
			fmt.Fprintf(w, "unknown argument %q\n", args[i])
			return
		}
	}

	switch {
	case list:
		h.cmdSocksList(w)
	case del != "":
		h.cmdSocksDel(w, del)
	case agentTok != "" || listen != "":
		h.cmdSocksAdd(w, agentTok, listen)
	default:
		fmt.Fprintln(w, "usage: socks --add --id <agent-uuid> --listen <ip:port> | socks --del <uuid> | socks --list")
	}
}

func (h *hub) cmdSocksAdd(w io.Writer, agentTok, listen string) {
	if agentTok == "" || listen == "" {
		fmt.Fprintln(w, "usage: socks --add --id <agent-uuid> --listen <ip:port>")
		return
	}
	if _, _, err := net.SplitHostPort(listen); err != nil {
		fmt.Fprintf(w, "invalid --listen %q (use ip:port): %v\n", listen, err)
		return
	}
	agentID, connected, err := h.resolveAgent(agentTok)
	if err != nil {
		fmt.Fprintln(w, paint(cMagenta, err.Error()))
		return
	}

	h.mu.Lock()
	sp := &socksProxy{id: uuid.New(), agentID: agentID, listen: listen}
	h.socks[sp.id] = sp
	s := h.byUUID[agentID]
	hasRule := false
	for _, r := range h.rules {
		if r.agentID == agentID {
			hasRule = true
			break
		}
	}
	h.mu.Unlock()

	if s != nil {
		h.pushSocks(s)
	}
	h.saveState()
	state := "agent offline; will apply on reconnect"
	if connected {
		state = "proxy active on agent"
	}
	fmt.Fprintf(w, "%s %s\n  agent %s: SOCKS5 on %s %s\n",
		paint(cGreen, "socks proxy created:"), paint(cMagenta, sp.id),
		paint(cCyan, short(agentID)), paint(cCyan, listen), paint(cGray, "("+state+")"))
	if !hasRule {
		fmt.Fprintf(w, "  %s\n", paint(cMagenta, "note: this agent has no route rules yet; add one so the proxy can reach a network, e.g. 'route --add 172.16.71.0/24 --id "+short(agentID)+"'"))
	}
}

func (h *hub) cmdSocksDel(w io.Writer, tok string) {
	h.mu.Lock()
	sp, err := h.findSocksLocked(tok)
	if err != nil {
		h.mu.Unlock()
		fmt.Fprintln(w, paint(cMagenta, err.Error()))
		return
	}
	delete(h.socks, sp.id)
	s := h.byUUID[sp.agentID]
	h.mu.Unlock()

	if s != nil {
		h.pushSocks(s)
	}
	h.saveState()
	fmt.Fprintf(w, "%s %s (%s)\n", paint(cGreen, "socks proxy removed:"), paint(cMagenta, sp.id), paint(cCyan, sp.listen))
}

func (h *hub) cmdSocksList(w io.Writer) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if len(h.socks) == 0 {
		fmt.Fprintln(w, paint(cGray, "(no socks proxies)"))
		return
	}
	var rows [][]string
	for _, sp := range h.socks {
		state := "offline"
		if h.byUUID[sp.agentID] != nil {
			state = "online"
		}
		rows = append(rows, []string{sp.id, sp.agentID, sp.listen, state})
	}
	base := []string{cMagenta, cCyan, cCyan, ""}
	renderTable(w, []string{"SOCKS-UUID", "AGENT-UUID", "LISTEN", "AGENT"}, rows,
		func(col int, val string) string {
			if col == 3 {
				return statusColor(val)
			}
			return base[col]
		})
}

func (h *hub) findSocksLocked(tok string) (*socksProxy, error) {
	if sp, ok := h.socks[tok]; ok {
		return sp, nil
	}
	var match *socksProxy
	for id, sp := range h.socks {
		if strings.HasPrefix(id, tok) {
			if match != nil {
				return nil, fmt.Errorf("prefix %q is ambiguous", tok)
			}
			match = sp
		}
	}
	if match == nil {
		return nil, fmt.Errorf("no socks proxy matches %q", tok)
	}
	return match, nil
}

func (h *hub) findForwardLocked(tok string) (*forward, error) {
	if f, ok := h.forwards[tok]; ok {
		return f, nil
	}
	var match *forward
	for id, f := range h.forwards {
		if strings.HasPrefix(id, tok) {
			if match != nil {
				return nil, fmt.Errorf("prefix %q is ambiguous", tok)
			}
			match = f
		}
	}
	if match == nil {
		return nil, fmt.Errorf("no port-forward matches %q", tok)
	}
	return match, nil
}

// resolveAgent turns a token (full uuid or unique prefix of a connected agent)
// into a full agent uuid. A full valid uuid is accepted even if offline.
func (h *hub) resolveAgent(tok string) (string, bool, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if uuid.Valid(tok) {
		_, connected := h.byUUID[tok]
		return tok, connected, nil
	}
	var match string
	for id := range h.byUUID {
		if strings.HasPrefix(id, tok) {
			if match != "" {
				return "", false, fmt.Errorf("prefix %q is ambiguous", tok)
			}
			match = id
		}
	}
	if match == "" {
		return "", false, fmt.Errorf("no connected agent matches %q (use the full uuid if it is offline)", tok)
	}
	return match, true, nil
}

// findRuleLocked resolves a route token (full uuid or unique prefix). Holds mu.
func (h *hub) findRuleLocked(tok string) (*rule, error) {
	if r, ok := h.rules[tok]; ok {
		return r, nil
	}
	var match *rule
	for id, r := range h.rules {
		if strings.HasPrefix(id, tok) {
			if match != nil {
				return nil, fmt.Errorf("prefix %q is ambiguous", tok)
			}
			match = r
		}
	}
	if match == nil {
		return nil, fmt.Errorf("no rule matches %q", tok)
	}
	return match, nil
}
