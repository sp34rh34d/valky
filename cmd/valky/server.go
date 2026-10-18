package main

import (
	"crypto/subtle"
	"flag"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"valky/internal/config"
	"valky/internal/netutil"
	"valky/internal/protocol"
	"valky/internal/uuid"
)

// agentReadTimeout is how long the server waits for any frame from an agent
// before declaring the connection dead. It must exceed the agent's keepalive
// interval (20s) with margin.
const agentReadTimeout = 60 * time.Second

// session is one authenticated, connected client (agent).
type session struct {
	uuid   string
	remote string
	virtIP net.IP
	segs   []*net.IPNet // LAN segments the client advertised
	mode   string       // "tunnel" or "proxy" (reported by the agent)
	conn   net.Conn
	wmu    sync.Mutex

	// stream relay state (guarded by hub.smu)
	streams  map[uint32]*streamEnd // wire id on this connection -> peer end
	inboundN uint32                // counter for ids allocated toward this session
}

// streamEnd points to the other side of a relayed port-forward stream.
type streamEnd struct {
	peer   *session
	peerID uint32
}

func (s *session) send(t protocol.MessageType, payload []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return protocol.WriteFrame(s.conn, t, payload)
}

// rule is a routing/ACL entry: agent <agentID> is allowed to reach <network>.
// Each rule has its own UUID so the operator can delete it by id.
type rule struct {
	id      string
	agentID string
	network *net.IPNet
	random  bool // load-balance across agents that deliver the same network
	nat     bool // masquerade overlay traffic on the agent that delivers network
}

// forward is a client-side TCP port-forward: agent <agentID> listens on
// <listen> and proxies connections to <target> over the tunnel. targetNet is
// the target host as a /32, used to auto-authorize and route the traffic.
type forward struct {
	id        string
	agentID   string
	listen    string // ip:port on the agent
	target    string // ip:port reachable through the tunnel
	targetNet *net.IPNet
}

// socksProxy is a client-side SOCKS5 listener: agent <agentID> exposes a proxy
// on <listen> that can reach whatever the agent's route rules allow.
type socksProxy struct {
	id      string
	agentID string
	listen  string
}

// publishedNet is a destination-side subnet route: the server delivers traffic
// for <network> to agent <agentID>, even if the agent did not auto-advertise it
// as a connected segment (e.g. a network reachable behind the agent).
type publishedNet struct {
	id      string
	agentID string
	network *net.IPNet
}

// hub holds live sessions and the rule table, and performs routing + ACL.
type hub struct {
	cfg       *config.ServerConfig
	encrypt   bool   // require an encrypted transport with each agent
	statePath string // where the policy is persisted ("" disables persistence)

	mu        sync.RWMutex
	smu       sync.Mutex          // guards all sessions' stream tables/counters
	byUUID    map[string]*session // agent uuid -> live session
	byVIP     map[string]*session // virtual IP -> live session
	usedIPs   map[string]bool
	rules     map[string]*rule         // rule uuid -> rule (persists across reconnects)
	forwards  map[string]*forward      // forward uuid -> forward
	socks     map[string]*socksProxy   // socks uuid -> socks proxy
	published map[string]*publishedNet // published-net uuid -> subnet route
}

func newHub(cfg *config.ServerConfig) *hub {
	return &hub{
		cfg:       cfg,
		byUUID:    map[string]*session{},
		byVIP:     map[string]*session{},
		usedIPs:   map[string]bool{},
		rules:     map[string]*rule{},
		forwards:  map[string]*forward{},
		socks:     map[string]*socksProxy{},
		published: map[string]*publishedNet{},
	}
}

// runServer orchestrates the server lifecycle. The actual hub always runs as a
// background daemon so that detaching/closing the console never drops client
// connections. The foreground process is only an interactive console attached
// to the daemon over a local control channel.
func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	cfgPath := fs.String("config", "config.ini", "path to config.ini")
	ctrl := fs.String("ctrl", defaultCtrlAddr, "control channel address (127.0.0.1:port)")
	bg := fs.Bool("bg", false, "launch in the background without opening the console")
	background := fs.Bool("background", false, "alias of --bg")
	resume := fs.Bool("resume", false, "reattach the console to a server already in the background")
	createCfg := fs.Bool("create-config", false, "generate config.ini with a random MD5 key and exit")
	logFile := fs.String("log", "", "write the background log to this file (default: no log)")
	encrypt := fs.Bool("encrypt", false, "require an encrypted link with agents (X25519 + AES-256-GCM, authenticated by the shared key)")
	state := fs.String("state", "", "path to persist the policy across restarts (default: valky.state next to config.ini)")
	fs.Parse(args)

	if *createCfg {
		if err := createConfig(*cfgPath); err != nil {
			log.Fatalf("create-config: %v", err)
		}
		return
	}

	// Internal mode: this process IS the background daemon (set by respawn).
	if isDaemonChild() {
		cfg, err := config.LoadServer(*cfgPath)
		if err != nil {
			log.Fatalf("config: %v", err)
		}
		statePath := *state
		if statePath == "" {
			statePath = filepath.Join(filepath.Dir(*cfgPath), "valky.state")
		}
		runServerDaemon(cfg, *ctrl, *encrypt || cfg.Encrypt, statePath)
		return
	}

	// --resume: just attach the console to the running daemon.
	if *resume {
		if err := attachConsole(*ctrl); err != nil {
			log.Fatalf("resume: %v", err)
		}
		return
	}

	// Make sure the daemon is running (spawn it detached if not).
	spawned, err := ensureDaemon(*ctrl, *logFile)
	if err != nil {
		log.Fatalf("start daemon: %v", err)
	}

	if *bg || *background {
		switch {
		case spawned && *logFile != "":
			fmt.Printf("valky server running in the background (control %s, log %s)\n", *ctrl, *logFile)
		case spawned:
			fmt.Printf("valky server running in the background (control %s)\n", *ctrl)
		default:
			fmt.Printf("valky server was already running in the background (control %s)\n", *ctrl)
		}
		fmt.Println("use 'valky --resume' to open the console, or 'valky --stop' to stop it")
		return
	}

	if err := attachConsole(*ctrl); err != nil {
		log.Fatalf("console: %v", err)
	}
}

// runServerDaemon is the real server: it listens for clients, serves the
// control channel, and runs until 'stop' or a signal.
func runServerDaemon(cfg *config.ServerConfig, ctrlAddr string, encrypt bool, statePath string) {
	h := newHub(cfg)
	h.encrypt = encrypt
	h.statePath = statePath
	h.loadState()

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatalf("listen on %s: %v", cfg.Listen, err)
	}
	ctrlLn, err := net.Listen("tcp", ctrlAddr)
	if err != nil {
		log.Fatalf("listen on control channel %s: %v", ctrlAddr, err)
	}
	writePIDFile(pidPath())
	log.Printf("valky server (daemon) listening on %s (overlay %s), control %s, encrypt=%v",
		cfg.Listen, cfg.Overlay, ctrlAddr, encrypt)

	// Client connections.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Printf("accept: %v", err)
				continue
			}
			go h.handle(conn)
		}
	}()

	// Control channel (consoles attach here).
	h.serveControl(ctrlLn)
}

// allocIP returns the next free host address in the overlay. Caller holds mu.
func (h *hub) allocIP() net.IP {
	base := h.cfg.Overlay.IP.Mask(h.cfg.Overlay.Mask).To4()
	if base == nil {
		return nil
	}
	ones, bits := h.cfg.Overlay.Mask.Size()
	count := 1 << uint(bits-ones)
	for i := 1; i < count-1; i++ {
		ip := addToIP(base, i)
		if !h.usedIPs[ip.String()] {
			return ip
		}
	}
	return nil
}

func addToIP(base net.IP, n int) net.IP {
	ip := make(net.IP, 4)
	copy(ip, base.To4())
	v := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	v += uint32(n)
	ip[0], ip[1], ip[2], ip[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
	return ip
}

func (h *hub) handle(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()

	// Optional encrypted transport. When the server requires it, the agent must
	// support it; otherwise the connection is refused. All subsequent frames use
	// the (possibly wrapped) connection.
	sec, enc, err := secureServerHandshake(conn, []byte(h.cfg.Key), h.encrypt)
	if err != nil {
		log.Printf("%s: secure handshake: %v", remote, err)
		return
	}
	conn = sec

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	t, payload, err := protocol.ReadFrame(conn)
	if err != nil {
		log.Printf("%s: handshake: %v", remote, err)
		return
	}
	if t != protocol.TypeAuth {
		log.Printf("%s: expected auth, got type %d", remote, t)
		return
	}
	lines := strings.SplitN(string(payload), "\n", 3)
	if len(lines) < 3 {
		log.Printf("%s: malformed auth", remote)
		return
	}
	passwd, agentID, segStr := lines[0], strings.TrimSpace(lines[1]), lines[2]
	if subtle.ConstantTimeCompare([]byte(passwd), []byte(h.cfg.Key)) != 1 {
		_ = protocol.WriteFrame(conn, protocol.TypeAuthFail, []byte("wrong key"))
		log.Printf("%s: authentication failed", remote)
		return
	}
	if !uuid.Valid(agentID) {
		_ = protocol.WriteFrame(conn, protocol.TypeAuthFail, []byte("invalid agent uuid"))
		log.Printf("%s: invalid agent uuid %q", remote, agentID)
		return
	}
	segs := parseSegs(segStr)

	h.mu.Lock()
	// Last connection wins: if this agent uuid is already connected (e.g. a
	// restart whose old half-open connection the server hasn't noticed yet),
	// drop the stale session and take over its overlay IP. This ensures a
	// restarted client re-registers with its current segments.
	var vip net.IP
	if old, dup := h.byUUID[agentID]; dup {
		old.conn.Close()
		delete(h.byUUID, agentID)
		delete(h.byVIP, old.virtIP.String())
		vip = old.virtIP // reuse the same overlay IP (still in usedIPs)
		log.Printf("agent %s reconnected; replacing previous session", short(agentID))
	} else {
		vip = h.allocIP()
		if vip == nil {
			h.mu.Unlock()
			_ = protocol.WriteFrame(conn, protocol.TypeAuthFail, []byte("overlay full"))
			return
		}
		h.usedIPs[vip.String()] = true
	}
	s := &session{uuid: agentID, remote: remote, virtIP: vip, segs: segs, conn: conn,
		streams: map[uint32]*streamEnd{}}
	h.byUUID[agentID] = s
	h.byVIP[vip.String()] = s
	h.mu.Unlock()

	defer func() {
		h.cleanupStreams(s)
		h.mu.Lock()
		// Only tear down if we are still the registered session (a newer
		// connection with the same uuid may have taken over).
		if h.byUUID[agentID] == s {
			delete(h.byUUID, agentID)
			delete(h.byVIP, vip.String())
			delete(h.usedIPs, vip.String())
		}
		h.mu.Unlock()
		log.Printf("agent %s (%s) disconnected", agentID, remote)
	}()

	ones, _ := h.cfg.Overlay.Mask.Size()
	assigned := fmt.Sprintf("%s/%d", vip.String(), ones)
	if err := protocol.WriteFrame(conn, protocol.TypeAuthOK, []byte(assigned)); err != nil {
		return
	}
	// Reapply any existing rules, forwards and socks proxies for this agent.
	h.pushRoutes(s)
	h.pushForwards(s)
	h.pushSocks(s)
	h.pushNAT(s)
	log.Printf("agent %s connected: %s vip=%s segments=%s encrypted=%v", agentID, remote, vip, cidrs(segs), enc)

	// Dead-peer detection: the agent sends a keepalive every 20s, so require a
	// frame at least every agentReadTimeout. A stale/half-open connection then
	// errors out and the session (and its overlay IP) is reclaimed by the defer.
	conn.SetReadDeadline(time.Now().Add(agentReadTimeout))
	for {
		t, payload, err := protocol.ReadFrame(conn)
		if err != nil {
			return
		}
		conn.SetReadDeadline(time.Now().Add(agentReadTimeout))
		switch t {
		case protocol.TypeKeepAlive:
		case protocol.TypeMode:
			h.mu.Lock()
			s.mode = string(payload)
			h.mu.Unlock()
		case protocol.TypeSegments:
			newSegs := parseSegs(string(payload))
			h.mu.Lock()
			s.segs = newSegs
			h.mu.Unlock()
			// Delivered networks changed, so recompute which networks this agent
			// must masquerade.
			h.pushNAT(s)
			log.Printf("agent %s updated segments: %s", short(s.uuid), cidrs(newSegs))
		case protocol.TypeData:
			h.forward(s, payload)
		case protocol.TypeStreamOpen:
			id, rest := decodeID(payload)
			h.onStreamOpen(s, id, string(rest))
		case protocol.TypeStreamData:
			id, data := decodeID(payload)
			h.onStreamData(s, id, data)
		case protocol.TypeStreamClose:
			id, _ := decodeID(payload)
			h.onStreamClose(s, id)
		}
	}
}

// onStreamOpen relays a port-forward stream open to the agent that owns the
// target, after an ACL check, and records the id translation for both sides.
func (h *hub) onStreamOpen(from *session, id uint32, target string) {
	host, _, err := net.SplitHostPort(target)
	var ip net.IP
	if err == nil {
		ip = net.ParseIP(host)
	}
	if ip == nil {
		from.send(protocol.TypeStreamClose, encodeID(id, nil))
		return
	}
	h.mu.RLock()
	ok := h.allowedLocked(from, ip)
	// Delivery is pinned by (client, destination), so every stream from this
	// client to this target uses the same agent and its stable NAT source —
	// keeping stateful sessions (e.g. web logins) intact under --random.
	target2 := h.deliverTargetLocked(from, ip)
	h.mu.RUnlock()
	if !ok || target2 == nil || target2 == from {
		log.Printf("stream DROP %s -> %s (unauthorized or no destination)", short(from.uuid), target)
		from.send(protocol.TypeStreamClose, encodeID(id, nil))
		return
	}

	h.smu.Lock()
	target2.inboundN++
	bID := (target2.inboundN & 0x7fffffff) | 0x80000000
	from.streams[id] = &streamEnd{peer: target2, peerID: bID}
	target2.streams[bID] = &streamEnd{peer: from, peerID: id}
	h.smu.Unlock()

	target2.send(protocol.TypeStreamOpen, encodeID(bID, []byte(target)))
}

func (h *hub) onStreamData(from *session, id uint32, data []byte) {
	h.smu.Lock()
	e := from.streams[id]
	h.smu.Unlock()
	if e == nil {
		return
	}
	e.peer.send(protocol.TypeStreamData, encodeID(e.peerID, data))
}

func (h *hub) onStreamClose(from *session, id uint32) {
	h.smu.Lock()
	e := from.streams[id]
	if e != nil {
		delete(from.streams, id)
		if e.peer != nil {
			delete(e.peer.streams, e.peerID)
		}
	}
	h.smu.Unlock()
	if e != nil && e.peer != nil {
		e.peer.send(protocol.TypeStreamClose, encodeID(e.peerID, nil))
	}
}

// cleanupStreams tears down all streams owned by s and notifies the peers.
func (h *hub) cleanupStreams(s *session) {
	h.smu.Lock()
	type notif struct {
		peer *session
		pid  uint32
	}
	var ns []notif
	for _, e := range s.streams {
		if e.peer != nil {
			delete(e.peer.streams, e.peerID)
			ns = append(ns, notif{e.peer, e.peerID})
		}
	}
	s.streams = map[uint32]*streamEnd{}
	h.smu.Unlock()
	for _, n := range ns {
		n.peer.send(protocol.TypeStreamClose, encodeID(n.pid, nil))
	}
}

// forward applies ACL checks and relays one packet to its destination agent.
func (h *hub) forward(from *session, pkt []byte) {
	if netutil.IPVersion(pkt) != 4 {
		return
	}
	src, dst, err := netutil.SrcDstV4(pkt)
	if err != nil {
		return
	}
	h.mu.RLock()
	ok := h.allowedLocked(from, dst)
	target := h.deliverTargetLocked(from, dst)
	h.mu.RUnlock()

	if !ok {
		log.Printf("DROP %s -> %s (agent %s unauthorized)", src, dst, short(from.uuid))
		return
	}
	if target == nil || target == from {
		return
	}
	if err := target.send(protocol.TypeData, pkt); err != nil {
		log.Printf("forward to %s: %v", short(target.uuid), err)
	}
}

// allowedLocked: overlay addresses are always reachable (so replies return);
// LAN destinations require a matching rule. Caller holds mu.
func (h *hub) allowedLocked(from *session, dst net.IP) bool {
	if h.cfg.Overlay.Contains(dst) {
		return true
	}
	for _, r := range h.rules {
		if r.agentID == from.uuid && r.network.Contains(dst) {
			return true
		}
	}
	// A port-forward implicitly authorizes its agent to reach the target host.
	for _, f := range h.forwards {
		if f.agentID == from.uuid && f.targetNet != nil && f.targetNet.Contains(dst) {
			return true
		}
	}
	return false
}

// candidatesLocked returns the live agents that own dst at the most specific
// prefix (longest-prefix match), sorted by uuid for determinism. An agent that
// matches dst with several networks contributes its longest one. Caller holds mu.
func (h *hub) candidatesLocked(dst net.IP) []*session {
	best := -1
	perAgent := map[*session]int{}
	consider := func(s *session, network *net.IPNet) {
		if s == nil || !network.Contains(dst) {
			return
		}
		ones, _ := network.Mask.Size()
		if o, ok := perAgent[s]; !ok || ones > o {
			perAgent[s] = ones
		}
		if ones > best {
			best = ones
		}
	}
	for _, s := range h.byUUID {
		for _, seg := range s.segs {
			consider(s, seg)
		}
	}
	for _, p := range h.published {
		consider(h.byUUID[p.agentID], p.network)
	}
	if best < 0 {
		return nil
	}
	var out []*session
	for s, o := range perAgent {
		if o == best {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].uuid < out[j].uuid })
	return out
}

// routeForLocked returns the single deterministic delivery agent for dst: the
// most specific match (longest prefix), ties broken by lowest uuid. Caller holds
// mu. Used when no source/flow context applies (e.g. overlay replies).
func (h *hub) routeForLocked(dst net.IP) *session {
	if s := h.byVIP[dst.String()]; s != nil {
		return s
	}
	cands := h.candidatesLocked(dst)
	if len(cands) == 0 {
		return nil
	}
	return cands[0]
}

// randomRuleLocked reports whether `from` has a --random rule covering dst, i.e.
// traffic to dst may be load-balanced across the agents that deliver it. Holds mu.
func (h *hub) randomRuleLocked(from *session, dst net.IP) bool {
	for _, r := range h.rules {
		if r.random && r.agentID == from.uuid && r.network.Contains(dst) {
			return true
		}
	}
	return false
}

// deliverTargetLocked picks the delivery agent for a packet/stream from `from` to
// dst. With a --random rule and more than one delivering agent, it spreads load
// across them while keeping session affinity: the choice is pinned by the
// (client, destination) pair, so every connection from one client to one service
// uses the same agent. That keeps the agent's NAT source address stable across
// the client's many connections and does not reset stateful sessions (e.g. a web
// login). Different clients still spread across the agents. Caller holds mu.
func (h *hub) deliverTargetLocked(from *session, dst net.IP) *session {
	if s := h.byVIP[dst.String()]; s != nil {
		return s
	}
	cands := h.candidatesLocked(dst)
	if len(cands) == 0 {
		return nil
	}
	if len(cands) > 1 && h.randomRuleLocked(from, dst) {
		return cands[netutil.AffinityHash(from.virtIP, dst)%uint32(len(cands))]
	}
	return cands[0]
}

// pushRoutes sends an agent the full set of CIDRs it should route into the
// tunnel: the overlay plus every network granted by a rule for its uuid.
func (h *hub) pushRoutes(s *session) {
	h.mu.RLock()
	set := []string{h.cfg.Overlay.String()}
	for _, r := range h.rules {
		if r.agentID == s.uuid {
			set = append(set, r.network.String())
		}
	}
	// Ensure the agent also routes the targets of its port-forwards.
	for _, f := range h.forwards {
		if f.agentID == s.uuid && f.targetNet != nil {
			set = append(set, f.targetNet.String())
		}
	}
	h.mu.RUnlock()
	if err := s.send(protocol.TypeRoutes, []byte(strings.Join(set, ","))); err != nil {
		log.Printf("send routes to %s: %v", short(s.uuid), err)
	}
}

// deliversLocked reports whether session s delivers traffic for network n into a
// local LAN: s advertised a segment, or publishes a subnet route, that covers n.
// This is the agent that must masquerade so the NAT applies where packets leave
// the tunnel. Caller holds mu.
func (h *hub) deliversLocked(s *session, n *net.IPNet) bool {
	for _, seg := range s.segs {
		if seg.Contains(n.IP) {
			return true
		}
	}
	for _, p := range h.published {
		if p.agentID == s.uuid && p.network.Contains(n.IP) {
			return true
		}
	}
	return false
}

// pushNAT sends an agent the full set of networks it should masquerade overlay
// traffic toward: every NAT-enabled rule's network that this agent delivers (NAT
// is on by default; --no-nat clears rule.nat). The set is independent of which
// agent the rule authorizes (that is the consumer); NAT belongs on the delivering
// agent, where packets exit the tunnel into the LAN.
func (h *hub) pushNAT(s *session) {
	h.mu.RLock()
	seen := map[string]bool{}
	var set []string
	for _, r := range h.rules {
		if !r.nat || !h.deliversLocked(s, r.network) {
			continue
		}
		cidr := r.network.String()
		if !seen[cidr] {
			seen[cidr] = true
			set = append(set, cidr)
		}
	}
	h.mu.RUnlock()
	if err := s.send(protocol.TypeNAT, []byte(strings.Join(set, ","))); err != nil {
		log.Printf("send nat to %s: %v", short(s.uuid), err)
	}
}

// pushNATAll recomputes and pushes the NAT set to every connected agent. Used
// after a rule changes, since the delivering agent may differ from the agent the
// rule authorizes.
func (h *hub) pushNATAll() {
	h.mu.RLock()
	sessions := make([]*session, 0, len(h.byUUID))
	for _, s := range h.byUUID {
		sessions = append(sessions, s)
	}
	h.mu.RUnlock()
	for _, s := range sessions {
		h.pushNAT(s)
	}
}

// pushForwards sends an agent the full set of TCP port-forwards it should run.
func (h *hub) pushForwards(s *session) {
	h.mu.RLock()
	var set []string
	for _, f := range h.forwards {
		if f.agentID == s.uuid {
			set = append(set, f.listen+"|"+f.target)
		}
	}
	h.mu.RUnlock()
	if err := s.send(protocol.TypeForwards, []byte(strings.Join(set, ","))); err != nil {
		log.Printf("send forwards to %s: %v", short(s.uuid), err)
	}
}

// pushSocks sends an agent the full set of SOCKS5 proxy listeners it should run.
func (h *hub) pushSocks(s *session) {
	h.mu.RLock()
	var set []string
	for _, sp := range h.socks {
		if sp.agentID == s.uuid {
			set = append(set, sp.listen)
		}
	}
	h.mu.RUnlock()
	if err := s.send(protocol.TypeSocks, []byte(strings.Join(set, ","))); err != nil {
		log.Printf("send socks to %s: %v", short(s.uuid), err)
	}
}

func parseSegs(s string) []*net.IPNet {
	var out []*net.IPNet
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if _, nd, err := net.ParseCIDR(f); err == nil {
			out = append(out, nd)
		}
	}
	return out
}

func cidrs(ns []*net.IPNet) string {
	if len(ns) == 0 {
		return "-"
	}
	out := make([]string, len(ns))
	for i, n := range ns {
		out[i] = n.String()
	}
	return strings.Join(out, ",")
}

func short(id string) string {
	if len(id) >= 8 {
		return id[:8]
	}
	return id
}
