package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"valky/internal/netutil"
	"valky/internal/protocol"
	"valky/internal/uuid"
)

// tunDevice is the subset of the TUN interface the client needs. It lets
// client.go stay platform-neutral while the concrete device is created by the
// per-OS openTUN implementations.
type tunDevice interface {
	io.ReadWriteCloser
	Name() string
}

// runClient orchestrates the client lifecycle. The network engine (TUN + server
// link + forwards + socks) always runs as a background process that serves a
// local control channel; the foreground process is only a console attached to it.
//
// The engine and the console are launched with a clean argv (just the title) and
// their parameters passed through the environment, while the shared key is handed
// to the engine over a pipe (stdin). As a result `ps`/`ps auxf` never show the
// key — only the title (default "valky", or --name).
func runClient(args []string) {
	// Env-driven roles, set when we spawn/re-exec ourselves with a clean argv.
	if isClientEngine() {
		ip, port, passwd, dev, id, cctrl, enc := readEngineEnv()
		runClientEngine(ip, port, passwd, dev, id, cctrl, enc)
		return
	}
	if isClientConsole() {
		if err := attachClientConsole(os.Getenv("VALKY_CCTRL")); err != nil {
			log.Fatalf("console: %v", err)
		}
		return
	}

	fs := flag.NewFlagSet("client", flag.ExitOnError)
	ip := fs.String("ip", "", "valky server IP (required)")
	port := fs.Int("port", 0, "valky server port (required)")
	passwd := fs.String("passwd", "", "shared key (required)")
	dev := fs.String("dev", "", "TUN interface name (optional)")
	id := fs.String("id", "", "agent UUID (optional; generated and persisted if omitted)")
	bg := fs.Bool("bg", false, "launch in the background without opening the console")
	background := fs.Bool("background", false, "alias of --bg")
	resume := fs.Bool("resume", false, "reopen the console of a backgrounded client")
	stop := fs.Bool("stop", false, "stop the backgrounded client")
	cctrl := fs.String("cctrl", defaultClientCtrlAddr, "client control channel (127.0.0.1:port)")
	logFile := fs.String("log", "", "write the background log to this file (default: no log)")
	name := fs.String("name", "", "process title shown in ps (default: valky) — the key never appears in ps")
	enc := fs.Bool("encrypt", false, "require an encrypted link; refuse to connect if the server offers plaintext")
	fs.Parse(args)

	if *resume {
		if err := attachClientConsole(*cctrl); err != nil {
			log.Fatalf("resume: %v", err)
		}
		return
	}
	if *stop {
		if err := stopClient(*cctrl); err != nil {
			log.Fatalf("stop: %v", err)
		}
		return
	}

	if *ip == "" || *port == 0 || *passwd == "" {
		fmt.Fprintln(os.Stderr, "missing --ip, --port or --passwd")
		fs.Usage()
		os.Exit(2)
	}

	title := *name
	if title == "" {
		title = "valky"
	}

	spawned, err := ensureClientEngine(*ip, *port, *passwd, *dev, *id, *cctrl, *logFile, title, *enc)
	if err != nil {
		log.Fatalf("start client: %v", err)
	}
	if *bg || *background {
		switch {
		case spawned && *logFile != "":
			fmt.Printf("valky client running in the background (control %s, log %s)\n", *cctrl, *logFile)
		case spawned:
			fmt.Printf("valky client running in the background (control %s)\n", *cctrl)
		default:
			fmt.Printf("valky client already running in the background (control %s)\n", *cctrl)
		}
		fmt.Println("use 'valky client --resume' to open the console, or 'valky client --stop' to stop it")
		return
	}
	// Foreground console, re-exec'd with a clean argv so the key the user typed
	// does not linger in this process's command line either.
	reexecConsole(title, *cctrl)
}

// isClientConsole reports whether this process is a re-exec'd clean console.
func isClientConsole() bool { return os.Getenv("VALKY_CLIENT_CONSOLE") == "1" }

// readEngineEnv reads the engine's parameters from the environment and the shared
// key from stdin (a pipe fed by the parent), so none of them appear on argv.
func readEngineEnv() (ip string, port int, passwd, dev, id, cctrl string, enc bool) {
	ip = os.Getenv("VALKY_IP")
	port, _ = strconv.Atoi(os.Getenv("VALKY_PORT"))
	dev = os.Getenv("VALKY_DEV")
	id = os.Getenv("VALKY_ID")
	cctrl = os.Getenv("VALKY_CCTRL")
	enc = os.Getenv("VALKY_ENCRYPT") == "1"
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	passwd = strings.TrimRight(line, "\r\n")
	return
}

// ensureClientEngine starts the background engine if not already running. It is
// launched with a clean argv (just `title`), its parameters passed via the
// environment and the shared key written to its stdin pipe — so neither `ps` nor
// `ps -E` reveal the key.
func ensureClientEngine(ip string, port int, passwd, dev, id, cctrl, logFile, title string, enc bool) (bool, error) {
	if isRunning(cctrl) {
		return false, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return false, err
	}
	out := logFile
	if out == "" {
		out = os.DevNull
	}
	logf, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return false, err
	}
	defer logf.Close()
	pr, pw, err := os.Pipe()
	if err != nil {
		return false, err
	}
	encVal := "0"
	if enc {
		encVal = "1"
	}
	cmd := &exec.Cmd{
		Path: exe,
		Args: []string{title},
		Env: append(os.Environ(),
			"VALKY_CLIENT_ENGINE=1",
			"VALKY_IP="+ip,
			"VALKY_PORT="+strconv.Itoa(port),
			"VALKY_DEV="+dev,
			"VALKY_ID="+id,
			"VALKY_CCTRL="+cctrl,
			"VALKY_ENCRYPT="+encVal,
		),
		Stdin:       pr,
		Stdout:      logf,
		Stderr:      logf,
		SysProcAttr: detachSysProcAttr(),
	}
	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return false, err
	}
	pr.Close()
	io.WriteString(pw, passwd+"\n") // hand the key over the pipe, then close
	pw.Close()
	_ = cmd.Process.Release()

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if isRunning(cctrl) {
			return true, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	hint := "(no log; pass --log <file> to capture output)"
	if logFile != "" {
		hint = "check " + logFile
	}
	return false, fmt.Errorf("client engine did not come up; %s", hint)
}

// reexecConsole replaces this process with a clean console (argv = just title,
// control address via env, no key), so the foreground command line typed by the
// user does not linger in ps. On platforms without exec it attaches directly.
func reexecConsole(title, cctrl string) {
	exe, err := os.Executable()
	if err == nil {
		env := append(os.Environ(), "VALKY_CLIENT_CONSOLE=1", "VALKY_CCTRL="+cctrl)
		err = execSelf(exe, []string{title}, env) // never returns on success
	}
	if aerr := attachClientConsole(cctrl); aerr != nil {
		log.Fatalf("console: %v", aerr)
	}
	_ = err
}

// runClientEngine is the real client: it connects, sets up the TUN (if allowed),
// runs forwards/socks, and serves the control channel. It reconnects with backoff
// whenever the link drops, keeping the TUN device, managers and control channel up
// across reconnects. It runs until 'stop' / self-destruct.
func runClientEngine(ipStr string, portN int, passwd, dev, id, cctrl string, requireEnc bool) {
	server := net.JoinHostPort(ipStr, fmt.Sprintf("%d", portN))

	// Stable agent identity: explicit --id, else load/persist one on disk.
	agentID := id
	if agentID == "" {
		agentID = loadOrCreateAgentID()
	} else if !uuid.Valid(agentID) {
		log.Fatalf("--id %q is not a valid UUID", agentID)
	}
	log.Printf("agent UUID: %s", agentID)

	segStrs := scanSegments()
	log.Printf("advertised local segments: %s", strings.Join(segStrs, ", "))

	// Serve the control channel so a console can attach/reattach (served once).
	ctrlLn, err := net.Listen("tcp", cctrl)
	if err != nil {
		log.Fatalf("listen on client control channel %s: %v", cctrl, err)
	}
	writePIDFile(clientPidPath())

	// Shared, connection-independent state. The writer's underlying connection is
	// swapped on each (re)connect; the TUN device, managers and background loops
	// are created once and reused across reconnects.
	cw := &connWriter{}
	mux := newStreamMux(cw)
	fm := newForwardManager(mux)
	sm := newSocksManager(mux)

	var (
		ifce      tunDevice
		rm        *routeManager
		nm        *natManager
		ns        *netstackEgress
		tunMode   bool
		devName   string
		assigned  string
		modeStr   = "proxy"
		setupDone bool // TUN + background loops started
	)

	const maxBackoff = 30 * time.Second
	backoff := time.Second
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}

	for {
		conn, err := dialer.Dial("tcp", server)
		if err != nil {
			log.Printf("connect to %s failed: %v (retry in %s)", server, err, backoff)
			time.Sleep(backoff)
			backoff = growBackoff(backoff, maxBackoff)
			continue
		}

		// Optional encryption: offer it and follow the server's choice (refusing
		// plaintext if --encrypt was set).
		sconn, enc, err := secureClientHandshake(conn, []byte(passwd), requireEnc)
		if err != nil {
			log.Printf("secure handshake failed: %v (retry in %s)", err, backoff)
			conn.Close()
			time.Sleep(backoff)
			backoff = growBackoff(backoff, maxBackoff)
			continue
		}
		conn = sconn

		// Authenticate.
		authPayload := fmt.Sprintf("%s\n%s\n%s", passwd, agentID, strings.Join(segStrs, ","))
		if err := protocol.WriteFrame(conn, protocol.TypeAuth, []byte(authPayload)); err != nil {
			conn.Close()
			time.Sleep(backoff)
			backoff = growBackoff(backoff, maxBackoff)
			continue
		}
		t, payload, err := protocol.ReadFrame(conn)
		if err != nil {
			conn.Close()
			time.Sleep(backoff)
			backoff = growBackoff(backoff, maxBackoff)
			continue
		}
		if t != protocol.TypeAuthOK {
			reason := string(payload)
			if t != protocol.TypeAuthFail {
				reason = fmt.Sprintf("unexpected reply type %d", t)
			}
			log.Printf("server rejected the connection: %s (retry in %s)", reason, backoff)
			conn.Close()
			time.Sleep(backoff)
			backoff = growBackoff(backoff, maxBackoff)
			continue
		}
		newAssigned := string(payload)
		backoff = time.Second // connected successfully; reset backoff

		if !setupDone {
			// First successful connection: set up the TUN (if privileged) and the
			// persistent background loops. Reused across later reconnects.
			assigned = newAssigned
			log.Printf("authenticated; assigned overlay address: %s", assigned)
			if d, err := openTUN(dev, assigned); err != nil {
				log.Printf("no tunnel (proxy mode): %v", err)
				log.Printf("run as administrator/root for a native L3 tunnel; proxy mode still routes L3 in userspace")
				// Proxy mode: no TUN, so stand up a userspace TCP/IP stack to
				// deliver raw L3 packets routed to us (e.g. from a tunnel-mode
				// agent). Needs no privileges; port-forwards/SOCKS work regardless.
				if e, nerr := newNetstackEgress(cw); nerr != nil {
					log.Printf("netstack egress unavailable: %v (L3 to this agent will be dropped; use SOCKS)", nerr)
				} else {
					ns = e
					log.Printf("userspace L3 egress ready (proxy mode)")
				}
			} else {
				ifce = d
				tunMode = true
				devName = ifce.Name()
				modeStr = "tunnel"
				log.Printf("TUN interface %s", devName)
				rm = &routeManager{dev: devName}
				if err := rm.configureAddress(assigned); err != nil {
					log.Fatalf("configure interface: %v", err)
				}
				if _, ipnet, err := net.ParseCIDR(assigned); err == nil {
					nm = newNATManager(ipnet.String())
				} else {
					log.Printf("nat: cannot derive overlay network from %q: %v", assigned, err)
				}
				// TUN -> server pump (persistent; writes are dropped while
				// disconnected and resume once reconnected).
				go func() {
					buf := make([]byte, 65535)
					for {
						n, err := ifce.Read(buf)
						if err != nil {
							log.Fatalf("TUN read: %v", err)
						}
						_ = cw.write(protocol.TypeData, buf[:n])
					}
				}()
			}

			// Keepalive (persistent). A failed keepalive on a live connection
			// closes it so the read loop unblocks and reconnects (half-open links).
			go func() {
				tk := time.NewTicker(20 * time.Second)
				defer tk.Stop()
				for range tk.C {
					if err := cw.write(protocol.TypeKeepAlive, nil); err != nil && err != errNotConnected {
						cw.closeCurrent()
					}
				}
			}()

			// Segment rescan (persistent): follow the host's networks live.
			go func() {
				last := strings.Join(segStrs, ",")
				tk := time.NewTicker(30 * time.Second)
				defer tk.Stop()
				for range tk.C {
					joined := strings.Join(scanSegments(), ",")
					if joined == last {
						continue
					}
					last = joined
					if err := cw.write(protocol.TypeSegments, []byte(joined)); err == nil {
						log.Printf("local segments changed, updated server: %s", joined)
					}
				}
			}()

			cs := &clientState{
				server:   server,
				agentID:  agentID,
				assigned: assigned,
				dev:      devName,
				tunMode:  tunMode,
				segs:     segStrs,
				fm:       fm,
				sm:       sm,
				nm:       nm,
			}
			go serveClientControl(ctrlLn, cs)
			setupDone = true
		} else if tunMode && newAssigned != assigned {
			// Overlay IP changed across a reconnect (unusual): reconfigure.
			if err := rm.configureAddress(newAssigned); err != nil {
				log.Printf("reconfigure interface to %s: %v", newAssigned, err)
			} else {
				assigned = newAssigned
			}
		}

		cw.setConn(conn)
		mux.reset() // drop streams from the previous connection
		_ = cw.write(protocol.TypeMode, []byte(modeStr))
		if enc {
			log.Printf("link established (encrypted); waiting for rules from the server...")
		} else {
			log.Printf("link established (plaintext); waiting for rules from the server...")
		}

		// Serve the link until it drops, then loop and reconnect.
		runClientLink(conn, tunMode, ifce, ns, rm, nm, mux, fm, sm)
		log.Printf("connection lost; reconnecting to %s...", server)
		conn.Close()
		cw.setConn(nil)
	}
}

// scanSegments returns the host's advertisable LAN segments as CIDR strings.
func scanSegments() []string {
	segs, err := netutil.LocalSegments()
	if err != nil {
		return nil
	}
	out := make([]string, len(segs))
	for i, s := range segs {
		out[i] = s.String()
	}
	return out
}

// growBackoff doubles d up to max, for the reconnect loop.
func growBackoff(d, max time.Duration) time.Duration {
	d *= 2
	if d > max {
		d = max
	}
	return d
}

// runClientLink reads frames from the server over one connection and dispatches
// them, returning when the connection errors (so the caller can reconnect).
func runClientLink(conn net.Conn, tunMode bool, ifce tunDevice, ns *netstackEgress, rm *routeManager, nm *natManager, mux *streamMux, fm *forwardManager, sm *socksManager) {
	for {
		t, payload, err := protocol.ReadFrame(conn)
		if err != nil {
			return
		}
		switch t {
		case protocol.TypeData:
			if tunMode {
				ifce.Write(payload)
			} else if ns != nil {
				// Proxy mode: deliver the L3 packet through the userspace stack.
				ns.inject(payload)
			}
		case protocol.TypeRoutes:
			if tunMode {
				rm.reconcile(parseCIDRList(string(payload)))
			}
		case protocol.TypeNAT:
			if tunMode && nm != nil {
				nm.reconcile(parseCIDRList(string(payload)))
			}
		case protocol.TypeForwards:
			fm.reconcile(parseCIDRList(string(payload)))
		case protocol.TypeSocks:
			sm.reconcile(parseCIDRList(string(payload)))
		case protocol.TypeDestroy:
			selfDestruct()
		case protocol.TypeStreamOpen:
			id, rest := decodeID(payload)
			mux.handleOpen(id, string(rest))
		case protocol.TypeStreamData:
			id, data := decodeID(payload)
			mux.handleData(id, data)
		case protocol.TypeStreamClose:
			id, _ := decodeID(payload)
			mux.handleClose(id)
		}
	}
}

func parseCIDRList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// routeManager keeps the kernel routing table in sync with the set of CIDRs the
// server wants this client to route into the tunnel. The add/del/configure
// methods are implemented per OS in tun_*.go.
type routeManager struct {
	dev       string
	installed map[string]bool
}

// reconcile adds routes present in desired but missing, and removes routes no
// longer desired, so deny/allow changes from the server take effect live.
func (r *routeManager) reconcile(desired []string) {
	if r.installed == nil {
		r.installed = map[string]bool{}
	}
	want := map[string]bool{}
	for _, c := range desired {
		want[c] = true
		if !r.installed[c] {
			if err := r.addRoute(c); err != nil {
				log.Printf("add route %s: %v", c, err)
				continue
			}
			r.installed[c] = true
		}
	}
	for c := range r.installed {
		if !want[c] {
			if err := r.delRoute(c); err != nil {
				log.Printf("remove route %s: %v", c, err)
				continue
			}
			delete(r.installed, c)
		}
	}
	log.Printf("active routes: %s", strings.Join(desired, ", "))
}

// natManager keeps egress NAT in sync with the set of delivered networks the
// server marks for masquerading (on by default; `route --add ... --no-nat` opts
// out).
// For each such network it SNATs overlay-sourced traffic so LAN hosts reply to
// this agent (which they can route to) instead of to the originator's overlay
// address. The per-OS primitives natEnable/natDisable live in nat_*.go; they are
// no-ops outside Linux.
type natManager struct {
	overlay string // overlay network CIDR, e.g. "10.9.0.0/24"
	active  map[string]bool
}

func newNATManager(overlay string) *natManager {
	return &natManager{overlay: overlay, active: map[string]bool{}}
}

// reconcile installs masquerade rules for newly desired networks and removes
// those no longer wanted, so changes from the server take effect live.
func (m *natManager) reconcile(desired []string) {
	want := map[string]bool{}
	for _, c := range desired {
		want[c] = true
		if !m.active[c] {
			if err := natEnable(m.overlay, c); err != nil {
				log.Printf("nat: enable %s -> %s: %v", m.overlay, c, err)
				continue
			}
			m.active[c] = true
		}
	}
	for c := range m.active {
		if !want[c] {
			natDisable(m.overlay, c)
			delete(m.active, c)
		}
	}
	if len(desired) > 0 {
		log.Printf("active egress NAT: %s", strings.Join(desired, ", "))
	}
}

// teardown removes every masquerade rule this manager installed. Called on exit,
// where deferred cleanup would be skipped by os.Exit.
func (m *natManager) teardown() {
	for c := range m.active {
		natDisable(m.overlay, c)
		delete(m.active, c)
	}
}

// loadOrCreateAgentID returns a stable UUID for this client, read from (or
// written to) the user's config directory so rules survive restarts.
// agentIDPath is where the stable agent UUID is persisted.
func agentIDPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "valky", "agent-id")
}

func loadOrCreateAgentID() string {
	path := agentIDPath()
	dir := filepath.Dir(path)
	if b, err := os.ReadFile(path); err == nil {
		if s := strings.TrimSpace(string(b)); uuid.Valid(s) {
			return s
		}
	}
	newID := uuid.New()
	if err := os.MkdirAll(dir, 0o700); err == nil {
		if err := os.WriteFile(path, []byte(newID+"\n"), 0o600); err != nil {
			log.Printf("warning: could not save UUID to %s: %v", path, err)
		} else {
			log.Printf("agent UUID saved to %s", path)
		}
	}
	return newID
}

// selfDestruct wipes the agent's persisted identity and runtime files, deletes
// its own binary and exits. Ordered by the server (TypeDestroy) for incident
// response when a client is compromised. Best-effort: it keeps going on errors
// and always exits.
func selfDestruct() {
	log.Printf("SELF-DESTRUCT ordered by server: wiping and exiting")
	// Overwrite then remove the stable identity so it cannot reconnect as the
	// same agent even if the file is recovered.
	if p := agentIDPath(); p != "" {
		_ = os.WriteFile(p, make([]byte, 64), 0o600)
		_ = os.Remove(p)
	}
	_ = os.Remove(clientPidPath())
	_ = os.Remove(clientHistoryFile())
	// Delete our own executable (platform-specific: Unix unlinks the running
	// binary directly; Windows schedules a helper to delete it after we exit).
	if exe, err := os.Executable(); err == nil {
		deleteSelf(exe)
	}
	os.Exit(0)
}

// run executes an OS command, echoing it for visibility.
func run(name string, args ...string) error {
	log.Printf("+ %s %s", name, strings.Join(args, " "))
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
