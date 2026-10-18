package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/chzyer/readline"
)

// defaultCtrlAddr is the local control channel the daemon listens on and the
// console attaches to. It is bound to loopback only.
const defaultCtrlAddr = "127.0.0.1:47655"

func pidPath() string { return filepath.Join(os.TempDir(), "valky.pid") }

// isDaemonChild reports whether this process was respawned as the background
// server daemon.
func isDaemonChild() bool { return os.Getenv("VALKY_DAEMON") == "1" }

// isRunning reports whether a daemon is already listening on the control addr.
func isRunning(ctrlAddr string) bool {
	c, err := net.DialTimeout("tcp", ctrlAddr, 300*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// ensureDaemon starts the background daemon if it is not already running. It
// returns whether a new daemon was spawned. logFile is "" to discard output.
func ensureDaemon(ctrlAddr, logFile string) (bool, error) {
	if isRunning(ctrlAddr) {
		return false, nil
	}
	if err := respawn("VALKY_DAEMON=1", logFile); err != nil {
		return false, err
	}
	// Wait for the control channel to come up.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if isRunning(ctrlAddr) {
			return true, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	hint := "(no log; pass --log <file> to capture output)"
	if logFile != "" {
		hint = "check " + logFile
	}
	return false, fmt.Errorf("daemon did not respond; %s", hint)
}

// respawn relaunches this binary with the same arguments, detached from the
// terminal, with the marker environment variable set so the child knows its
// role. Output goes to logFile, or is discarded when logFile is "".
func respawn(marker, logFile string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	out := logFile
	if out == "" {
		out = os.DevNull
	}
	logf, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer logf.Close()

	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), marker)
	cmd.Stdin = nil
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = detachSysProcAttr()
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

func writePIDFile(path string) {
	_ = os.WriteFile(path, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644)
}

// serveControl accepts console connections on the control channel. Each line is
// one command; the response is terminated by a NUL byte. A 'stop' command shuts
// the daemon down.
func (h *hub) serveControl(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("control accept: %v", err)
			continue
		}
		go h.handleControl(conn)
	}
}

func (h *hub) handleControl(conn net.Conn) {
	defer conn.Close()
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		stop := h.exec(sc.Text(), conn)
		conn.Write([]byte{0}) // response terminator
		if stop {
			_ = os.Remove(pidPath())
			log.Printf("stopped by console")
			os.Exit(0)
		}
	}
}

// completer provides Tab-completion for the console commands and their flags.
func completer() *readline.PrefixCompleter {
	return readline.NewPrefixCompleter(
		readline.PcItem("ls"),
		readline.PcItem("list"),
		readline.PcItem("show"),
		readline.PcItem("kick"),
		readline.PcItem("destroy"),
		readline.PcItem("route",
			readline.PcItem("--add"),
			readline.PcItem("--id"),
			readline.PcItem("--random"),
			readline.PcItem("--no-nat"),
			readline.PcItem("--del"),
			readline.PcItem("--list"),
			readline.PcItem("--via"),
			readline.PcItem("--via-del"),
			readline.PcItem("--via-list"),
		),
		readline.PcItem("forward",
			readline.PcItem("--add"),
			readline.PcItem("--id"),
			readline.PcItem("--listen"),
			readline.PcItem("--to"),
			readline.PcItem("--del"),
			readline.PcItem("--list"),
		),
		readline.PcItem("socks",
			readline.PcItem("--add"),
			readline.PcItem("--id"),
			readline.PcItem("--listen"),
			readline.PcItem("--del"),
			readline.PcItem("--list"),
		),
		readline.PcItem("help"),
		readline.PcItem("detach"),
		readline.PcItem("bg"),
		readline.PcItem("stop"),
		readline.PcItem("shutdown"),
		readline.PcItem("quit"),
		readline.PcItem("exit"),
	)
}

func historyFile() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "valky-history")
	}
	_ = os.MkdirAll(filepath.Join(dir, "valky"), 0o700)
	return filepath.Join(dir, "valky", "history")
}

// attachConsole connects to a running daemon and runs the interactive console
// with Tab-completion, command history (up/down) and a themed UI.
func attachConsole(ctrlAddr string) error {
	conn, err := net.DialTimeout("tcp", ctrlAddr, 2*time.Second)
	if err != nil {
		return fmt.Errorf("no background server at %s (start it with 'valky server --config ...'): %w", ctrlAddr, err)
	}
	defer conn.Close()
	r := bufio.NewReader(conn)

	fmt.Println(banner(ctrlAddr))

	rl, err := readline.NewEx(&readline.Config{
		Prompt:            prompt(),
		HistoryFile:       historyFile(),
		AutoComplete:      completer(),
		InterruptPrompt:   "^C",
		EOFPrompt:         "detach",
		HistorySearchFold: true,
	})
	if err != nil {
		// Fall back to a plain line reader if readline cannot init (no TTY).
		return attachConsolePlain(conn, r)
	}
	defer rl.Close()

	for {
		line, err := rl.Readline()
		if err != nil { // Ctrl-D or Ctrl-C: detach, leave the daemon running
			fmt.Println(paint(cGray, "console detached; server keeps running in the background"))
			return nil
		}
		line = strings.TrimSpace(line)
		switch line {
		case "":
			continue
		case "detach", "bg", "quit", "exit":
			fmt.Println(paint(cGray, "console detached; server keeps running in the background"))
			return nil
		}
		if _, err := fmt.Fprintf(conn, "%s\n", line); err != nil {
			fmt.Println(paint(cMagenta, "lost connection to server"))
			return nil
		}
		resp, err := r.ReadString(0)
		if len(resp) > 0 {
			fmt.Print(strings.TrimRight(resp, "\x00"))
		}
		if err != nil {
			fmt.Println(paint(cMagenta, "server stopped"))
			return nil
		}
	}
}

// attachConsolePlain is the no-TTY fallback (e.g. piped input).
func attachConsolePlain(conn net.Conn, r *bufio.Reader) error {
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		switch line {
		case "":
			continue
		case "detach", "bg", "quit", "exit":
			return nil
		}
		if _, err := fmt.Fprintf(conn, "%s\n", line); err != nil {
			return nil
		}
		resp, err := r.ReadString(0)
		if len(resp) > 0 {
			fmt.Print(strings.TrimRight(resp, "\x00"))
		}
		if err != nil {
			return nil
		}
	}
	return nil
}

// stopDaemon tells a running daemon to shut down.
func stopDaemon(ctrlAddr string) error {
	conn, err := net.DialTimeout("tcp", ctrlAddr, 2*time.Second)
	if err != nil {
		return fmt.Errorf("no background server at %s", ctrlAddr)
	}
	defer conn.Close()
	fmt.Fprintln(conn, "stop")
	r := bufio.NewReader(conn)
	resp, _ := r.ReadString(0)
	fmt.Print(strings.TrimRight(resp, "\x00"))
	return nil
}
