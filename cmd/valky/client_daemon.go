package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chzyer/readline"
)

// defaultClientCtrlAddr is the client engine's local control channel (distinct
// from the server's 47655).
const defaultClientCtrlAddr = "127.0.0.1:47656"

func clientPidPath() string { return filepath.Join(os.TempDir(), "valky-client.pid") }

// isClientEngine reports whether this process is the background client engine.
func isClientEngine() bool { return os.Getenv("VALKY_CLIENT_ENGINE") == "1" }

// serveClientControl accepts console connections for the client engine.
func serveClientControl(ln net.Listener, cs *clientState) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("client control accept: %v", err)
			continue
		}
		go handleClientControl(conn, cs)
	}
}

func handleClientControl(conn net.Conn, cs *clientState) {
	defer conn.Close()
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch line {
		case "status":
			cs.writeStatus(conn)
		case "stop", "shutdown":
			fmt.Fprintln(conn, paint(cMagenta, "stopping client..."))
			conn.Write([]byte{0})
			if cs.nm != nil {
				cs.nm.teardown()
			}
			_ = os.Remove(clientPidPath())
			log.Printf("stopped by console")
			os.Exit(0)
		default:
			fmt.Fprintf(conn, "%s %q (try 'help')\n", paint(cMagenta, "unknown command"), line)
		}
		conn.Write([]byte{0})
	}
}

// attachClientConsole connects to the running client engine and runs the themed,
// interactive console (Tab-completion, history).
func attachClientConsole(ctrlAddr string) error {
	conn, err := net.DialTimeout("tcp", ctrlAddr, 2*time.Second)
	if err != nil {
		return fmt.Errorf("no background client at %s (start it with 'valky client --ip ...'): %w", ctrlAddr, err)
	}
	defer conn.Close()
	r := bufio.NewReader(conn)

	fmt.Println(clientBanner(ctrlAddr))

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          clientPrompt(),
		HistoryFile:     clientHistoryFile(),
		AutoComplete:    clientCompleter(),
		InterruptPrompt: "^C",
		EOFPrompt:       "detach",
	})
	if err != nil {
		return attachClientConsolePlain(conn, r)
	}
	defer rl.Close()

	for {
		line, err := rl.Readline()
		if err != nil {
			fmt.Println(paint(cGray, "console detached; client keeps running in the background"))
			return nil
		}
		line = strings.TrimSpace(line)
		switch line {
		case "":
			continue
		case "detach", "bg", "background", "quit", "exit":
			fmt.Println(paint(cGray, "console detached; client keeps running in the background"))
			return nil
		case "help", "?":
			fmt.Print(clientHelp())
			continue
		}
		if _, err := fmt.Fprintf(conn, "%s\n", line); err != nil {
			fmt.Println(paint(cMagenta, "lost connection to client engine"))
			return nil
		}
		resp, err := r.ReadString(0)
		if len(resp) > 0 {
			fmt.Print(strings.TrimRight(resp, "\x00"))
		}
		if err != nil {
			fmt.Println(paint(cMagenta, "client stopped"))
			return nil
		}
	}
}

func attachClientConsolePlain(conn net.Conn, r *bufio.Reader) error {
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		switch line {
		case "":
			continue
		case "detach", "bg", "background", "quit", "exit":
			return nil
		case "help", "?":
			fmt.Print(clientHelp())
			continue
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

func clientHistoryFile() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "valky-client-history")
	}
	_ = os.MkdirAll(filepath.Join(dir, "valky"), 0o700)
	return filepath.Join(dir, "valky", "client-history")
}

// stopClient tells a running client engine to shut down.
func stopClient(ctrlAddr string) error {
	conn, err := net.DialTimeout("tcp", ctrlAddr, 2*time.Second)
	if err != nil {
		return fmt.Errorf("no background client at %s", ctrlAddr)
	}
	defer conn.Close()
	fmt.Fprintln(conn, "stop")
	r := bufio.NewReader(conn)
	resp, _ := r.ReadString(0)
	fmt.Print(strings.TrimRight(resp, "\x00"))
	return nil
}
