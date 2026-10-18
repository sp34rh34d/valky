// Command valky is a single binary with two subcommands:
//
//	valky server --config config.ini
//	valky client --ip <server> --port <port> --passwd <secret> [--dev name]
//
// The server is the hub: clients connect to it and can reach each other's
// network segments only according to the rules the operator sets in the
// server's interactive console.
package main

import (
	"fmt"
	"os"
)

func usage() {
	fmt.Fprint(os.Stderr, `valky - client/server tunnel

Usage:
  valky server --create-config [--config config.ini]   generate config.ini with a random MD5 key
  valky server --config config.ini [--encrypt] [--state <file>] [--bg] [--ctrl 127.0.0.1:47655] [--log <file>]
  valky --resume [--ctrl 127.0.0.1:47655]   reattach the console to the background server
  valky --stop   [--ctrl 127.0.0.1:47655]   stop the background server
  valky client --ip <server> --port <port> --passwd <key> [--dev <iface>] [--id <uuid>] [--bg] [--cctrl 127.0.0.1:47656] [--log <file>] [--name valky]
  valky client --resume [--cctrl 127.0.0.1:47656]   reopen the console of a backgrounded client
  valky client --stop   [--cctrl 127.0.0.1:47656]   stop the backgrounded client

`)
}

func main() {
	// Re-exec'd client roles carry a clean argv (just the title), so dispatch on
	// the environment before inspecting os.Args.
	if isClientEngine() || isClientConsole() {
		runClient(nil)
		return
	}
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	case "--resume", "resume":
		if err := attachConsole(ctrlFrom(os.Args[2:])); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "--stop", "stop":
		if err := stopDaemon(ctrlFrom(os.Args[2:])); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

// ctrlFrom extracts an optional "--ctrl <addr>" from args, defaulting otherwise.
func ctrlFrom(args []string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--ctrl" {
			return args[i+1]
		}
	}
	return defaultCtrlAddr
}
