//go:build unix

package main

import "syscall"

// execSelf replaces the current process image with argv/env (keeping the same
// PID and controlling terminal). On success it never returns.
func execSelf(exe string, argv, env []string) error {
	return syscall.Exec(exe, argv, env)
}
