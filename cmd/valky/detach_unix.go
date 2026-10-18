//go:build !windows

package main

import "syscall"

// detachSysProcAttr starts the child in a new session so it is not killed when
// the parent terminal closes.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
