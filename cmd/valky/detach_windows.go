//go:build windows

package main

import "syscall"

// detachSysProcAttr starts the child detached from the console in its own
// process group so it keeps running after the parent exits.
func detachSysProcAttr() *syscall.SysProcAttr {
	const (
		detachedProcess     = 0x00000008
		createNewProcessGrp = 0x00000200
	)
	return &syscall.SysProcAttr{CreationFlags: detachedProcess | createNewProcessGrp}
}
