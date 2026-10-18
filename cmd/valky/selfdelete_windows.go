//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// deleteSelf removes the running binary on Windows, where a running .exe is
// locked and cannot delete itself. It spawns a detached cmd helper that waits a
// moment for this process to exit (releasing the file) and then deletes it.
func deleteSelf(exe string) {
	const (
		detachedProcess  = 0x00000008
		createNoWindow   = 0x08000000
		createNewProcGrp = 0x00000200
	)
	c := exec.Command("cmd")
	c.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: detachedProcess | createNoWindow | createNewProcGrp,
		// Raw command line: wait ~1s, then force-delete our binary.
		CmdLine: `cmd /C ping 127.0.0.1 -n 2 >nul & del /F /Q "` + exe + `"`,
	}
	_ = c.Start()
}
