//go:build unix

package main

import "os"

// deleteSelf removes the running binary. On Unix a running executable can be
// unlinked; the inode is freed once the process exits.
func deleteSelf(exe string) {
	_ = os.Remove(exe)
}
