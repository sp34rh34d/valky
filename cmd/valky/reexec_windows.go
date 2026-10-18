//go:build !unix

package main

import "errors"

// execSelf is unsupported outside Unix (no in-place exec); callers fall back to
// running the console in the current process.
func execSelf(string, []string, []string) error {
	return errors.New("exec not supported on this platform")
}
