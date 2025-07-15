//go:build !windows

package cmd

import "os/exec"

func GetWindowsBrowserCommand(url string) *exec.Cmd {
	return nil
}
