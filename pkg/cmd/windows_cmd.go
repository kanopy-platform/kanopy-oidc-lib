//go:build windows

package cmd

import (
	"fmt"
	"os/exec"
	"syscall"
)

func GetWindowsBrowserCommand(url string) *exec.Cmd {
	path := "cmd"
	cmd := exec.Command(path)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: fmt.Sprintf("/c start \"\" \"%s\"", url)}
	return cmd
}
