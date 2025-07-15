package cmd

import (
	"fmt"
	"os/exec"
	"runtime"
)

func GetBrowserCommand(url string) (*exec.Cmd, error) {
	os := runtime.GOOS
	path := ""
	var cmd *exec.Cmd
	var args []string
	switch os {
	case "windows":
		cmd = GetWindowsBrowserCommand(url)
	case "darwin":
		path = "open"
		args = []string{url}
		cmd = exec.Command(path, args...)
	case "linux":
		path = "xdg-open"
		args = []string{url}
		cmd = exec.Command(path, args...)
	default:
		return nil, fmt.Errorf("unsupported platform")
	}

	return cmd, nil
}
