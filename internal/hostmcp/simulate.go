package hostmcp

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"regexp"
	"time"
)

// packageName is a Debian package name, as apt prints it.
var packageName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.:~-]{0,127}$`)

// AptSimulate asks apt what installing a package would install, without
// root and without changing anything (apt-get -s), with the options
// nia-hostd installs with. What it prints is shown to the task's reviewer
// and never decided on: nil when apt cannot say.
func AptSimulate(ctx context.Context, pkg string) []string {
	if !packageName.MatchString(pkg) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/apt-get", "-s", "-q", "-o", "Debug::NoLocking=1", "install", "--no-install-recommends", "--", pkg)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return simulated(out)
}

var instLine = regexp.MustCompile(`^Inst (\S+)`)

// simulated reads the packages apt-get -s would install, at most 500.
func simulated(out []byte) []string {
	var installs []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() && len(installs) < 500 {
		if match := instLine.FindSubmatch(scanner.Bytes()); match != nil && packageName.Match(match[1]) {
			installs = append(installs, string(match[1]))
		}
	}
	return installs
}
