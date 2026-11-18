//go:build linux

package hostd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// treeSum is the SHA-256 of every path, mode and content under root: the
// machine's state, to compare before and after the hostile runs.
func treeSum(t *testing.T, root string) string {
	t.Helper()
	hash := sha256.New()
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			hash.Write([]byte("err " + p))
			return nil
		}
		info, _ := d.Info()
		hash.Write([]byte(p + " " + info.Mode().String()))
		if d.Type().IsRegular() && info.Size() < 1<<20 {
			data, _ := os.ReadFile(p)
			hash.Write(data)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			target, _ := os.Readlink(p)
			hash.Write([]byte(target))
		}
		return nil
	})
	return hex.EncodeToString(hash.Sum(nil))
}

// TestPodmanEscapes runs what a hostile agent would try in a dry run, and
// checks that each one fails and that the machine is the same after. Same
// conditions as TestPodmanDryRun.
func TestPodmanEscapes(t *testing.T) {
	if os.Getenv("NIA_PODMAN_TEST") != "yes" {
		t.Skip("NIA_PODMAN_TEST=yes runs this, as root, where podman is installed")
	}
	s, _, _ := machine(t, `{"name":"vps","mode":"enforce","rule_of_two":"require_approval","destructive":"require_approval","tools":[],"host":{"etc":{}}}`)
	scratch, _ := os.MkdirTemp("/tmp", "p")
	defer os.RemoveAll(scratch)
	s.ScratchRoot = scratch
	s.Sandbox = Podman{Root: scratch + "/podman", RunRoot: scratch + "/podman-run"}

	// What root keeps on this machine, where a dry run must not see it.
	os.MkdirAll("/data/backups", 0o700)
	os.WriteFile("/data/backups/db.sql", []byte("DATA-SECRET\n"), 0o600)
	os.WriteFile("/swapfile-nia", []byte("SWAP-SECRET\n"), 0o600)
	os.MkdirAll("/etc/vault", 0o700)
	os.WriteFile("/etc/vault/token", []byte("VAULT-SECRET\n"), 0o644)
	os.MkdirAll("/root/.ssh", 0o700)
	os.WriteFile("/root/.ssh/id_ed25519", []byte("ROOT-KEY-SECRET\n"), 0o600)
	defer os.RemoveAll("/data")
	defer os.Remove("/swapfile-nia")
	defer os.RemoveAll("/etc/vault")
	secrets := []string{"DATA-SECRET", "SWAP-SECRET", "VAULT-SECRET", "ROOT-KEY-SECRET"}

	trees := []string{"/etc", "/usr/local", "/data", "/root"}
	before := map[string]string{}
	for _, tree := range trees {
		before[tree] = treeSum(t, tree)
	}
	swap, _ := os.ReadFile("/swapfile-nia")

	attempts := []struct {
		name, script string
		// refused must appear in the output; leaks must not.
		refused []string
	}{
		{"read root's data", "cat /data/backups/db.sql; ls -A /data; cat /swapfile-nia; cat /root/.ssh/id_ed25519; cat /etc/vault/token", nil},
		{"remount the root", "mount -o remount,rw / 2>&1; mount -t tmpfs x /usr 2>&1; touch /usr/x 2>&1", []string{"Read-only file system"}},
		{"a user namespace", "unshare -U -r -m sh -c 'mount -t tmpfs x /etc && echo mounted > /etc/inside; cat /etc/inside' 2>&1; unshare -m sh -c 'echo no' 2>&1", nil},
		{"chroot and pivot", "chroot / id 2>&1; pivot_root / / 2>&1", nil},
		{"setuid programs", "sudo -n id 2>&1; su -c id 2>&1; ls -l /usr/bin/sudo 2>&1", nil},
		{"kernel and devices", "cat /proc/kcore 2>&1 | head -c 20; cat /dev/mem 2>&1 | head -c 20; ls /dev/sda* /dev/vd* /dev/nvme* 2>&1; echo 1 > /proc/sys/kernel/sysrq 2>&1; echo b > /proc/sysrq-trigger 2>&1; insmod /x.ko 2>&1; echo x > /sys/kernel/uevent_helper 2>&1", nil},
		{"other processes", "ls /proc | grep -c '^[0-9]'; kill -9 1 2>&1; cat /proc/1/environ 2>&1 | head -c 50", nil},
		{"the network", "getent hosts example.com 2>&1 || echo no-dns; cat /proc/net/route; (exec 3<>/dev/tcp/1.1.1.1/443) 2>&1; python3 -c 'import socket; socket.create_connection((\"1.1.1.1\", 443), 3)' 2>&1 | tail -1", nil},
		{"fill the layer", "dd if=/dev/zero of=/etc/big bs=1M count=200 2>&1 | head -2", []string{"No space left on device", "bytes, more than 8388608"}},
		{"fill the inodes", "mkdir -p /etc/many && i=0; while [ $i -lt 40000 ]; do touch /etc/many/$i 2>/dev/null || { echo full at $i; break; }; i=$((i+1)); done", []string{"full at", "too_many"}},
		{"podman's own files", "echo x > /etc/hostname 2>&1; echo x > /etc/resolv.conf 2>&1; echo x > /etc/hosts 2>&1; true", nil},
		{"the masked directories", "echo x > /var/x && echo x > /tmp/x && echo x > /root/x && ls /var /tmp /root", nil},
	}
	for _, a := range attempts {
		t.Run(a.name, func(t *testing.T) {
			// The marker proves the script ran: an attempt that never ran proves nothing.
			resp := s.Do(context.Background(), Request{Action: DryRunAction, Script: a.script + "\necho NIA-RAN-$((40+2))"})
			text := resp.Output + resp.Error
			if !strings.Contains(text, "NIA-RAN-42") {
				t.Fatalf("the script did not run: %s", text)
			}
			t.Logf("%s", strings.ReplaceAll(text, `\n`, "\n"))
			for _, secret := range secrets {
				if strings.Contains(text, secret) {
					t.Errorf("%s came out", secret)
				}
			}
			var r Report
			json.Unmarshal([]byte(resp.Output), &r)
			if _, why := r.Applicable(); why != "" {
				text += " " + why
			}
			if len(resp.Output) > 1<<20 {
				t.Errorf("a report of %d bytes", len(resp.Output))
			}
			for _, want := range a.refused {
				if !strings.Contains(text, want) {
					t.Errorf("output lacks %q", want)
				}
			}
		})
	}
	// A pipe in the layer cannot be applied: the dry run says so, no plan.
	resp := s.Do(context.Background(), Request{Action: DryRunAction, Script: "mkfifo /etc/fifo && echo made"})
	if resp.OK || !strings.Contains(resp.Error+resp.Output, "pipe") {
		t.Errorf("a pipe: %+v", resp)
	}

	for _, tree := range trees {
		if after := treeSum(t, tree); after != before[tree] {
			t.Errorf("%s changed", tree)
		}
	}
	if data, _ := os.ReadFile("/swapfile-nia"); string(data) != string(swap) {
		t.Error("/swapfile-nia changed")
	}
	// Nothing left behind: no mount of a dry run, no container.
	time.Sleep(time.Second)
	if mounts, _ := os.ReadFile("/proc/self/mountinfo"); strings.Contains(string(mounts), scratch) {
		t.Errorf("mounts left:\n%s", mounts)
	}
	if entries, _ := os.ReadDir(scratch); len(entries) > 2 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Logf("scratch holds %v (kept plans and podman's storage)", names)
	}
}

// TestPodmanLimits: the container's processes and memory are bounded where
// the machine has cgroup v2 (every systemd distribution of today).
func TestPodmanLimits(t *testing.T) {
	if os.Getenv("NIA_PODMAN_TEST") != "yes" {
		t.Skip("NIA_PODMAN_TEST=yes runs this, as root, where podman is installed")
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skip("no cgroup v2 here: podman cannot bound processes and memory")
	}
	s, _, _ := machine(t, `{"name":"vps","mode":"enforce","rule_of_two":"require_approval","destructive":"require_approval","tools":[],"host":{"etc":{}}}`)
	scratch, _ := os.MkdirTemp("/tmp", "p")
	defer os.RemoveAll(scratch)
	s.ScratchRoot = scratch
	s.Sandbox = Podman{Root: scratch + "/podman", RunRoot: scratch + "/podman-run"}
	resp := s.Do(context.Background(), Request{Action: DryRunAction, Script: "cat /sys/fs/cgroup/pids.max /sys/fs/cgroup/memory.max; i=0; while [ $i -lt 400 ]; do sleep 20 & i=$((i+1)); done 2>&1 | tail -1; echo NIA-RAN"})
	t.Logf("%s", resp.Output)
	if !strings.Contains(resp.Output, "256") || !strings.Contains(resp.Output, "536870912") || !strings.Contains(resp.Output, "fork") {
		t.Errorf("not bounded: %s", resp.Output)
	}
}

// TestPodmanTimeout: a script past its time is stopped, nothing is kept and
// no container is left.
func TestPodmanTimeout(t *testing.T) {
	if os.Getenv("NIA_PODMAN_TEST") != "yes" {
		t.Skip("NIA_PODMAN_TEST=yes runs this, as root, where podman is installed")
	}
	s, _, _ := machine(t, `{"name":"vps","mode":"enforce","rule_of_two":"require_approval","destructive":"require_approval","tools":[],"host":{"etc":{}}}`)
	scratch, _ := os.MkdirTemp("/tmp", "p")
	defer os.RemoveAll(scratch)
	s.ScratchRoot, s.DryTimeout = scratch, 3*time.Second
	p := Podman{Root: scratch + "/podman", RunRoot: scratch + "/podman-run"}
	s.Sandbox = p
	start := time.Now()
	resp := s.Do(context.Background(), Request{Action: DryRunAction, Script: "echo x > /etc/slow; sleep 60; echo late"})
	var r Report
	json.Unmarshal([]byte(resp.Output), &r)
	if elapsed := time.Since(start); elapsed > 20*time.Second || r.Failed == "" || strings.Contains(r.Output, "late") || len(s.Plans()) != 0 {
		t.Errorf("after %v: %+v", elapsed, r)
	}
	ps := exec.Command("podman", "--root", p.Root, "--runroot", p.RunRoot, "--storage-driver", "vfs", "--log-level", "error", "ps", "-a", "-q")
	ps.Env = append(os.Environ(), "CONTAINERS_STORAGE_CONF="+p.RunRoot+".storage.conf")
	out, _ := ps.CombinedOutput()
	if strings.TrimSpace(string(out)) != "" {
		t.Errorf("containers left: %s", out)
	}
}
