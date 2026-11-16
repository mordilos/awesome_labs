package lima

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const testNet = "user,id=net0,net=192.168.5.0/24,dhcpstart=192.168.5.15,hostfwd=tcp:127.0.0.1:60022-:22"

func TestOffsecWrapper(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "fake qemu")
	if err := os.WriteFile(real, []byte("#!/bin/bash\nprintf '%s\\n' \"$@\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, online := range []bool{false, true} {
		wrapper := filepath.Join(dir, "wrapper")
		if err := os.WriteFile(wrapper, []byte(offsecWrapper(real, online)), 0o700); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(wrapper, "-name", "lima-kl-offsec", "-netdev", testNet, "-drive", "file=has space").CombinedOutput()
		if err != nil {
			t.Fatalf("wrapper: %v: %s", err, out)
		}
		if strings.Contains(string(out), restrictedSuffix) == online {
			t.Fatalf("online=%v: %s", online, out)
		}
		if !strings.Contains(string(out), "file=has space\n") {
			t.Fatalf("lost argument: %s", out)
		}
		for _, network := range []string{
			testNet + ",guestfwd=tcp:192.168.5.4:80-tcp:127.0.0.1:80",
			testNet + ",restrict=off", testNet + ",smb=/", "tap,id=net0", "socket,id=net0,fd=3",
			strings.Replace(testNet, "127.0.0.1", "0.0.0.0", 1),
		} {
			if out, err := exec.Command(wrapper, "-name", "lima-kl-offsec", "-netdev", network).CombinedOutput(); err == nil {
				t.Fatalf("accepted unsafe network %q: %s", network, out)
			}
		}
		for _, extra := range [][]string{{"-netdev", testNet}, {"-nic", "user"}, {"-readconfig", "other.conf"}} {
			args := append([]string{"-name", "lima-kl-offsec", "-netdev", testNet}, extra...)
			if err := exec.Command(wrapper, args...).Run(); err == nil {
				t.Fatalf("accepted %v", args)
			}
		}
		for _, probe := range [][]string{{"--version"}, {"-M", "none", "-accel", "help"}, {"-M", "none", "-netdev", "help"}, {"-machine", "help"}, {"-cpu", "help", "-machine", "q35"}, {"-cpu", "help", "-machine", "virt"}} {
			if out, err := exec.Command(wrapper, probe...).CombinedOutput(); err != nil {
				t.Fatalf("probe %v: %v %s", probe, err, out)
			}
		}
	}
}

func TestRestrictedCommand(t *testing.T) {
	good := "qemu-system-x86_64 -name lima-kl-offsec -netdev " + testNet + restrictedSuffix
	if !restrictedCommand(good) {
		t.Fatal("rejected restricted command")
	}
	for _, bad := range []string{
		strings.Replace(good, restrictedSuffix, "", 1),
		strings.Replace(good, "restrict=on", "restrict=off", 1),
		good + " -netdev user,id=net1", good + " -nic user", good + " -readconfig extra.conf",
		strings.Replace(good, "127.0.0.1", "0.0.0.0", 1),
		strings.Replace(good, "lima-kl-offsec", "another-vm", 1),
	} {
		if restrictedCommand(bad) {
			t.Fatalf("accepted %s", bad)
		}
	}
}

func TestOffsecConfig(t *testing.T) {
	b, err := os.ReadFile("../../vms/offsec.yaml")
	if err != nil {
		t.Fatal(err)
	}
	in := Instance{Dir: filepath.Join(t.TempDir(), "kl-offsec")}
	if err := os.Mkdir(in.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, from, to string
		valid          bool
	}{
		{"template", "", "", true},
		{"VZ", "vmType: qemu", "vmType: vz", false},
		{"mount", "mounts: []", "mounts: [{location: '~'}]", false},
		{"extra network", "networks: []", "networks: [{lima: user-v2}]", false},
		{"DNS proxy", "enabled: false", "enabled: true", false},
		{"SSH agent", "forwardAgent: false", "forwardAgent: true", false},
		{"X11", "forwardX11: false", "forwardX11: true", false},
		{"forward loopback", "guestIPMustBeZero: false", "guestIPMustBeZero: true", false},
		{"forward ports", "ignore: true", "ignore: false", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := string(b)
			if tc.from != "" {
				body = strings.Replace(body, tc.from, tc.to, 1)
			}
			if err := os.WriteFile(filepath.Join(in.Dir, "lima.yaml"), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := ValidateOffsecConfig(in); (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
	if err := os.WriteFile(filepath.Join(in.Dir, "lima.yaml"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(filepath.Dir(in.Dir), "_config")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "override.yaml"), []byte("ssh: {forwardAgent: true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateOffsecConfig(in); err == nil {
		t.Fatal("accepted global override")
	}
}
