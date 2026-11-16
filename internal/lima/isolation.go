package lima

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Only Lima's single SLIRP interface and localhost SSH forward are allowed.
// Reconstructing this argument rejects guestfwd, SMB, TFTP and extra forwards.
const offsecNetPattern = `^user,id=net0,net=192\.168\.5\.0/24,dhcpstart=192\.168\.5\.15,hostfwd=tcp:127\.0\.0\.1:([0-9]+)-:22$`
const restrictedSuffix = ",restrict=on,ipv6=off"

func offsecWrapper(real string, online bool) string {
	suffix := restrictedSuffix
	if online {
		suffix = ""
	}
	return `#!/usr/bin/env bash
set -euo pipefail
# Lima probes QEMU before launching it. These invocations do not boot a guest.
case "$*" in
  --version|-version|"-M none -accel help"|"-M none -netdev help"|"-machine help"|"-cpu help -machine q35"|"-cpu help -machine virt") exec ` + shellQuote(real) + ` "$@" ;;
esac
args=()
networks=0
name=
while (( $# )); do
  case "$1" in
    -netdev)
      [[ ${2:-} =~ ` + offsecNetPattern + ` ]] || { echo 'unsafe offsec network argument' >&2; exit 1; }
      networks=$((networks + 1))
      args+=("-netdev" "$2` + suffix + `")
      shift 2 ;;
    -net|-nic|-readconfig|-netdev=*|-net=*|-nic=*|-readconfig=*)
      echo 'additional offsec network configuration is forbidden' >&2; exit 1 ;;
    -name) name=${2:-}; args+=("$1" "$name"); shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
[[ $networks == 1 && $name == lima-kl-offsec ]] || { echo 'expected one network for kl-offsec' >&2; exit 1; }
exec ` + shellQuote(real) + ` "${args[@]}"
`
}

// StartOffsec uses a dedicated QEMU launcher on both Linux and macOS. Online
// mode is reserved for a newly created VM, before it has run any exercises.
func StartOffsec(ctx context.Context, stateDir string, online bool, log io.Writer) error {
	arch := qemuArch()
	if arch == "" {
		return fmt.Errorf("offsec isolation requires QEMU on amd64 or arm64")
	}
	real, err := exec.LookPath("qemu-system-" + arch)
	if err != nil {
		return fmt.Errorf("offsec isolation requires QEMU (run awesome_labs install): %w", err)
	}
	real, err = filepath.EvalSymlinks(real)
	if err != nil {
		return err
	}
	dir := filepath.Join(stateDir, "offsec-qemu")
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o700); err != nil {
		return err
	}
	if err := ensureSymlink(filepath.Join(filepath.Dir(filepath.Dir(real)), "share"), filepath.Join(dir, "share")); err != nil {
		return err
	}
	wrapper := filepath.Join(dir, "bin", "qemu-system-"+arch)
	if err := writeExecutable(wrapper, []byte(offsecWrapper(real, online))); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, Binary, "start", "--tty=false", "--timeout=30m", "kl-offsec")
	key := "QEMU_SYSTEM_" + strings.ToUpper(arch)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, key+"=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, key+"="+wrapper)
	cmd.Stdout, cmd.Stderr = log, log
	return cmd.Run()
}

// ValidateOffsecConfig rejects old VZ instances and host integration overrides.
func ValidateOffsecConfig(in Instance) error {
	if in.Dir == "" {
		return fmt.Errorf("offsec instance directory is missing")
	}
	// Lima merges these files again on every boot. Reading only lima.yaml
	// would miss overrides that restore mounts, forwarding or another backend.
	for _, name := range []string{"default.yaml", "override.yaml"} {
		path := filepath.Join(filepath.Dir(in.Dir), "_config", name)
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		var config map[string]any
		if err := yaml.Unmarshal(data, &config); err != nil {
			return err
		}
		if len(config) != 0 {
			return fmt.Errorf("offsec isolation cannot use shared Lima configuration %s; use a separate LIMA_HOME without defaults or overrides", path)
		}
	}
	b, err := os.ReadFile(filepath.Join(in.Dir, "lima.yaml"))
	if err != nil {
		return err
	}
	var c struct {
		VMType       string `yaml:"vmType"`
		Mounts       []any  `yaml:"mounts"`
		Networks     []any  `yaml:"networks"`
		CopyToHost   []any  `yaml:"copyToHost"`
		HostResolver struct {
			Enabled *bool `yaml:"enabled"`
		} `yaml:"hostResolver"`
		SSH struct {
			ForwardAgent      bool `yaml:"forwardAgent"`
			ForwardX11        bool `yaml:"forwardX11"`
			ForwardX11Trusted bool `yaml:"forwardX11Trusted"`
		} `yaml:"ssh"`
		PortForwards []struct {
			GuestIP           string `yaml:"guestIP"`
			GuestIPMustBeZero *bool  `yaml:"guestIPMustBeZero"`
			Proto             string `yaml:"proto"`
			Ignore            bool   `yaml:"ignore"`
		} `yaml:"portForwards"`
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return err
	}
	if c.VMType != "qemu" || len(c.Mounts)+len(c.Networks)+len(c.CopyToHost) != 0 ||
		c.HostResolver.Enabled == nil || *c.HostResolver.Enabled ||
		c.SSH.ForwardAgent || c.SSH.ForwardX11 || c.SSH.ForwardX11Trusted || len(c.PortForwards) != 1 {
		return fmt.Errorf("offsec VM has unsafe host integrations; rebuild it with awesome_labs env rebuild offsec")
	}
	p := c.PortForwards[0]
	if p.GuestIP != "0.0.0.0" || p.GuestIPMustBeZero == nil || *p.GuestIPMustBeZero || p.Proto != "any" || !p.Ignore {
		return fmt.Errorf("offsec VM must disable all automatic port forwarding")
	}
	return nil
}

// CheckOffsecIsolation inspects the actual host process, never a guest-written
// marker. A VM started directly with limactl is rejected before running scripts.
func CheckOffsecIsolation(ctx context.Context, in Instance) error {
	if in.Status != "Running" || in.DriverPID <= 0 || in.VMType != "qemu" {
		return fmt.Errorf("offsec VM is not running under restricted QEMU")
	}
	if err := ValidateOffsecConfig(in); err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, "ps", "-ww", "-p", strconv.Itoa(in.DriverPID), "-o", "command=").Output()
	if err != nil {
		return fmt.Errorf("inspect offsec QEMU: %w", err)
	}
	if !restrictedCommand(string(out)) {
		return fmt.Errorf("offsec VM networking is not isolated; stop it and start it through awesome_labs")
	}
	return nil
}

func restrictedCommand(command string) bool {
	fields := strings.Fields(command)
	nets, named := 0, false
	pattern := regexp.MustCompile(strings.TrimSuffix(offsecNetPattern, "$") + regexp.QuoteMeta(restrictedSuffix) + "$")
	for i, field := range fields {
		for _, prefix := range []string{"-netdev=", "-net=", "-nic=", "-readconfig="} {
			if strings.HasPrefix(field, prefix) {
				return false
			}
		}
		switch field {
		case "-net", "-nic", "-readconfig":
			return false
		case "-name":
			named = i+1 < len(fields) && fields[i+1] == "lima-kl-offsec"
		case "-netdev":
			nets++
			if i+1 >= len(fields) || !pattern.MatchString(fields[i+1]) {
				return false
			}
		}
	}
	return nets == 1 && named
}
