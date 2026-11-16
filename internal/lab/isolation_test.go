package lab

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"awesome_labs/internal/lima"
)

// Fake only the process boundary: exercise the real creation/boot/validation
// lifecycle without creating VMs or executing root provisioning scripts.
func fakeOffsec(t *testing.T) (*Manager, string) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for the fake limactl")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OFFSEC_TEST_DIR", dir)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	old := lima.Binary
	lima.Binary = filepath.Join(bin, "limactl")
	t.Cleanup(func() { lima.Binary = old })
	script := `import os,sys,json,pathlib,shutil
d=pathlib.Path(os.environ['OFFSEC_TEST_DIR']); vm=d/'vm'; a=sys.argv[1:]
with (d/'calls').open('a') as f: f.write(a[0]+'\n')
if a[0]=='list':
 if vm.exists():
  running=(vm/'running').exists()
  print(json.dumps(dict(name='kl-offsec',dir=str(vm),status='Running' if running else 'Stopped',vmType='qemu',driverPID=123 if running else 0)))
elif a[0]=='create':
 vm.mkdir(); shutil.copyfile(a[-1],vm/'lima.yaml')
elif a[0]=='start':
 wrapper=next(v for k,v in os.environ.items() if k.startswith('QEMU_SYSTEM_'))
 offline=',restrict=on,ipv6=off' in pathlib.Path(wrapper).read_text()
 with (d/'boots').open('a') as f: f.write(('offline' if offline else 'online')+'\n')
 (vm/'running').touch(); (vm/'offline').write_text(str(offline))
elif a[0]=='stop':
 (vm/'running').unlink(missing_ok=True)
elif a[0]=='shell':
 sys.stdin.read()
 if os.environ.get('OFFSEC_FAIL_BOOTSTRAP')=='1': sys.exit(1)
else: sys.exit(2)
`
	if err := os.WriteFile(lima.Binary, []byte("#!"+python+"\n"+script), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"x86_64", "aarch64"} {
		if err := os.WriteFile(filepath.Join(bin, "qemu-system-"+arch), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	ps := `#!/bin/sh
printf 'qemu -name lima-kl-offsec -netdev user,id=net0,net=192.168.5.0/24,dhcpstart=192.168.5.15,hostfwd=tcp:127.0.0.1:60022-:22'
if [ "$(cat "$OFFSEC_TEST_DIR/vm/offline")" = True ]; then printf ',restrict=on,ipv6=off'; fi
printf '\n'
`
	if err := os.WriteFile(filepath.Join(bin, "ps"), []byte(ps), 0o700); err != nil {
		t.Fatal(err)
	}
	// Avoid contacting any real SSH control master during the fake bootstrap.
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return &Manager{Assets: os.DirFS("../.."), StateDir: dir, User: "lab", logFile: io.Discard}, dir
}

func TestOffsecProvisionThenAlwaysOffline(t *testing.T) {
	m, dir := fakeOffsec(t)
	if err := m.Ensure(t.Context(), OffsecEnv, io.Discard); err != nil {
		t.Fatal(err)
	}
	boots, _ := os.ReadFile(filepath.Join(dir, "boots"))
	if string(boots) != "online\noffline\n" {
		t.Fatalf("boots: %s", boots)
	}
	if _, err := os.Stat(filepath.Join(dir, "vm", offsecProvisioned)); err != nil {
		t.Fatal(err)
	}
	if err := m.Ensure(t.Context(), OffsecEnv, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(t.Context(), OffsecEnv, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := m.Ensure(t.Context(), OffsecEnv, io.Discard); err != nil {
		t.Fatal(err)
	}
	boots, _ = os.ReadFile(filepath.Join(dir, "boots"))
	if string(boots) != "online\noffline\noffline\n" {
		t.Fatalf("reconnected existing VM: %s", boots)
	}
	if err := os.WriteFile(filepath.Join(dir, "vm", "offline"), []byte("False"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.CheckIsolation(t.Context(), OffsecEnv); err == nil {
		t.Fatal("accepted direct unrestricted restart")
	}
	if err := m.Ensure(t.Context(), OffsecEnv, io.Discard); err == nil {
		t.Fatal("accepted running unrestricted VM")
	}
}

func TestOffsecFailedProvisioningStopsAndRequiresRebuild(t *testing.T) {
	m, dir := fakeOffsec(t)
	t.Setenv("OFFSEC_FAIL_BOOTSTRAP", "1")
	if err := m.Ensure(t.Context(), OffsecEnv, io.Discard); err == nil {
		t.Fatal("expected bootstrap failure")
	}
	if _, err := os.Stat(filepath.Join(dir, "vm", "running")); !os.IsNotExist(err) {
		t.Fatal("failed provisioning VM left running")
	}
	if _, err := os.Stat(filepath.Join(dir, "vm", offsecProvisioned)); !os.IsNotExist(err) {
		t.Fatal("failed VM marked provisioned")
	}
	t.Setenv("OFFSEC_FAIL_BOOTSTRAP", "")
	if err := m.Ensure(t.Context(), OffsecEnv, io.Discard); err == nil || !strings.Contains(err.Error(), "rebuild") {
		t.Fatalf("retry must require rebuild: %v", err)
	}
	boots, _ := os.ReadFile(filepath.Join(dir, "boots"))
	if string(boots) != "online\n" {
		t.Fatalf("reconnected interrupted VM: %s", boots)
	}
}
