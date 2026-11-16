package lab

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"awesome_labs/internal/exercise"
	"awesome_labs/internal/lima"
)

const offsecProvisioned = "awesome-labs-isolation-v1"

// ensureOffsec never reconnects an existing exercise VM to the outside network.
// Only a newly created instance may provision online. Interrupted provisioning
// requires rebuilding, because the guest's readiness files are not trustworthy.
func (m *Manager) ensureOffsec(ctx context.Context, env Env, log io.Writer) (err error) {
	all, err := lima.List(ctx)
	if err != nil {
		return err
	}
	vm := env.Primary()
	in := all[vm.Name]
	if in.Status != "" {
		if err := lima.ValidateOffsecConfig(in); err != nil {
			return err
		}
		if _, err := os.Stat(filepath.Join(in.Dir, offsecProvisioned)); err != nil {
			return fmt.Errorf("offsec VM lacks a completed isolation setup; run awesome_labs env rebuild offsec")
		}
		if in.Status != "Running" {
			m.setClean(env, false)
			if err := lima.StartOffsec(ctx, m.StateDir, false, log); err != nil {
				return err
			}
		}
		if err := m.CheckIsolation(ctx, env); err != nil {
			return err
		}
		return m.pushKit(ctx, env, log)
	}

	tmpl, err := m.template(env, vm)
	if err != nil {
		return err
	}
	fmt.Fprintln(log, "==> creating offsec VM: online provisioning, then an isolated reboot")
	if err := lima.Create(ctx, vm.Name, tmpl, log); err != nil {
		return err
	}
	// Stop even when the caller's context was cancelled. Never leave a failed
	// online bootstrap running, and never run exercises after a failed transition.
	defer func() {
		if err != nil {
			stopCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if stopErr := lima.Stop(stopCtx, vm.Name, log); stopErr != nil {
				err = fmt.Errorf("%w; also failed to stop provisioning VM: %v", err, stopErr)
			}
		}
	}()
	all, err = lima.List(ctx)
	if err != nil {
		return err
	}
	in = all[vm.Name]
	if err = lima.ValidateOffsecConfig(in); err != nil {
		return err
	}
	if err = lima.StartOffsec(ctx, m.StateDir, true, log); err != nil {
		return err
	}
	if err = m.pushKit(ctx, env, log); err != nil {
		return err
	}
	if err = m.bootstrapOffsec(ctx, env, log); err != nil {
		return err
	}
	if _, err = m.root(ctx, vm, "echo "+KitVersion+" >/var/lib/kubelab/ready", nil, log); err != nil {
		return err
	}
	resetSSHMux(vm.Name)
	if err = lima.Stop(ctx, vm.Name, log); err != nil {
		return err
	}
	fmt.Fprintln(log, "==> restarting offsec with host-enforced network isolation")
	if err = lima.StartOffsec(ctx, m.StateDir, false, log); err != nil {
		return err
	}
	if err = m.CheckIsolation(ctx, env); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(in.Dir, offsecProvisioned), []byte("provisioned offline\n"), 0o600); err != nil {
		return err
	}
	m.setClean(env, false)
	m.SetTainted(env, false)
	return nil
}

// CheckIsolation protects shell, check, solve and reset as well as initial setup.
func (m *Manager) CheckIsolation(ctx context.Context, env Env) error {
	if env.Profile != exercise.ProfileOffsec {
		return nil
	}
	all, err := lima.List(ctx)
	if err != nil {
		return err
	}
	return lima.CheckOffsecIsolation(ctx, all[env.Primary().Name])
}
