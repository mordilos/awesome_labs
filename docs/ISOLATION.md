# Security VM isolation

The security VM uses QEMU's restricted user-mode network on Linux and macOS.
The host-side launcher accepts exactly one network backend and one localhost SSH
forward. It rejects additional adapters, guest forwards and file-sharing services.
It disables external IPv6; IPv6 exercises inside guest namespaces still work.
The template disables Lima's host integration features, and the app rejects shared
Lima defaults/overrides rather than assuming that the stored template is effective.

Only the first provisioning boot may use an unrestricted network. No exercise runs
during that boot. Successful provisioning is followed by a stopped VM, a restricted
boot, verification of the live host process, and a marker in the host's instance
directory. A guest-writable readiness marker cannot enable online reprovisioning.
Ordinary errors and cancellation attempt to stop an unfinished provisioning VM;
if the app is forcibly killed or the host crashes, rebuild the unfinished instance.

This does not defend against a compromised host account, hypervisor vulnerabilities,
or a user explicitly starting QEMU/Lima outside this application. Start `kl-offsec`
through awesome_labs. Existing VMs must be rebuilt, which deletes their contents.
The policy applies to both offsec and defensive tracks, which share this VM.

## Automated checks

```bash
go test ./...
```

Tests execute the launcher against a fake QEMU, reject unsafe network arguments and
host-integration settings, and exercise provisioning/restart/failure transitions
through a fake limactl. These tests do not prove live packet filtering.

## Live acceptance checks (Linux and macOS)

Use a disposable lab environment. `verify` resets lab state and may delete other lab
VMs, as documented in the README. Rebuild an existing `kl-offsec` before these checks.

1. Run `awesome_labs env up offsec`. Confirm online provisioning is followed by an
   isolated reboot. Check `limactl list --json` for the driver PID; its host process
   must have one `-netdev user,...,restrict=on,ipv6=off` argument and only the SSH
   host forward. Do not use guest `iptables` output as proof of isolation.
2. Run `awesome_labs verify offsec-web-005` to exercise command injection and SSRF
   against local targets. Both reference solutions must pass while isolated.
3. Start a temporary HTTP server on the workstation bound to `127.0.0.1`, and
   confirm it responds from the workstation. From `awesome_labs shell offsec`,
   attempt the same request as root using `192.168.5.2` and the server's port.
   It must fail. Repeat against a controlled listener on the workstation's LAN
   address, and a controlled external endpoint; verify neither receives traffic.
4. Check UDP DNS requests to `192.168.5.3` and an external resolver: they must not
   leave the VM. Check IPv6 egress separately. Use packet capture on the controlled
   destination where practical; a timeout alone is not sufficient evidence.
5. Inside the VM, start a listener on an otherwise unused port. Confirm it is
   reachable inside the guest but no matching listener appears on host localhost.
6. Stop and restart with `awesome_labs env stop offsec` and `awesome_labs env up offsec`.
   Repeat the network checks. The VM must never provision online again.
7. Interrupt a fresh provisioning run. The VM should stop; a subsequent `env up`
   must require a rebuild instead of silently granting another online boot.

Keep QEMU, Lima and their dependencies patched. The restricted network controls
guest network traffic; it is not a general guarantee against VM escape.

References: [QEMU networking options](https://www.qemu.org/docs/master/system/invocation.html),
[Lima port forwarding](https://lima-vm.io/docs/config/port/).
