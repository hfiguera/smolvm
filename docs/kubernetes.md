# Kubernetes

smolvm ships a **containerd shim v2**, so Kubernetes runs a pod as its own microVM
through a `RuntimeClass`, the same integration point Kata uses. The Linux release
carries the shim and the manifests; there is nothing to build.

On each node that should run microVM pods (requires KVM):

```bash
# 1. install the shim + runtime artifacts, then apply the containerd config it prints
sudo ./kubernetes/install-k8s-runtime.sh
sudo systemctl restart containerd

# 2. label the node so the RuntimeClass will schedule to it
kubectl label node <node> smolvm-runtime=true
```

Then register the class and run a pod:

```bash
kubectl apply -f kubernetes/runtimeclass.yaml
kubectl apply -f kubernetes/example-pod.yaml
kubectl logs smolvm-hello    # prints the guest's own kernel, so it is a real VM
```

Any pod opts in with `runtimeClassName: smolvm`.

## Sandbox attempt limit for a dedicated worker

On a fresh worker with a single SmolVM sandbox slot, an administrator can
configure a lifetime limit on sandbox attempts. Each admitted sandbox ID spends
one attempt before the shim creates any per-ID files. Cleanup can run at the
limit, and spent attempts stay charged after cleanup and across restarts.
Containerd continues to report failed Pod sandbox creation when the limit has
been reached.

The shim records the original sandbox's Delete request before cleanup and
holds an owner lock through Create and while the task is active. Either a
recorded Delete or a released owner lock allows cleanup to resume. Start the
worker timer below so cleanup can make progress while admission is paused.
Create also retries eligible cleanup before evaluating its own admission.
Older pending attempts without recorded runtime storage can use the normal
shim Create or Delete paths. Pending attempts without ownership require a
Delete for the original ID.

To provision a new register, run as the account that runs containerd:

```sh
set -eu
umask 077
budget=/var/lib/smolvm-sandbox-attempt-budget
mkdir -m 0700 "$budget"
: > "$budget/lock"
printf '%s\n' '{"version":1,"limit":2,"admitted":[],"pending":null}' > "$budget/attempts.json"
```

Set `SMOLVM_SANDBOX_ATTEMPT_BUDGET_DIR` to that absolute directory in the
containerd service environment, or in the K3s service when it runs containerd.
All shim processes must inherit the same setting. Use local storage outside
the VM and Pod share roots. The example limit of two is useful for testing.
Choose a limit from 1 to 2,048 based on the worker's storage and inventory
budget. Retain the directory and original lock inodes for the life of the
worker, including `sandbox-owner`, which the shim creates on first admission.
Start with a freshly provisioned worker when renewing the budget.

### Worker reconciliation timer

On a systemd node, put the sandbox budget directory and SmolVM runtime
environment (including any XDG data and cache overrides) in a root-owned
`/etc/smolvm/sandbox-worker.env`. Set
`EnvironmentFile=/etc/smolvm/sandbox-worker.env` in the `[Service]` section of
the containerd or K3s service drop-in. Run the reconciliation service as the
same account. The shim checks the recorded database and VM cache identities
before the reconciliation service can clean up an attempt. Apply the drop-in
when starting the guarded runtime, then enable the timer.

Save as `/etc/systemd/system/smolvm-sandbox-reconcile.service`:

```ini
[Unit]
Description=Reconcile the SmolVM worker's pending sandbox
After=local-fs.target

[Service]
Type=oneshot
EnvironmentFile=/etc/smolvm/sandbox-worker.env
ExecStart=/usr/local/bin/containerd-shim-smolvm-v2 reconcile-sandbox-budget
TimeoutStartSec=2min
```

Save as `/etc/systemd/system/smolvm-sandbox-reconcile.timer`:

```ini
[Unit]
Description=Retry pending SmolVM sandbox cleanup

[Timer]
OnBootSec=10s
OnUnitInactiveSec=10s
AccuracySec=1s

[Install]
WantedBy=timers.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now smolvm-sandbox-reconcile.timer
```

## Shim child-process ownership

The embedded engine waits for foreground helpers such as `cp`, `chmod` and
image-extraction tools through their own `Child` handles. The shim configures
containerd-shim without its process-wide reaper: an independent `waitpid(-1)`
can otherwise consume a helper's exit first and make its real owner report
`ECHILD` (`No child processes`), even after a successful copy.

Detached VM boot processes remain registered with the engine's per-PID reaper.
The shim sweeps that registry in the background, preserving exit status even
when no client performs a liveness query. It does not become a subreaper for
unregistered grandchildren; their supervising ancestor remains responsible.
Guest task exits still use the existing guest event/watch path.

The Linux regression uses the real containerd-shim bootstrap and SIGCHLD loop in
separate fixture processes. It demonstrates the old competing wait and checks
helper results, cancellation signals, copies, detached VM exits and orphan
ownership without requiring KVM or a containerd daemon:

```bash
cargo test --locked -p smolvm-shim
```
