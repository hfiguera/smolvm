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

The shim records the original sandbox's Delete request before cleanup. If
cleanup fails, the next sandbox Create retries that cleanup before evaluating
its own admission. A running sandbox holds the slot until its requested
cleanup succeeds.

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
budget. Retain the directory and original lock inode for the life of the
worker. Start with a freshly provisioned worker when renewing the budget.

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
