//! Shim v2 process lifecycle: what containerd invokes to start/stop the shim
//! itself. One shim process serves one pod (grouped by task id).

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use containerd_shim::asynchronous::{run, spawn, ExitSignal, Shim};
use containerd_shim::publisher::RemotePublisher;
use containerd_shim::util::timestamp;
use containerd_shim::{Config, Error, Flags, StartOpts};
use containerd_shim_protos::api::DeleteResponse;
use log::warn;

use crate::attempt_budget::DIRECTORY_ENV;
use crate::backend::MockBackend;
use crate::engine::{cleanup_sandbox, EnginePodBackend, ShimBackend};
use crate::task::TaskService;

pub const RUNTIME_ID: &str = "io.containerd.smolvm.v2";

pub struct Service {
    exit: Arc<ExitSignal>,
    backend: OnceLock<Arc<ShimBackend>>,
    namespace: String,
    /// Task id containerd invoked us with. For the sandbox shim this is the
    /// sandbox id, which is also the persistent machine's name — used by
    /// `delete_shim` to reap a leaked VM after a shim crash.
    id: String,
}

#[async_trait]
impl Shim for Service {
    // Engine-backed by default (real microVMs); SMOLVM_SHIM_MOCK=1 keeps the
    // in-process mock so tests/smoke runs work on hosts without KVM.
    type T = TaskService<ShimBackend>;

    async fn new(_runtime_id: &str, args: &Flags, _config: &mut Config) -> Self {
        Service {
            exit: Arc::new(ExitSignal::default()),
            backend: OnceLock::new(),
            namespace: args.namespace.clone(),
            id: args.id.clone(),
        }
    }

    async fn start_shim(&mut self, opts: StartOpts) -> Result<String, Error> {
        // Group a container task under its sandbox's shim (via the CRI
        // `io.kubernetes.cri.sandbox-id` annotation) so the container reaches the
        // shim process that owns the pod VM. Without this, containerd 2.2+ starts
        // a fresh shim per container — which has no sandbox in its state, so the
        // container task fails with "no sandbox created for this pod". The shim's
        // `start` action runs with the bundle directory as its CWD.
        let grouping = crate::bundle::sandbox_grouping(".").unwrap_or_else(|| opts.id.clone());
        let address = spawn(opts, &grouping, Vec::new()).await?;
        Ok(address)
    }

    async fn delete_shim(&mut self) -> Result<DeleteResponse, Error> {
        // Containerd invokes the shim binary's `delete` action after disconnect.
        // A live guarded owner handles the saved request in wait(); after its
        // exit, a fresh process can still find and clean up the persisted VM.
        // Best-effort — a missing machine (a container-task delete, or a VM
        // already cleaned by the graceful path) is not an error.
        let id = self.id.clone();
        let reaped = tokio::task::spawn_blocking(move || cleanup_sandbox(&id, false))
            .await
            .map_err(|error| error.to_string())
            .and_then(|result| result);
        if let Err(error) = reaped {
            if std::env::var_os(DIRECTORY_ENV).is_some() {
                return Err(Error::Other(error));
            }
            warn!("delete_shim: reaping {} failed: {error}", self.id);
        }
        Ok(DeleteResponse {
            exit_status: 137,
            exited_at: Some(timestamp()?).into(),
            ..Default::default()
        })
    }

    async fn wait(&mut self) {
        if let (true, Some(ShimBackend::Engine(backend))) = (
            std::env::var_os(DIRECTORY_ENV).is_some(),
            self.backend.get().map(Arc::as_ref),
        ) {
            tokio::select! {
                _ = self.exit.wait() => {},
                _ = backend.wait_for_cleanup_request() => {},
            }
        } else {
            self.exit.wait().await;
        }
    }

    async fn create_task_service(&self, publisher: RemotePublisher) -> Self::T {
        let backend = self.backend.get_or_init(|| {
            Arc::new(if std::env::var("SMOLVM_SHIM_MOCK").as_deref() == Ok("1") {
                warn!("SMOLVM_SHIM_MOCK=1: using mock backend (no VMs will boot)");
                ShimBackend::Mock(MockBackend::default())
            } else {
                ShimBackend::Engine(EnginePodBackend::new())
            })
        });
        TaskService::new(
            backend.clone(),
            Some(Arc::new(publisher)),
            self.namespace.clone(),
            self.exit.clone(),
        )
    }
}

pub fn run_shim() {
    let body = async {
        let _reaper = crate::reaper::VmReaper::start();
        run::<Service>(RUNTIME_ID, Some(crate::reaper::configuration())).await;
    };
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(body);
}
