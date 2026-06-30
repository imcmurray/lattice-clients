//! FRB-bridged surface for the Lattice Node client.
//!
//! Thin wrappers over the `lattice-mobile` facade. Heavy crypto (scrypt KDF, PQ
//! keygen) is pushed onto the runtime's blocking pool so the UI never stalls;
//! async transport work is bridged onto the facade's tokio runtime. Logic and
//! cryptography live below this layer.

use std::future::Future;
use std::sync::Arc;

use flutter_rust_bridge::frb;
use lattice_mobile::{self as lm, runtime, LatticeNode, NodeEvent};

use crate::frb_generated::StreamSink;

/// flutter_rust_bridge initialization hook.
#[frb(init)]
pub fn init_app() {
    flutter_rust_bridge::setup_default_user_utils();
}

/// Await an async future on the node's tokio runtime from FRB's executor.
async fn on_rt<F, T>(fut: F) -> T
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = futures::channel::oneshot::channel();
    runtime().spawn(async move {
        let _ = tx.send(fut.await);
    });
    rx.await.expect("runtime task dropped before completing")
}

/// Run a blocking (CPU-bound) closure on the runtime's blocking pool — for
/// scrypt KDF and PQ keygen, which would otherwise stall FRB's worker.
async fn blocking<F, T>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = futures::channel::oneshot::channel();
    runtime().spawn_blocking(move || {
        let _ = tx.send(f());
    });
    rx.await.expect("blocking task dropped before completing")
}

// ===========================================================================
// Identity (onboarding / unlock)
// ===========================================================================

/// A freshly generated identity — mnemonic shown once, then stored.
pub struct NewIdentity {
    pub mnemonic: String,
    pub peer_id_hex: String,
    pub fingerprint: String,
}

/// Public, non-secret summary of an identity.
pub struct IdentitySummary {
    pub peer_id_hex: String,
    pub fingerprint: String,
}

impl From<lm::NewIdentity> for NewIdentity {
    fn from(n: lm::NewIdentity) -> Self {
        Self {
            mnemonic: n.mnemonic,
            peer_id_hex: n.peer_id_hex,
            fingerprint: n.fingerprint,
        }
    }
}

impl From<lm::IdentitySummary> for IdentitySummary {
    fn from(s: lm::IdentitySummary) -> Self {
        Self {
            peer_id_hex: s.peer_id_hex,
            fingerprint: s.fingerprint,
        }
    }
}

/// Generate a brand-new PQ-hybrid identity (not yet persisted).
pub async fn generate_identity() -> Result<NewIdentity, String> {
    blocking(|| lm::generate_identity().map(NewIdentity::from).map_err(|e| e.to_string())).await
}

/// Validate a mnemonic and preview its identity (recovery / confirmation).
pub async fn summarize_mnemonic(mnemonic: String) -> Result<IdentitySummary, String> {
    blocking(move || {
        lm::summarize_mnemonic(&mnemonic)
            .map(IdentitySummary::from)
            .map_err(|e| e.to_string())
    })
    .await
}

/// Encrypt + persist `mnemonic` under `passphrase` to `<dir>/identity.age`.
pub async fn store_identity(
    dir: String,
    mnemonic: String,
    passphrase: String,
) -> Result<IdentitySummary, String> {
    blocking(move || {
        lm::store_identity(&dir, &mnemonic, &passphrase)
            .map(IdentitySummary::from)
            .map_err(|e| e.to_string())
    })
    .await
}

/// Whether an encrypted identity already exists at `dir`.
#[frb(sync)]
pub fn identity_exists(dir: String) -> bool {
    lm::identity_exists(&dir)
}

// ===========================================================================
// Node
// ===========================================================================

/// Opaque handle to a loaded Lattice node, held by the Dart side.
#[frb(opaque)]
pub struct Node {
    inner: Arc<LatticeNode>,
}

impl Node {
    /// Unlock: decrypt the stored identity in `dir` with `passphrase` and build
    /// a node. Network binds lazily on `startListening`/`connect`.
    pub async fn open(dir: String, passphrase: String) -> Result<Node, String> {
        blocking(move || {
            LatticeNode::load(&dir, &passphrase)
                .map(|inner| Node { inner })
                .map_err(|e| e.to_string())
        })
        .await
    }

    /// This node's stable PeerId, hex-encoded.
    #[frb(sync)]
    pub fn peer_id_hex(&self) -> String {
        self.inner.peer_id_hex()
    }

    /// Short, comparable fingerprint of the PeerId.
    #[frb(sync)]
    pub fn fingerprint(&self) -> String {
        self.inner.fingerprint()
    }

    /// The 24-word backup mnemonic — gate behind biometric + explicit intent.
    #[frb(sync)]
    pub fn mnemonic(&self) -> String {
        self.inner.mnemonic()
    }

    /// The dial ticket for this node (binds the transport if needed). Render as QR.
    pub async fn my_ticket(&self) -> Result<String, String> {
        let inner = Arc::clone(&self.inner);
        on_rt(async move { inner.my_ticket().await.map_err(|e| e.to_string()) }).await
    }

    /// Go online + accept connections; emits a `Listening` event with the ticket.
    #[frb(sync)]
    pub fn start_listening(&self) {
        self.inner.start_listening();
    }

    /// Stop accepting new connections; emits `ListeningStopped`.
    #[frb(sync)]
    pub fn stop_listening(&self) {
        self.inner.stop_listening();
    }

    /// Dial a peer by ticket (runs in the background; watch the event stream).
    #[frb(sync)]
    pub fn connect(&self, ticket: String) {
        self.inner.connect(ticket);
    }

    /// Send a UTF-8 message to a connected peer (by hex PeerId).
    pub async fn send(&self, peer_id_hex: String, body: String) -> Result<(), String> {
        let inner = Arc::clone(&self.inner);
        on_rt(async move { inner.send(peer_id_hex, body).await.map_err(|e| e.to_string()) }).await
    }

    /// Subscribe to the node's event stream. Spawns a forwarder on the runtime
    /// that pushes each event into Dart until the node is torn down.
    #[frb(sync)]
    pub fn events(&self, sink: StreamSink<LatticeEvent>) {
        let inner = Arc::clone(&self.inner);
        runtime().spawn(async move {
            while let Some(ev) = inner.next_event().await {
                if sink.add(LatticeEvent::from(ev)).is_err() {
                    break;
                }
            }
        });
    }
}

/// Dart-facing mirror of [`lattice_mobile::NodeEvent`].
pub enum LatticeEvent {
    Listening { ticket: String },
    ListeningStopped,
    PeerConnected { peer_id_hex: String },
    Resumed { peer_id_hex: String },
    Reconnecting { peer_id_hex: String },
    Message { peer_id_hex: String, body: String },
    PeerDisconnected { peer_id_hex: String },
    Error { message: String },
}

impl From<NodeEvent> for LatticeEvent {
    fn from(e: NodeEvent) -> Self {
        match e {
            NodeEvent::Listening { ticket } => LatticeEvent::Listening { ticket },
            NodeEvent::ListeningStopped => LatticeEvent::ListeningStopped,
            NodeEvent::PeerConnected { peer_id_hex } => LatticeEvent::PeerConnected { peer_id_hex },
            NodeEvent::Resumed { peer_id_hex } => LatticeEvent::Resumed { peer_id_hex },
            NodeEvent::Reconnecting { peer_id_hex } => LatticeEvent::Reconnecting { peer_id_hex },
            NodeEvent::Message { peer_id_hex, body } => LatticeEvent::Message { peer_id_hex, body },
            NodeEvent::PeerDisconnected { peer_id_hex } => {
                LatticeEvent::PeerDisconnected { peer_id_hex }
            }
            NodeEvent::Error { message } => LatticeEvent::Error { message },
        }
    }
}
