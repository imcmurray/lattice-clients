//! `lattice-mobile` — an FFI-safe facade over the Lattice P2P framework.
//!
//! Two concerns, deliberately separated:
//!
//! * **Identity at rest** — free functions that generate / recover an identity
//!   and encrypt the BIP39 mnemonic under a passphrase (age scrypt) to
//!   `<dir>/identity.age`. Pure crypto + disk: no network, no async. The
//!   passphrase itself is held by the platform keystore on the Dart side.
//! * **The live node** — [`LatticeNode`] owns the tokio runtime, the iroh
//!   transport (bound lazily), and the live peer sessions, and emits a
//!   [`NodeEvent`] stream. Transport binding is decoupled from identity load so
//!   the UI can show the PeerId instantly and go online only when asked.
//!
//! All cryptography and transport live in the audited Lattice crates; this is
//! glue only. The wire preamble matches the `lattice-net` reference CLI.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use lattice::prelude::*;
use lattice::transport::{read_frame, write_frame, IrohConn, IrohTransport};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::AbortHandle;
use zeroize::Zeroizing;

/// 32-byte PeerId, used as the session map key.
type PeerKey = [u8; 32];

// Connection preamble (matches lattice-net): the dialer's first frame is
// [mode] ++ its identity bundle; the listener replies with one decision byte.
const MODE_FRESH: u8 = 0;
const MODE_RESUME: u8 = 1;
const DECISION_FRESH: u8 = 0;
const DECISION_RESUMED: u8 = 1;
const IDENTITY_FILE: &str = "identity.age";

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// The shared multi-thread tokio runtime that drives all node I/O. Owning our
/// own runtime keeps this facade independent of the FFI layer's executor.
pub fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime")
    })
}

// ===========================================================================
// Identity at rest (offline)
// ===========================================================================

/// A freshly generated identity, not yet persisted. The mnemonic is the only
/// way to recover it — show it once, confirm it, then [`store_identity`].
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

/// Generate a brand-new PQ-hybrid identity. Pure crypto: no network, no disk.
pub fn generate_identity() -> Result<NewIdentity> {
    let kp = Keypair::generate(CryptoSuite::Hybrid)?;
    Ok(NewIdentity {
        mnemonic: kp.mnemonic().to_string(),
        peer_id_hex: peer_hex(&kp),
        fingerprint: fingerprint(&kp),
    })
}

/// Validate a mnemonic and derive its identity summary (recovery preview /
/// onboarding confirmation). Errors if the phrase isn't a valid identity.
pub fn summarize_mnemonic(mnemonic: &str) -> Result<IdentitySummary> {
    let kp = Keypair::from_mnemonic(CryptoSuite::Hybrid, mnemonic)?;
    Ok(IdentitySummary {
        peer_id_hex: peer_hex(&kp),
        fingerprint: fingerprint(&kp),
    })
}

/// Encrypt `mnemonic` under `passphrase` (age scrypt) to `<dir>/identity.age`,
/// `0600`. Validates the mnemonic first so we never persist garbage. Returns
/// the resulting identity summary.
pub fn store_identity(dir: &str, mnemonic: &str, passphrase: &str) -> Result<IdentitySummary> {
    let summary = summarize_mnemonic(mnemonic)?;
    std::fs::create_dir_all(dir).map_err(|e| Error::Other(format!("create dir: {e}")))?;
    let recipient = age::scrypt::Recipient::new(secret(passphrase));
    let ct = age::encrypt(&recipient, mnemonic.as_bytes())
        .map_err(|e| Error::Crypto(format!("age encrypt: {e}")))?;
    write_file_0600(&identity_path(dir), &ct)?;
    Ok(summary)
}

/// Whether an encrypted identity already exists at `dir`.
pub fn identity_exists(dir: &str) -> bool {
    identity_path(dir).exists()
}

fn identity_path(dir: &str) -> PathBuf {
    Path::new(dir).join(IDENTITY_FILE)
}

fn load_mnemonic(dir: &str, passphrase: &str) -> Result<Zeroizing<String>> {
    let ct = std::fs::read(identity_path(dir))
        .map_err(|e| Error::Other(format!("read identity: {e}")))?;
    let identity = age::scrypt::Identity::new(secret(passphrase));
    let pt = age::decrypt(&identity, &ct)
        .map_err(|e| Error::Crypto(format!("decrypt failed (wrong passphrase?): {e}")))?;
    String::from_utf8(pt)
        .map(Zeroizing::new)
        .map_err(|_| Error::Crypto("stored identity is not valid UTF-8".into()))
}

fn secret(p: &str) -> age::secrecy::SecretString {
    age::secrecy::SecretString::from(p.to_owned())
}

fn peer_hex(kp: &Keypair) -> String {
    hex::encode(kp.peer_id().0)
}

/// A short, human-comparable fingerprint: first 4 and last 4 bytes of the PeerId.
fn fingerprint(kp: &Keypair) -> String {
    let id = kp.peer_id().0;
    format!("{}…{}", hex::encode(&id[..4]), hex::encode(&id[28..]))
}

fn write_file_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| Error::Other(format!("create identity file: {e}")))?;
        f.write_all(bytes)
            .map_err(|e| Error::Other(format!("write identity file: {e}")))
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes).map_err(|e| Error::Other(format!("write identity file: {e}")))
    }
}

// ===========================================================================
// Live node (transport + sessions)
// ===========================================================================

/// Everything the UI observes from the node, as a single event stream.
#[derive(Clone, Debug)]
pub enum NodeEvent {
    /// Now accepting connections; `ticket` is the blob a peer dials (render as QR).
    Listening { ticket: String },
    /// The accept loop was stopped (listen toggle off).
    ListeningStopped,
    /// A secure session was established with a peer (fresh handshake).
    PeerConnected { peer_id_hex: String },
    /// A dropped session was resumed without re-handshaking (ratchet preserved).
    Resumed { peer_id_hex: String },
    /// The dialer lost a peer and is retrying (with resume on success).
    Reconnecting { peer_id_hex: String },
    /// Live link health for a peer: whether the selected path is direct (vs
    /// relayed) and its round-trip time in ms (once measured).
    Link {
        peer_id_hex: String,
        direct: bool,
        rtt_ms: Option<u32>,
    },
    /// A decrypted application message arrived.
    Message { peer_id_hex: String, body: String },
    /// A peer's session ended (transport drop or local teardown).
    PeerDisconnected { peer_id_hex: String },
    /// A non-fatal error worth surfacing in the diagnostics console.
    Error { message: String },
}

/// A loaded Lattice node. Build with [`LatticeNode::load`], subscribe via
/// [`next_event`](Self::next_event), then drive [`start_listening`](Self::start_listening)
/// / [`connect`](Self::connect). The transport binds lazily on first use.
pub struct LatticeNode {
    me: Arc<Keypair>,
    transport: Arc<Mutex<Option<Arc<IrohTransport>>>>,
    peers: Arc<Mutex<HashMap<PeerKey, mpsc::UnboundedSender<Vec<u8>>>>>,
    listen_task: Arc<Mutex<Option<AbortHandle>>>,
    /// The single active outbound dial loop (replaced on each `connect`).
    dial_task: Arc<Mutex<Option<AbortHandle>>>,
    /// Ratchet sessions kept across drops so a reconnecting peer can resume
    /// without a fresh handshake (the listener side of resumption).
    kept: Arc<Mutex<HashMap<PeerKey, SecureSession>>>,
    events_tx: mpsc::UnboundedSender<NodeEvent>,
    events_rx: Mutex<Option<mpsc::UnboundedReceiver<NodeEvent>>>,
}

impl LatticeNode {
    /// Decrypt the stored identity at `dir` with `passphrase` and build a node.
    /// No network yet — the transport binds on first `start_listening`/`connect`.
    pub fn load(dir: &str, passphrase: &str) -> Result<Arc<Self>> {
        let mnemonic = load_mnemonic(dir, passphrase)?;
        let me = Keypair::from_mnemonic(CryptoSuite::Hybrid, &mnemonic)?;
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        Ok(Arc::new(Self {
            me: Arc::new(me),
            transport: Arc::new(Mutex::new(None)),
            peers: Arc::new(Mutex::new(HashMap::new())),
            listen_task: Arc::new(Mutex::new(None)),
            dial_task: Arc::new(Mutex::new(None)),
            kept: Arc::new(Mutex::new(HashMap::new())),
            events_tx,
            events_rx: Mutex::new(Some(events_rx)),
        }))
    }

    /// This node's stable PeerId, hex-encoded.
    pub fn peer_id_hex(&self) -> String {
        peer_hex(&self.me)
    }

    /// Short, comparable fingerprint of the PeerId.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.me)
    }

    /// The 24-word BIP39 backup mnemonic. Gate behind biometric + explicit intent.
    pub fn mnemonic(&self) -> String {
        self.me.mnemonic().to_string()
    }

    /// Pull the next event (drives the Dart-side stream). `None` once torn down.
    pub async fn next_event(&self) -> Option<NodeEvent> {
        let mut guard = self.events_rx.lock().await;
        match guard.as_mut() {
            Some(rx) => rx.recv().await,
            None => None,
        }
    }

    /// Bind the iroh transport if not already online; returns the shared handle.
    async fn ensure_online(&self) -> Result<Arc<IrohTransport>> {
        let mut g = self.transport.lock().await;
        if let Some(t) = g.as_ref() {
            return Ok(Arc::clone(t));
        }
        let t = Arc::new(IrohTransport::bind().await?);
        *g = Some(Arc::clone(&t));
        Ok(t)
    }

    /// The dial ticket for this node (binds the transport if needed). Compact:
    /// it carries only the iroh address + this node's 32-byte PeerId, not the
    /// full PQ public-key bundle — small enough for a QR. The dialer fetches the
    /// keys over the wire and verifies they hash to this PeerId.
    pub async fn my_ticket(&self) -> Result<String> {
        let t = self.ensure_online().await?;
        t.ticket(&self.me.peer_id().0).await
    }

    /// Go online and start accepting inbound connections. Emits `Listening`
    /// with the ticket, then runs an abortable accept loop.
    pub fn start_listening(self: &Arc<Self>) {
        let node = Arc::clone(self);
        runtime().spawn(async move {
            let t = match node.ensure_online().await {
                Ok(t) => t,
                Err(e) => return node.emit_err(format!("go online: {e}")),
            };
            match t.ticket(&node.me.peer_id().0).await {
                Ok(ticket) => {
                    let _ = node.events_tx.send(NodeEvent::Listening { ticket });
                }
                Err(e) => return node.emit_err(format!("ticket: {e}")),
            }

            // Replace any prior accept loop.
            if let Some(h) = node.listen_task.lock().await.take() {
                h.abort();
            }
            let n2 = Arc::clone(&node);
            let handle = runtime().spawn(async move {
                loop {
                    match t.accept_conn().await {
                        Ok(conn) => {
                            let n3 = Arc::clone(&n2);
                            runtime().spawn(async move { n3.handle_incoming(conn).await });
                        }
                        Err(e) => {
                            let _ = n2
                                .events_tx
                                .send(NodeEvent::Error { message: format!("accept: {e}") });
                        }
                    }
                }
            });
            *node.listen_task.lock().await = Some(handle.abort_handle());
        });
    }

    /// Stop accepting new connections (existing sessions stay up). Emits
    /// `ListeningStopped`.
    pub fn stop_listening(self: &Arc<Self>) {
        let node = Arc::clone(self);
        runtime().spawn(async move {
            if let Some(h) = node.listen_task.lock().await.take() {
                h.abort();
            }
            let _ = node.events_tx.send(NodeEvent::ListeningStopped);
        });
    }

    /// Dial a peer by ticket and keep the session alive across drops: on a
    /// disconnect it re-dials with resume (falling back to a fresh handshake if
    /// the peer can't resume), with exponential backoff while unreachable.
    pub fn connect(self: &Arc<Self>, ticket: String) {
        let node = Arc::clone(self);
        runtime().spawn(async move {
            // Replace any existing dial loop so repeated taps don't stack
            // reconnect loops (which would race + spam transport timeouts).
            if let Some(h) = node.dial_task.lock().await.take() {
                h.abort();
            }
            let runner = Arc::clone(&node);
            let handle = runtime().spawn(async move { runner.dial_loop(ticket).await });
            *node.dial_task.lock().await = Some(handle.abort_handle());
        });
    }

    /// Send a UTF-8 message to a connected peer (by hex PeerId).
    pub async fn send(&self, peer_id_hex: String, body: String) -> Result<()> {
        let key = decode_peer_key(&peer_id_hex)?;
        let tx = self.peers.lock().await.get(&key).cloned();
        match tx {
            Some(tx) => tx
                .send(body.into_bytes())
                .map_err(|_| Error::Other("peer session closed".into())),
            None => Err(Error::Other("no live session with that peer".into())),
        }
    }

    // --- internals ---------------------------------------------------------

    /// Responder: read the dialer's preamble, resume a kept session if asked and
    /// available, else run a fresh handshake. Keeps the recovered session for a
    /// future resume.
    async fn handle_incoming(self: Arc<Self>, mut conn: IrohConn) {
        // Compact-ticket protocol: send our full identity first so the dialer
        // can verify it against the PeerId in the ticket and use it for the KEM.
        if conn.send(&self.me.public().to_bytes()).await.is_err() {
            return;
        }
        let preamble = match conn.recv().await {
            Ok(p) => p,
            Err(e) => return self.emit_err(format!("preamble: {e}")),
        };
        if preamble.is_empty() {
            return self.emit_err("empty preamble".into());
        }
        let mode = preamble[0];
        let peer = match PublicIdentity::from_bytes(&preamble[1..]) {
            Ok(p) => p,
            Err(e) => return self.emit_err(format!("bad peer identity: {e}")),
        };
        let key = peer.peer_id().0;
        let hex = hex::encode(key);

        let resumable = if mode == MODE_RESUME {
            self.kept.lock().await.remove(&key)
        } else {
            self.kept.lock().await.remove(&key); // drop any stale session
            None
        };

        let cs = if let Some(sess) = resumable {
            if conn.send(&[DECISION_RESUMED]).await.is_err() {
                return;
            }
            let _ = self.events_tx.send(NodeEvent::Resumed { peer_id_hex: hex });
            ConnectedSession::resume(conn, sess)
        } else {
            if conn.send(&[DECISION_FRESH]).await.is_err() {
                return;
            }
            match ConnectedSession::accept(conn, self.me.as_ref(), &peer).await {
                Ok(cs) => cs,
                Err(e) => return self.emit_err(format!("handshake: {e}")),
            }
        };

        if let Some(recovered) = self.run_session(peer, cs).await {
            self.kept.lock().await.insert(key, recovered);
        }
    }

    /// Dialer reconnect loop for one ticket. Returns never (runs until the node
    /// is dropped); each iteration dials, runs the session, then re-dials.
    async fn dial_loop(self: Arc<Self>, ticket: String) {
        let mut kept: Option<SecureSession> = None;
        let mut backoff = 1u64;
        loop {
            match self.dial_once(&ticket, &mut kept).await {
                Ok(peer_hex) => {
                    backoff = 1;
                    let _ = self
                        .events_tx
                        .send(NodeEvent::Reconnecting { peer_id_hex: peer_hex });
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
                Err(e) => {
                    self.emit_err(format!("connect: {e} — retrying in {backoff}s"));
                    tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(30);
                }
            }
        }
    }

    /// One dial: negotiate resume-vs-fresh, run the session, stash the recovered
    /// ratchet into `kept` for the next attempt. Returns the peer's hex id.
    async fn dial_once(&self, ticket: &str, kept: &mut Option<SecureSession>) -> Result<String> {
        let t = self.ensure_online().await?;
        // The ticket carries the peer's 32-byte PeerId (the trust anchor).
        let (expected_peer_id, mut conn) = t.connect_ticket(ticket).await?;
        // The peer sends its full identity first; verify it hashes to the PeerId
        // from the ticket before trusting it (TOFU on the fingerprint).
        let identity_bytes = conn.recv().await?;
        let peer = PublicIdentity::from_bytes(&identity_bytes)?;
        if peer.peer_id().0.as_slice() != expected_peer_id.as_slice() {
            return Err(Error::Verify(
                "peer identity does not match the ticket fingerprint".into(),
            ));
        }
        let hex = hex::encode(peer.peer_id().0);

        let mode = if kept.is_some() { MODE_RESUME } else { MODE_FRESH };
        let mut preamble = vec![mode];
        preamble.extend_from_slice(&self.me.public().to_bytes());
        conn.send(&preamble).await?;
        let decision = conn.recv().await?;
        let resumed = decision.first() == Some(&DECISION_RESUMED);

        let cs = if resumed {
            let sess = kept
                .take()
                .ok_or_else(|| Error::Other("resume decision without a kept session".into()))?;
            let _ = self
                .events_tx
                .send(NodeEvent::Resumed { peer_id_hex: hex.clone() });
            ConnectedSession::resume(conn, sess)
        } else {
            let _ = kept.take(); // peer couldn't resume — drop stale, go fresh
            ConnectedSession::initiate(conn, self.me.as_ref(), &peer).await?
        };

        *kept = self.run_session(peer, cs).await;
        Ok(hex)
    }

    /// Full-duplex pump over one session: a reader task decrypts inbound frames
    /// into events while this task encrypts outbound messages from the peer's
    /// channel. The ratchet is shared behind a brief-hold mutex.
    /// Returns the recovered [`SecureSession`] (if the ratchet survived the drop
    /// intact) so the caller can resume it on the next connection.
    async fn run_session(
        &self,
        peer: PublicIdentity,
        cs: ConnectedSession<IrohConn>,
    ) -> Option<SecureSession> {
        let key = peer.peer_id().0;
        let hex = hex::encode(key);

        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        self.peers.lock().await.insert(key, out_tx);
        let _ = self
            .events_tx
            .send(NodeEvent::PeerConnected { peer_id_hex: hex.clone() });

        let (conn, secure) = cs.into_parts();
        let link_handle = conn.handle();
        let (mut send, mut recv) = conn.into_split();
        let secure = Arc::new(Mutex::new(secure));

        // Poll link health (direct-vs-relay + RTT) into the event stream.
        let poller = {
            let events_tx = self.events_tx.clone();
            let hex = hex.clone();
            runtime().spawn(async move {
                loop {
                    let info = link_handle.link();
                    let _ = events_tx.send(NodeEvent::Link {
                        peer_id_hex: hex.clone(),
                        direct: info.direct,
                        rtt_ms: info.rtt_ms.map(|v| v as u32),
                    });
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            })
        };

        let lost = Arc::new(Notify::new());
        let reader = {
            let secure = Arc::clone(&secure);
            let lost = Arc::clone(&lost);
            let events_tx = self.events_tx.clone();
            let hex = hex.clone();
            runtime().spawn(async move {
                while let Ok(frame) = read_frame(&mut recv).await {
                    match secure.lock().await.open(&frame) {
                        Ok(pt) => {
                            let _ = events_tx.send(NodeEvent::Message {
                                peer_id_hex: hex.clone(),
                                body: String::from_utf8_lossy(&pt).into_owned(),
                            });
                        }
                        Err(e) => {
                            let _ = events_tx
                                .send(NodeEvent::Error { message: format!("decrypt: {e}") });
                            break;
                        }
                    }
                }
                lost.notify_one();
            })
        };

        loop {
            tokio::select! {
                maybe = out_rx.recv() => match maybe {
                    Some(bytes) => {
                        let frame = match secure.lock().await.seal(&bytes) {
                            Ok(f) => f,
                            Err(e) => { self.emit_err(format!("encrypt: {e}")); break; }
                        };
                        if write_frame(&mut send, &frame).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
                _ = lost.notified() => break,
            }
        }

        reader.abort();
        poller.abort();
        let _ = reader.await;
        let _ = poller.await;
        self.peers.lock().await.remove(&key);
        let _ = self
            .events_tx
            .send(NodeEvent::PeerDisconnected { peer_id_hex: hex });
        // Reclaim sole ownership of the ratchet so a reconnect can resume it.
        Arc::try_unwrap(secure).ok().map(|m| m.into_inner())
    }

    fn emit_err(&self, message: String) {
        let _ = self.events_tx.send(NodeEvent::Error { message });
    }
}

fn decode_peer_key(peer_id_hex: &str) -> Result<PeerKey> {
    let bytes =
        hex::decode(peer_id_hex).map_err(|e| Error::Other(format!("bad peer id hex: {e}")))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Other("peer id must be 32 bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> String {
        std::env::temp_dir()
            .join(format!("lattice-m2-{tag}-{}", std::process::id()))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn identity_generate_store_load_roundtrip() {
        let dir = tmp_dir("roundtrip");
        let _ = std::fs::remove_dir_all(&dir);
        let pass = "correct horse battery staple";

        assert!(!identity_exists(&dir), "nothing stored yet");

        let generated = generate_identity().expect("generate");
        let stored = store_identity(&dir, &generated.mnemonic, pass).expect("store");
        assert_eq!(generated.peer_id_hex, stored.peer_id_hex);
        assert!(identity_exists(&dir), "identity.age written");

        // Load decrypts the same identity (the M2 priority round-trip).
        let node = LatticeNode::load(&dir, pass).expect("load");
        assert_eq!(node.peer_id_hex(), generated.peer_id_hex);
        assert_eq!(node.fingerprint(), generated.fingerprint);

        // A wrong passphrase must not decrypt.
        assert!(LatticeNode::load(&dir, "wrong passphrase").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recover_summary_matches_generated() {
        let generated = generate_identity().expect("generate");
        let summary = summarize_mnemonic(&generated.mnemonic).expect("summarize");
        assert_eq!(summary.peer_id_hex, generated.peer_id_hex);
        assert_eq!(summary.fingerprint, generated.fingerprint);
        assert!(summarize_mnemonic("not a valid mnemonic phrase").is_err());
    }

    #[test]
    fn decode_peer_key_accepts_32_bytes_rejects_junk() {
        let good = "ab".repeat(32); // 64 hex chars = 32 bytes
        assert!(decode_peer_key(&good).is_ok());
        assert!(decode_peer_key("zz").is_err()); // not hex
        assert!(decode_peer_key("abcd").is_err()); // wrong length
        assert!(decode_peer_key("").is_err());
    }
}
