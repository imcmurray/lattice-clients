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
//! glue only. The wire preamble matches the `lattice-net` reference CLI:
//!
//! * dialer → listener: `[mode] || dialer_nonce[32] || identity`
//!   (`mode` 0 = fresh with an all-zero nonce, 1 = resume with a random nonce)
//! * listener → dialer, fresh: `[0] || identity`, then the signed v2 handshake
//! * listener → dialer, resume: `[2] || listener_nonce[32] || listener_tag[32]
//!   || identity` (a challenge), answered by the dialer with one frame holding
//!   its 32-byte tag. Both tags are session-bound HMACs from `lattice-session`;
//!   the kept session is only consumed once the dialer's tag verifies.
//!
//! The retired decision byte 1 (unauthenticated resume) is rejected.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use lattice::prelude::*;
use lattice::session::{resume_nonce, ResumeRole};
use lattice::transport::{read_frame, write_frame, IrohConn, IrohTransport};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::AbortHandle;
use zeroize::Zeroizing;

/// 32-byte PeerId, used as the session map key.
type PeerKey = [u8; 32];

// Connection preamble (matches lattice-net); see the module docs.
const MODE_FRESH: u8 = 0;
const MODE_RESUME: u8 = 1;
const DECISION_FRESH: u8 = 0;
/// Retired: the old unauthenticated resume. A dialer that receives it errors.
const DECISION_RESUMED: u8 = 1;
const DECISION_CHALLENGE: u8 = 2;
const NONCE_LEN: usize = 32;
const TAG_LEN: usize = 32;
const MIN_PREAMBLE_LEN: usize = 1 + NONCE_LEN;
const RESUME_TAG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// Core `read_frame` cap.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
/// Max outgoing plaintext (UTF-8 bytes) per message: 60 KiB, a 4 KiB margin for
/// `SecureSession` framing overhead.
pub const MAX_MESSAGE_BYTES: usize = 60 * 1024;
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
    validate_passphrase(passphrase)?;
    let summary = summarize_mnemonic(mnemonic)?;
    std::fs::create_dir_all(dir).map_err(|e| Error::Other(format!("create dir: {e}")))?;
    let recipient = age::scrypt::Recipient::new(secret(passphrase));
    let ct = age::encrypt(&recipient, mnemonic.as_bytes())
        .map_err(|e| Error::Crypto(format!("age encrypt: {e}")))?;
    write_file_0600(&identity_path(dir), &ct)?;
    Ok(summary)
}

/// Reject empty or whitespace-only passphrases (any Unicode whitespace).
pub(crate) fn validate_passphrase(passphrase: &str) -> Result<()> {
    if passphrase.trim().is_empty() {
        return Err(Error::Other("passphrase must not be empty".into()));
    }
    Ok(())
}

/// Reject outgoing messages larger than [`MAX_MESSAGE_BYTES`] (UTF-8 bytes).
pub fn check_message_size(len: usize) -> Result<()> {
    if len > MAX_MESSAGE_BYTES {
        return Err(Error::Other(format!(
            "message too large: {len} bytes (max {MAX_MESSAGE_BYTES} bytes)"
        )));
    }
    Ok(())
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
    /// The peer failed authentication: an unsigned or forged handshake, a bad
    /// resume proof, or an identity that doesn't match the ticket.
    AuthFailed { peer_id_hex: String, message: String },
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
        validate_passphrase(passphrase)?;
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
        check_message_size(body.len())?;
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
    async fn handle_incoming(self: Arc<Self>, conn: IrohConn) {
        // The dialer sends its preamble first — that's what completes accept_bi
        // on our side (a QUIC bi-stream is only observed once the client sends).
        let mut claimed: Option<PeerKey> = None;
        let (peer, resumed, cs) =
            match listener_establish(conn, self.me.as_ref(), &self.kept, &mut claimed).await {
                Ok(x) => x,
                Err(e) => {
                    return match claimed {
                        Some(k) => self.report_failure(hex::encode(k), "handshake", e),
                        None => self.report_failure(String::new(), "preamble", e),
                    };
                }
            };
        let key = peer.peer_id().0;
        if resumed {
            let _ = self
                .events_tx
                .send(NodeEvent::Resumed { peer_id_hex: hex::encode(key) });
        }

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
                // Auth failures were already surfaced as `AuthFailed`.
                Err(Error::Verify(_)) => {
                    tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(30);
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
        let mut ticket_id: Option<Vec<u8>> = None;
        match self.dial_inner(ticket, kept, &mut ticket_id).await {
            Err(Error::Verify(msg)) => {
                // Surface auth failures distinctly; the dial loop retries quietly.
                let peer_id_hex = ticket_id.map(hex::encode).unwrap_or_default();
                let _ = self.events_tx.send(NodeEvent::AuthFailed {
                    peer_id_hex,
                    message: msg.clone(),
                });
                Err(Error::Verify(msg))
            }
            other => other,
        }
    }

    async fn dial_inner(
        &self,
        ticket: &str,
        kept: &mut Option<SecureSession>,
        ticket_id: &mut Option<Vec<u8>>,
    ) -> Result<String> {
        let t = self.ensure_online().await?;
        // The ticket carries the peer's 32-byte PeerId (the trust anchor).
        let (expected_peer_id, conn) = t.connect_ticket(ticket).await?;
        *ticket_id = Some(expected_peer_id.to_vec());

        // dialer_negotiate sends our preamble FIRST to open the QUIC bi-stream
        // (the listener's accept only completes once the client sends), then
        // verifies the listener's decision against the ticket PeerId.
        let (peer, resumed, cs) =
            dialer_establish(conn, self.me.as_ref(), expected_peer_id.as_slice(), kept).await?;
        let hex = hex::encode(peer.peer_id().0);
        if resumed {
            let _ = self
                .events_tx
                .send(NodeEvent::Resumed { peer_id_hex: hex.clone() });
        }

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

    /// Surface a failed inbound connection: `Error::Verify` becomes the distinct
    /// `AuthFailed` event, anything else keeps the generic `Error` text.
    fn report_failure(&self, peer_id_hex: String, what: &str, e: Error) {
        match e {
            Error::Verify(message) => {
                let _ = self
                    .events_tx
                    .send(NodeEvent::AuthFailed { peer_id_hex, message });
            }
            e => self.emit_err(format!("{what}: {e}")),
        }
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

// ===========================================================================
// Connection preamble, resume challenge, establish (generic over FrameIo)
// ===========================================================================

/// Frame-level duplex used by the preamble/challenge code. Implemented for
/// [`IrohConn`] and, in tests, for an in-memory adapter.
pub(crate) trait FrameIo: Send {
    fn send_frame(&mut self, bytes: &[u8]) -> impl Future<Output = Result<()>> + Send;
    fn recv_frame(&mut self) -> impl Future<Output = Result<Vec<u8>>> + Send;
}

impl FrameIo for IrohConn {
    fn send_frame(&mut self, bytes: &[u8]) -> impl Future<Output = Result<()>> + Send {
        async move { self.send(bytes).await }
    }
    fn recv_frame(&mut self) -> impl Future<Output = Result<Vec<u8>>> + Send {
        async move { self.recv().await }
    }
}

/// Parsed dialer preamble: `[mode] || dialer_nonce[32] || identity`.
pub(crate) struct Preamble {
    pub mode: u8,
    pub nonce: [u8; 32],
    pub peer: PublicIdentity,
}

pub(crate) fn encode_preamble(mode: u8, nonce: &[u8; 32], me: &PublicIdentity) -> Vec<u8> {
    let mut v = Vec::with_capacity(MIN_PREAMBLE_LEN + 64);
    v.push(mode);
    v.extend_from_slice(nonce);
    v.extend_from_slice(&me.to_bytes());
    v
}

pub(crate) fn parse_preamble(bytes: &[u8]) -> Result<Preamble> {
    if bytes.len() < MIN_PREAMBLE_LEN {
        return Err(Error::Other("short preamble".into()));
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&bytes[1..MIN_PREAMBLE_LEN]);
    let peer = PublicIdentity::from_bytes(&bytes[MIN_PREAMBLE_LEN..])
        .map_err(|e| Error::Other(format!("bad peer identity: {e}")))?;
    Ok(Preamble { mode: bytes[0], nonce, peer })
}

pub(crate) enum ListenerOutcome {
    /// Run a fresh `ConnectedSession::accept`. Nothing has been removed from `kept`.
    Fresh { peer: PublicIdentity },
    /// Proof verified. The session has already been removed from `kept`.
    Resume { peer: PublicIdentity, session: SecureSession },
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn listener_negotiate<C: FrameIo>(
    io: &mut C,
    me: &Keypair,
    kept: &Mutex<HashMap<PeerKey, SecureSession>>,
) -> Result<ListenerOutcome> {
    listener_negotiate_claimed(io, me, kept, &mut None).await
}

/// As [`listener_negotiate`], also reporting the PeerId the dialer claimed (once
/// its preamble parsed) so callers can attribute failures.
async fn listener_negotiate_claimed<C: FrameIo>(
    io: &mut C,
    me: &Keypair,
    kept: &Mutex<HashMap<PeerKey, SecureSession>>,
    claimed: &mut Option<PeerKey>,
) -> Result<ListenerOutcome> {
    let bytes = io.recv_frame().await?;
    let pre = parse_preamble(&bytes)?;
    let key = pre.peer.peer_id().0;
    *claimed = Some(key);
    let my_pub = me.public();

    if pre.mode == MODE_RESUME {
        let listener_nonce = resume_nonce()?;
        // Short lock: compute our tag, never hold it across network I/O.
        let listener_tag = {
            let g = kept.lock().await;
            g.get(&key).map(|s| {
                s.resume_tag(
                    ResumeRole::Listener,
                    &pre.peer,
                    &my_pub,
                    &pre.nonce,
                    &listener_nonce,
                )
            })
        };
        if let Some(listener_tag) = listener_tag {
            let mut reply = Vec::with_capacity(1 + NONCE_LEN + TAG_LEN + 64);
            reply.push(DECISION_CHALLENGE);
            reply.extend_from_slice(&listener_nonce);
            reply.extend_from_slice(&listener_tag);
            reply.extend_from_slice(&me.public().to_bytes());
            io.send_frame(&reply).await?;

            let tag = tokio::time::timeout(RESUME_TAG_TIMEOUT, io.recv_frame())
                .await
                .map_err(|_| Error::Other("timed out waiting for resume proof".into()))??;
            if tag.len() != TAG_LEN {
                return Err(Error::Other("malformed resume proof".into()));
            }

            // Verify + remove under one lock scope, with no await in between.
            let mut g = kept.lock().await;
            let sess = g
                .get(&key)
                .ok_or_else(|| Error::Other("kept session was taken by another connection".into()))?;
            sess.verify_resume_tag(
                ResumeRole::Dialer,
                &pre.peer,
                &my_pub,
                &pre.nonce,
                &listener_nonce,
                &tag,
            )?;
            let session = g
                .remove(&key)
                .ok_or_else(|| Error::Other("kept session vanished".into()))?;
            return Ok(ListenerOutcome::Resume { peer: pre.peer, session });
        }
    }

    // Fresh path: reply with our identity; the signed handshake follows.
    let mut reply = vec![DECISION_FRESH];
    reply.extend_from_slice(&me.public().to_bytes());
    io.send_frame(&reply).await?;
    Ok(ListenerOutcome::Fresh { peer: pre.peer })
}

pub(crate) enum DialerOutcome {
    /// The listener chose fresh. The caller runs `ConnectedSession::initiate`.
    Fresh { peer: PublicIdentity },
    /// Both proofs verified. The session has been taken out of the dialer's `kept`.
    Resume { peer: PublicIdentity, session: SecureSession },
}

/// Dialer side: send the preamble (opens the QUIC stream), then handle the
/// listener's decision. `expected_peer_id` is the PeerId from the ticket.
pub(crate) async fn dialer_negotiate<C: FrameIo>(
    io: &mut C,
    me: &Keypair,
    expected_peer_id: &[u8],
    kept: &mut Option<SecureSession>,
) -> Result<DialerOutcome> {
    let (mode, dialer_nonce) = if kept.is_some() {
        (MODE_RESUME, resume_nonce()?)
    } else {
        (MODE_FRESH, [0u8; NONCE_LEN])
    };
    io.send_frame(&encode_preamble(mode, &dialer_nonce, &me.public())).await?;

    let reply = io.recv_frame().await?;
    if reply.is_empty() {
        return Err(Error::Verify("empty reply from peer".into()));
    }
    let mismatch = || Error::Verify("peer identity does not match the ticket fingerprint".into());

    match reply[0] {
        DECISION_FRESH => {
            let peer = PublicIdentity::from_bytes(&reply[1..])?;
            if peer.peer_id().0.as_slice() != expected_peer_id {
                return Err(mismatch());
            }
            *kept = None; // peer chose fresh — drop the stale session
            Ok(DialerOutcome::Fresh { peer })
        }
        DECISION_CHALLENGE => {
            const HDR: usize = 1 + NONCE_LEN + TAG_LEN;
            if reply.len() < HDR + 1 {
                return Err(Error::Other("short resume challenge".into()));
            }
            let sess = kept
                .as_ref()
                .ok_or_else(|| Error::Other("resume challenge without a kept session".into()))?;
            let mut listener_nonce = [0u8; NONCE_LEN];
            listener_nonce.copy_from_slice(&reply[1..1 + NONCE_LEN]);
            let listener_tag = &reply[1 + NONCE_LEN..HDR];
            let peer = PublicIdentity::from_bytes(&reply[HDR..])?;
            if peer.peer_id().0.as_slice() != expected_peer_id {
                return Err(mismatch());
            }
            let my_pub = me.public();
            sess.verify_resume_tag(
                ResumeRole::Listener,
                &my_pub,
                &peer,
                &dialer_nonce,
                &listener_nonce,
                listener_tag,
            )?;
            let tag = sess.resume_tag(
                ResumeRole::Dialer,
                &my_pub,
                &peer,
                &dialer_nonce,
                &listener_nonce,
            );
            io.send_frame(&tag).await?;
            let session = kept
                .take()
                .ok_or_else(|| Error::Other("kept session vanished".into()))?;
            Ok(DialerOutcome::Resume { peer, session })
        }
        DECISION_RESUMED => Err(Error::Other(
            "peer uses the retired resume protocol; upgrade the peer".into(),
        )),
        other => Err(Error::Other(format!("unknown decision byte {other}"))),
    }
}

/// Listener: negotiate, then accept/resume, with the `kept` bookkeeping. The
/// stale kept session is only removed once a fresh `accept` succeeds, so a
/// forged handshake cannot destroy a peer's resumable session. Returns
/// `(peer, resumed, session)`.
pub(crate) async fn listener_establish<C>(
    mut conn: C,
    me: &Keypair,
    kept: &Mutex<HashMap<PeerKey, SecureSession>>,
    claimed: &mut Option<PeerKey>,
) -> Result<(PublicIdentity, bool, ConnectedSession<C>)>
where
    C: FrameIo + Connection,
{
    match listener_negotiate_claimed(&mut conn, me, kept, claimed).await? {
        ListenerOutcome::Resume { peer, session } => {
            Ok((peer, true, ConnectedSession::resume(conn, session)))
        }
        ListenerOutcome::Fresh { peer } => {
            let cs = ConnectedSession::accept(conn, me, &peer).await?;
            kept.lock().await.remove(&peer.peer_id().0);
            Ok((peer, false, cs))
        }
    }
}

/// Dialer counterpart of [`listener_establish`].
pub(crate) async fn dialer_establish<C>(
    mut conn: C,
    me: &Keypair,
    expected_peer_id: &[u8],
    kept: &mut Option<SecureSession>,
) -> Result<(PublicIdentity, bool, ConnectedSession<C>)>
where
    C: FrameIo + Connection,
{
    match dialer_negotiate(&mut conn, me, expected_peer_id, kept).await? {
        DialerOutcome::Resume { peer, session } => {
            Ok((peer, true, ConnectedSession::resume(conn, session)))
        }
        DialerOutcome::Fresh { peer } => {
            let cs = ConnectedSession::initiate(conn, me, &peer).await?;
            Ok((peer, false, cs))
        }
    }
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

    // --- in-memory transport -------------------------------------------------

    /// Length-prefixed (u32 BE) frames over a tokio duplex.
    struct MemConn {
        io: tokio::io::DuplexStream,
    }

    fn mem_pair() -> (MemConn, MemConn) {
        let (a, b) = tokio::io::duplex(1 << 20);
        (MemConn { io: a }, MemConn { io: b })
    }

    fn io_err(e: std::io::Error) -> Error {
        Error::Other(format!("mem io: {e}"))
    }

    impl MemConn {
        async fn write_msg(&mut self, bytes: &[u8]) -> Result<()> {
            use tokio::io::AsyncWriteExt;
            self.io
                .write_all(&(bytes.len() as u32).to_be_bytes())
                .await
                .map_err(io_err)?;
            self.io.write_all(bytes).await.map_err(io_err)?;
            self.io.flush().await.map_err(io_err)
        }

        async fn read_msg(&mut self) -> Result<Vec<u8>> {
            use tokio::io::AsyncReadExt;
            let mut len = [0u8; 4];
            self.io.read_exact(&mut len).await.map_err(io_err)?;
            let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
            self.io.read_exact(&mut buf).await.map_err(io_err)?;
            Ok(buf)
        }
    }

    impl FrameIo for MemConn {
        fn send_frame(&mut self, bytes: &[u8]) -> impl Future<Output = Result<()>> + Send {
            self.write_msg(bytes)
        }
        fn recv_frame(&mut self) -> impl Future<Output = Result<Vec<u8>>> + Send {
            self.read_msg()
        }
    }

    // What `ConnectedSession<C>` needs from a connection.
    impl Connection for MemConn {
        async fn send(&mut self, bytes: &[u8]) -> Result<()> {
            self.write_msg(bytes).await
        }
        async fn recv(&mut self) -> Result<Vec<u8>> {
            self.read_msg().await
        }
    }

    type Kept = Mutex<HashMap<PeerKey, SecureSession>>;

    fn kp() -> Keypair {
        Keypair::generate(CryptoSuite::Hybrid).expect("keygen")
    }

    fn pid(k: &Keypair) -> PeerKey {
        k.peer_id().0
    }

    /// A real fresh handshake: `a` dials `b`. Returns (a's session, b's session).
    async fn session_pair(a: &Keypair, b: &Keypair) -> (SecureSession, SecureSession) {
        let (ca, cb) = mem_pair();
        let mut kept_a = None;
        let kept_b: Kept = Mutex::new(HashMap::new());
        let mut claimed = None;
        let bid = pid(b);
        let (ra, rb) = tokio::join!(
            dialer_establish(ca, a, &bid, &mut kept_a),
            listener_establish(cb, b, &kept_b, &mut claimed)
        );
        let csa = ra.expect("dialer handshake").2;
        let csb = rb.expect("listener handshake").2;
        (csa.into_parts().1, csb.into_parts().1)
    }

    async fn kept_with(a: &Keypair, sess: SecureSession) -> Kept {
        let mut m = HashMap::new();
        m.insert(pid(a), sess);
        Mutex::new(m)
    }

    async fn assert_kept_has(kept: &Kept, a: &Keypair) {
        let g = kept.lock().await;
        assert_eq!(g.len(), 1);
        assert!(g.contains_key(&pid(a)));
    }

    /// Impostor/fake-peer preamble claiming `claim`'s identity.
    fn resume_preamble(claim: &Keypair, nonce: [u8; 32]) -> Vec<u8> {
        encode_preamble(MODE_RESUME, &nonce, &claim.public())
    }

    // --- listener ------------------------------------------------------------

    #[tokio::test]
    async fn forged_initiator_leaves_kept_unchanged() {
        let (alice, bob, eve) = (kp(), kp(), kp());
        let (_sa, sb) = session_pair(&alice, &bob).await;
        let kept = kept_with(&alice, sb).await;

        let (mut ce, cb) = mem_pair();
        let mut claimed = None;
        let bob_pub = bob.public();
        let eve_side = async {
            // Eve claims Alice's identity but signs with her own key.
            ce.write_msg(&encode_preamble(MODE_FRESH, &[0u8; 32], &alice.public()))
                .await
                .expect("preamble");
            ce.read_msg().await.expect("decision");
            let _ = ConnectedSession::initiate(ce, &eve, &bob_pub).await;
        };
        let (res, _) = tokio::join!(listener_establish(cb, &bob, &kept, &mut claimed), eve_side);
        assert!(matches!(res, Err(Error::Verify(_))), "forged handshake must be Verify");
        assert_kept_has(&kept, &alice).await;
    }

    #[tokio::test]
    async fn fresh_accept_ok_removes_stale_kept() {
        let (alice, bob) = (kp(), kp());
        let (_sa, stale_b) = session_pair(&alice, &bob).await;
        let kept = kept_with(&alice, stale_b).await;

        let (ca, cb) = mem_pair();
        let mut kept_a = None;
        let mut claimed = None;
        let bid = pid(&bob);
        let (ra, rb) = tokio::join!(
            dialer_establish(ca, &alice, &bid, &mut kept_a),
            listener_establish(cb, &bob, &kept, &mut claimed)
        );
        assert!(ra.is_ok() && rb.is_ok());
        assert!(kept.lock().await.is_empty(), "stale entry removed after accept");
    }

    #[tokio::test]
    async fn impostor_bogus_tag_rejected() {
        let (alice, bob) = (kp(), kp());
        let (_sa, sb) = session_pair(&alice, &bob).await;
        let kept = kept_with(&alice, sb).await;

        let (mut ci, mut cb) = mem_pair();
        let imp = async {
            ci.write_msg(&resume_preamble(&alice, [7u8; 32])).await.unwrap();
            let challenge = ci.read_msg().await.unwrap();
            assert_eq!(challenge[0], DECISION_CHALLENGE);
            ci.write_msg(&[0u8; TAG_LEN]).await.unwrap();
        };
        let (res, _) = tokio::join!(listener_negotiate(&mut cb, &bob, &kept), imp);
        assert!(matches!(res, Err(Error::Verify(_))));
        assert_kept_has(&kept, &alice).await;
    }

    #[tokio::test]
    async fn impostor_hangup_mid_challenge() {
        let (alice, bob) = (kp(), kp());
        let (_sa, sb) = session_pair(&alice, &bob).await;
        let kept = kept_with(&alice, sb).await;

        let (ci, mut cb) = mem_pair();
        let preamble = resume_preamble(&alice, [9u8; 32]);
        let imp = async move {
            let mut ci = ci;
            ci.write_msg(&preamble).await.unwrap();
            let _ = ci.read_msg().await.unwrap();
            // `ci` dropped here: hang up
        };
        let (res, _) = tokio::join!(listener_negotiate(&mut cb, &bob, &kept), imp);
        assert!(res.is_err());
        assert_kept_has(&kept, &alice).await;
    }

    #[tokio::test]
    async fn legacy_preamble_rejected() {
        let (alice, bob) = (kp(), kp());
        let (_sa, sb) = session_pair(&alice, &bob).await;
        let kept = kept_with(&alice, sb).await;

        let (mut ci, cb) = mem_pair();
        // Legacy shape: [mode] || identity, no nonce.
        let mut legacy = vec![MODE_RESUME];
        legacy.extend_from_slice(&alice.public().to_bytes());
        ci.write_msg(&legacy).await.unwrap();

        let res = async move {
            let mut cb = cb;
            listener_negotiate(&mut cb, &bob, &kept).await.map(|_| ()).map_err(|e| (e, kept))
        }
        .await;
        let (_, kept) = res.expect_err("legacy preamble must fail");
        assert_kept_has(&kept, &alice).await;
        // The listener's end is gone and nothing (no DECISION_FRESH) was written.
        assert!(ci.read_msg().await.is_err());
    }

    #[tokio::test]
    async fn short_preamble_rejected() {
        let (alice, bob) = (kp(), kp());
        let (_sa, sb) = session_pair(&alice, &bob).await;
        let kept = kept_with(&alice, sb).await;
        for n in [0usize, 1, 32] {
            let (mut ci, mut cb) = mem_pair();
            ci.write_msg(&vec![MODE_RESUME; n]).await.unwrap();
            assert!(listener_negotiate(&mut cb, &bob, &kept).await.is_err(), "len {n}");
            assert!(parse_preamble(&vec![MODE_RESUME; n]).is_err(), "len {n}");
        }
        assert_kept_has(&kept, &alice).await;
    }

    #[tokio::test]
    async fn fresh_mode_with_kept_session_goes_fresh() {
        let (alice, bob) = (kp(), kp());
        let (_sa, sb) = session_pair(&alice, &bob).await;
        let kept = kept_with(&alice, sb).await;

        let (mut ca, mut cb) = mem_pair();
        let mut no_kept = None;
        let bid = pid(&bob);
        let (rl, rd) = tokio::join!(
            listener_negotiate(&mut cb, &bob, &kept),
            dialer_negotiate(&mut ca, &alice, &bid, &mut no_kept)
        );
        assert!(matches!(rl, Ok(ListenerOutcome::Fresh { .. })));
        assert!(matches!(rd, Ok(DialerOutcome::Fresh { .. })));
        assert_kept_has(&kept, &alice).await;
    }

    // --- dialer --------------------------------------------------------------

    /// Fake listener: read the dialer's preamble, answer with `challenge(dialer_nonce)`.
    async fn fake_listener(
        cb: &mut MemConn,
        challenge: impl FnOnce([u8; 32]) -> Vec<u8>,
    ) {
        let pre = parse_preamble(&cb.read_msg().await.unwrap()).unwrap();
        cb.write_msg(&challenge(pre.nonce)).await.unwrap();
    }

    fn challenge_bytes(ln: &[u8; 32], tag: &[u8], ident: &PublicIdentity) -> Vec<u8> {
        let mut v = vec![DECISION_CHALLENGE];
        v.extend_from_slice(ln);
        v.extend_from_slice(tag);
        v.extend_from_slice(&ident.to_bytes());
        v
    }

    #[tokio::test]
    async fn wrong_listener_tag_rejected() {
        let (alice, bob) = (kp(), kp());
        let (sa, sb) = session_pair(&alice, &bob).await;
        let mut kept_a = Some(sa);
        let (mut ca, mut cb) = mem_pair();
        let (a_pub, b_pub) = (alice.public(), bob.public());
        let ln = [5u8; 32];
        let fake = fake_listener(&mut cb, |dn| {
            let mut tag = sb.resume_tag(ResumeRole::Listener, &a_pub, &b_pub, &dn, &ln).to_vec();
            tag[0] ^= 0xff;
            challenge_bytes(&ln, &tag, &bob.public())
        });
        let bid = pid(&bob);
        let (res, _) = tokio::join!(dialer_negotiate(&mut ca, &alice, &bid, &mut kept_a), fake);
        assert!(matches!(res, Err(Error::Verify(_))));
        assert!(kept_a.is_some());
        // The dialer sent no tag.
        let nothing = tokio::time::timeout(std::time::Duration::from_millis(100), cb.read_msg()).await;
        assert!(nothing.is_err(), "no tag must be sent");
    }

    #[tokio::test]
    async fn listener_identity_mismatch_keeps_session() {
        let (alice, bob, mallory) = (kp(), kp(), kp());
        let (sa, _sb) = session_pair(&alice, &bob).await;
        let mut kept_a = Some(sa);
        let (mut ca, mut cb) = mem_pair();
        // Identity is Mallory's, not the ticket's (Bob's).
        let fake = fake_listener(&mut cb, |_| challenge_bytes(&[5u8; 32], &[0u8; TAG_LEN], &mallory.public()));
        let bid = pid(&bob);
        let (res, _) = tokio::join!(dialer_negotiate(&mut ca, &alice, &bid, &mut kept_a), fake);
        assert!(matches!(res, Err(Error::Verify(_))));
        assert!(kept_a.is_some());
    }

    #[tokio::test]
    async fn legacy_decision_resumed_rejected() {
        let (alice, bob) = (kp(), kp());
        let (sa, _sb) = session_pair(&alice, &bob).await;
        let mut kept_a = Some(sa);
        let (mut ca, mut cb) = mem_pair();
        let fake = fake_listener(&mut cb, |_| {
            let mut v = vec![DECISION_RESUMED];
            v.extend_from_slice(&bob.public().to_bytes());
            v
        });
        let bid = pid(&bob);
        let (res, _) = tokio::join!(dialer_negotiate(&mut ca, &alice, &bid, &mut kept_a), fake);
        assert!(res.is_err());
        assert!(kept_a.is_some());
    }

    #[tokio::test]
    async fn challenge_without_kept_session_errors() {
        let (alice, bob) = (kp(), kp());
        let mut kept_a: Option<SecureSession> = None;
        let (mut ca, mut cb) = mem_pair();
        let fake = fake_listener(&mut cb, |_| challenge_bytes(&[5u8; 32], &[0u8; TAG_LEN], &bob.public()));
        let bid = pid(&bob);
        let (res, _) = tokio::join!(dialer_negotiate(&mut ca, &alice, &bid, &mut kept_a), fake);
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn resume_happy_path_both_directions() {
        let (alice, bob) = (kp(), kp());
        let (sa, sb) = session_pair(&alice, &bob).await;
        let mut kept_a = Some(sa);
        let kept_b = kept_with(&alice, sb).await;

        let (mut ca, mut cb) = mem_pair();
        let bid = pid(&bob);
        let (rd, rl) = tokio::join!(
            dialer_negotiate(&mut ca, &alice, &bid, &mut kept_a),
            listener_negotiate(&mut cb, &bob, &kept_b)
        );
        let mut sa = match rd {
            Ok(DialerOutcome::Resume { session, .. }) => session,
            _ => panic!("dialer should resume"),
        };
        let mut sb = match rl {
            Ok(ListenerOutcome::Resume { session, .. }) => session,
            _ => panic!("listener should resume"),
        };
        assert!(kept_a.is_none());
        assert!(kept_b.lock().await.is_empty());

        let ct = sa.seal(b"hello bob").unwrap();
        assert_eq!(sb.open(&ct).unwrap(), b"hello bob");
        let ct = sb.seal(b"hello alice").unwrap();
        assert_eq!(sa.open(&ct).unwrap(), b"hello alice");
    }

    // --- passphrase / size ---------------------------------------------------

    #[test]
    fn store_identity_rejects_blank_passphrase() {
        let dir = tmp_dir("blank-store");
        let _ = std::fs::remove_dir_all(&dir);
        let id = generate_identity().unwrap();
        for bad in ["", " \t\n"] {
            let err = store_identity(&dir, &id.mnemonic, bad).err().expect("must fail");
            assert!(err.to_string().contains("passphrase must not be empty"));
            assert!(!identity_exists(&dir));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_rejects_blank_passphrase() {
        let dir = tmp_dir("blank-load");
        let _ = std::fs::remove_dir_all(&dir);
        let id = generate_identity().unwrap();
        store_identity(&dir, &id.mnemonic, "real passphrase").unwrap();
        assert!(LatticeNode::load(&dir, "").is_err());
        assert!(LatticeNode::load(&dir, "   ").is_err());
        assert!(LatticeNode::load(&dir, "real passphrase").is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn message_size_limit() {
        assert!(check_message_size(MAX_MESSAGE_BYTES).is_ok());
        let err = check_message_size(MAX_MESSAGE_BYTES + 1).err().expect("too large");
        assert!(err.to_string().contains("too large"));
    }

    #[tokio::test]
    async fn send_rejects_oversized_message() {
        let dir = tmp_dir("send-big");
        let _ = std::fs::remove_dir_all(&dir);
        let id = generate_identity().unwrap();
        store_identity(&dir, &id.mnemonic, "real passphrase").unwrap();
        let node = LatticeNode::load(&dir, "real passphrase").unwrap();
        let err = node
            .send("ab".repeat(32), "x".repeat(MAX_MESSAGE_BYTES + 1))
            .await
            .err()
            .expect("oversized must fail");
        assert!(err.to_string().contains("too large"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn sealed_max_message_fits_frame() {
        let big = vec![0xabu8; MAX_MESSAGE_BYTES];
        let (alice, bob) = (kp(), kp());

        // First message on a fresh pair, from each side in turn.
        let (mut sa, _sb) = session_pair(&alice, &bob).await;
        assert!(sa.seal(&big).unwrap().len() <= MAX_FRAME_BYTES);
        let (_sa, mut sb) = session_pair(&alice, &bob).await;
        assert!(sb.seal(&big).unwrap().len() <= MAX_FRAME_BYTES);

        // After one message in each direction.
        let (mut sa, mut sb) = session_pair(&alice, &bob).await;
        let ct = sa.seal(b"ping").unwrap();
        sb.open(&ct).unwrap();
        let ct = sb.seal(b"pong").unwrap();
        sa.open(&ct).unwrap();
        assert!(sa.seal(&big).unwrap().len() <= MAX_FRAME_BYTES);
        assert!(sb.seal(&big).unwrap().len() <= MAX_FRAME_BYTES);
    }
}
