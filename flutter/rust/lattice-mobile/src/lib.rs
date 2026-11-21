//! `lattice-mobile` — an FFI-safe facade over the Lattice P2P framework.
//!
//! Two concerns, deliberately separated:
//!
//! * **Identity at rest** — free functions that generate / recover a ROOT
//!   identity and encrypt its BIP39 mnemonic under a passphrase (age scrypt) to
//!   `<dir>/identity.age`. Pure crypto + disk: no network, no async. The
//!   passphrase itself is held by the platform keystore on the Dart side. Next
//!   to it, [`LatticeNode::load`] keeps a separate Hybrid DEVICE key
//!   (`device.age`, the device mnemonic) and its root-signed `DeviceCert`
//!   (`device.cert.age`, 30-day lifetime, renewed at load within 7 days of
//!   expiry), both age-encrypted under the same passphrase.
//! * **The live node** — [`LatticeNode`] owns the tokio runtime, the iroh
//!   transport (bound lazily), and the live peer sessions, and emits a
//!   [`NodeEvent`] stream. Transport binding is decoupled from identity load so
//!   the UI can show the identity instantly and go online only when asked.
//!
//! All cryptography and transport live in the audited Lattice crates; this is
//! glue only. The wire protocol is exactly `lattice-net`'s (WIRE_VERSION 2, see
//! the `wire` module), so mobile and `lattice-net` nodes interoperate:
//!
//! * The ticket (v3) is the iroh address plus our ROOT and DEVICE PeerIds.
//! * The dialer's preamble is `[2] ‖ [mode] ‖ nonce[32] ‖ device identity`; the
//!   listener always answers with a hello (its device identity plus an auth
//!   bundle: root identity, device cert, optional revocation list), which the
//!   dialer checks against the ticket's ids before sending anything else.
//! * Then either a fresh device-key handshake followed by a sealed auth-bundle
//!   exchange, or a resume with mutual HMAC proofs. Both are bound to the two
//!   iroh endpoint ids (`lattice-net-cb-v1`).
//! * A listener with no room replies `[3]` (busy); a preamble of another wire
//!   version gets `[4, 2]`.
//!
//! The UI compares the peer's ROOT fingerprint and a safety number derived
//! from both roots out of band; nothing is marked verified automatically.
//! Inbound attempts pass the `lattice-net` flood limiter (`flood` module)
//! before any task is spawned.
#![forbid(unsafe_code)]

mod flood;
mod wire;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use lattice::identity::safety_number;
use lattice::prelude::*;
use lattice::transport::{
    encode_ticket, parse_ticket, read_frame, write_frame, IncomingConn, IrohConn, IrohTransport,
    ParsedTicket, TicketAddr,
};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, Mutex, Notify, Semaphore};
use tokio::task::AbortHandle;
use zeroize::Zeroizing;

use wire::{
    channel_binding, check_endpoint, classify_failure, lock, CertStatus, DeviceCreds,
    FailureKind, KeptPeer, KeptSessions, ListenGuard, PeerAuth, RevocationCache, SourceKey,
};

/// 32-byte PeerId, used as the session map key.
type PeerKey = [u8; 32];

/// Core `read_frame` cap.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
/// Max outgoing plaintext (UTF-8 bytes) per message: 60 KiB, a 4 KiB margin for
/// `SecureSession` framing overhead.
pub const MAX_MESSAGE_BYTES: usize = 60 * 1024;
const IDENTITY_FILE: &str = "identity.age";
/// age(passphrase, device mnemonic UTF-8).
const DEVICE_FILE: &str = "device.age";
/// age(passphrase, `DeviceCert::to_bytes()`).
const DEVICE_CERT_FILE: &str = "device.cert.age";

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

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ===========================================================================
// Identity at rest (offline)
// ===========================================================================

/// A freshly generated identity, not yet persisted. The mnemonic is the only
/// way to recover it — show it once, confirm it, then [`store_identity`].
/// `peer_id_hex` / `fingerprint` describe the ROOT identity.
pub struct NewIdentity {
    pub mnemonic: String,
    pub peer_id_hex: String,
    pub fingerprint: String,
}

/// Public, non-secret summary of a ROOT identity: its PeerId hex and
/// `PeerId::fingerprint()` (10 groups of 4 hex).
pub struct IdentitySummary {
    pub peer_id_hex: String,
    pub fingerprint: String,
}

/// Generate a brand-new PQ-hybrid root identity. Pure crypto: no network, no disk.
pub fn generate_identity() -> Result<NewIdentity> {
    let kp = Keypair::generate(CryptoSuite::Hybrid)?;
    Ok(NewIdentity {
        mnemonic: kp.mnemonic().to_string(),
        peer_id_hex: peer_hex(&kp),
        fingerprint: kp.peer_id().fingerprint(),
    })
}

/// Validate a mnemonic and derive its identity summary (recovery preview /
/// onboarding confirmation). Errors if the phrase isn't a valid identity.
pub fn summarize_mnemonic(mnemonic: &str) -> Result<IdentitySummary> {
    let kp = Keypair::from_mnemonic(CryptoSuite::Hybrid, mnemonic)?;
    Ok(IdentitySummary {
        peer_id_hex: peer_hex(&kp),
        fingerprint: kp.peer_id().fingerprint(),
    })
}

/// Encrypt `mnemonic` under `passphrase` (age scrypt) to `<dir>/identity.age`,
/// `0600`. Validates the mnemonic first so we never persist garbage. Returns
/// the resulting identity summary.
///
/// Fails closed (mirrors Lattice's identity store): it never overwrites an
/// existing identity, so a lost or failed keystore can't silently replace the
/// root mnemonic. The file is written atomically (temp file, fsync, rename),
/// so a crash can't leave a truncated identity behind.
pub fn store_identity(dir: &str, mnemonic: &str, passphrase: &str) -> Result<IdentitySummary> {
    validate_passphrase(passphrase)?;
    let summary = summarize_mnemonic(mnemonic)?;
    if identity_exists(dir) {
        return Err(Error::Other(
            "an identity already exists on this device; refusing to overwrite it".into(),
        ));
    }
    std::fs::create_dir_all(dir).map_err(|e| Error::Other(format!("create dir: {e}")))?;
    let ct = encrypt(passphrase, mnemonic.as_bytes())?;
    write_file_0600(&identity_path(dir), &ct, WriteMode::Replace)?;
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

fn device_path(dir: &str) -> PathBuf {
    Path::new(dir).join(DEVICE_FILE)
}

fn device_cert_path(dir: &str) -> PathBuf {
    Path::new(dir).join(DEVICE_CERT_FILE)
}

fn load_mnemonic(dir: &str, passphrase: &str) -> Result<Zeroizing<String>> {
    let pt = decrypt_file(&identity_path(dir), passphrase, "identity")?;
    String::from_utf8(pt.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| Error::Crypto("stored identity is not valid UTF-8".into()))
}

fn secret(p: &str) -> age::secrecy::SecretString {
    age::secrecy::SecretString::from(p.to_owned())
}

/// age-scrypt encrypt `plaintext` under `passphrase`.
fn encrypt(passphrase: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let recipient = age::scrypt::Recipient::new(secret(passphrase));
    age::encrypt(&recipient, plaintext).map_err(|e| Error::Crypto(format!("age encrypt: {e}")))
}

/// Read and age-scrypt decrypt `path` (`what` names it in errors).
fn decrypt_file(path: &Path, passphrase: &str, what: &str) -> Result<Zeroizing<Vec<u8>>> {
    let ct = std::fs::read(path).map_err(|e| Error::Other(format!("read {what}: {e}")))?;
    let identity = age::scrypt::Identity::new(secret(passphrase));
    age::decrypt(&identity, &ct)
        .map(Zeroizing::new)
        .map_err(|e| Error::Crypto(format!("decrypt failed (wrong passphrase?): {e}")))
}

fn peer_hex(kp: &Keypair) -> String {
    hex::encode(kp.peer_id().0)
}

/// How [`write_file_0600`] puts the finished temp file in place.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WriteMode {
    /// Rename over any existing file (atomic replace).
    Replace,
    /// Create only: fail if the target exists, never overwrite it.
    CreateNew,
}

/// The sibling temp file for `path`: its file name plus `.tmp`
/// (`identity.age.tmp`, `device.age.tmp`, `device.cert.age.tmp`).
fn temp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

/// Atomically write `path` (mode `0600` on unix) with `bytes`: write a sibling
/// temp file, fsync it, then move it into place. A crash leaves either no
/// file or the complete one, never a truncated file. With
/// [`WriteMode::CreateNew`] the move is a hard link that fails if `path`
/// already exists (falling back to an exists check plus rename where hard
/// links are unavailable), so an existing file is never replaced.
fn write_file_0600(path: &Path, bytes: &[u8], mode: WriteMode) -> Result<()> {
    use std::io::Write;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    let tmp = temp_path(path);
    let _ = std::fs::remove_file(&tmp); // stale temp from an earlier crash
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let written = (|| {
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        match mode {
            WriteMode::Replace => std::fs::rename(&tmp, path)?,
            WriteMode::CreateNew => {
                match std::fs::hard_link(&tmp, path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(e),
                    // Hard links can be unavailable (e.g. denied by Android's
                    // SELinux policy for app data): re-check, then rename.
                    // The check-then-rename has a TOCTOU window; that is
                    // acceptable because only this single app process writes
                    // these files.
                    Err(_) => {
                        if path.exists() {
                            return Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists));
                        }
                        std::fs::rename(&tmp, path)?;
                    }
                }
                let _ = std::fs::remove_file(&tmp);
            }
        }
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)?.sync_all()?; // persist the rename
        }
        Ok::<(), std::io::Error>(())
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            return Err(Error::Other(format!(
                "{name} already exists; refusing to overwrite it"
            )));
        }
        return Err(Error::Other(format!("write {name}: {e}")));
    }
    Ok(())
}

/// Load this install's device key and certificate, provisioning them if the
/// install has none yet (migration of root-only installs) and renewing the
/// certificate within [`wire::DEVICE_RENEW_WINDOW`] of expiry (or once expired).
///
/// Fails closed: a `device.age` that does not decrypt or parse, an orphan
/// `device.cert.age`, or a certificate for another device / root (or with a bad
/// signature) is an error and nothing is regenerated. `device.age` is never
/// overwritten; certificate renewal is the only replacement of an existing file.
pub(crate) fn load_or_provision_device(
    dir: &str,
    passphrase: &str,
    root: &Keypair,
    now: u64,
) -> Result<DeviceCreds> {
    validate_passphrase(passphrase)?;
    let dev_path = device_path(dir);
    let cert_path = device_cert_path(dir);
    let lifetime = wire::DEVICE_CERT_LIFETIME.as_secs();

    let device = if dev_path.exists() {
        let pt = decrypt_file(&dev_path, passphrase, "device key")?;
        let mnemonic = std::str::from_utf8(&pt)
            .map_err(|_| Error::Crypto("stored device key is not valid UTF-8".into()))?;
        Keypair::from_mnemonic(CryptoSuite::Hybrid, mnemonic)
            .map_err(|e| Error::Crypto(format!("stored device key is invalid: {e}")))?
    } else {
        if cert_path.exists() {
            return Err(Error::Other(format!(
                "{DEVICE_CERT_FILE} exists without {DEVICE_FILE}; refusing to provision a new device key"
            )));
        }
        let device = Keypair::generate(CryptoSuite::Hybrid)?;
        if device.peer_id() == root.peer_id() {
            return Err(Error::Crypto("device key must differ from the root".into()));
        }
        std::fs::create_dir_all(dir).map_err(|e| Error::Other(format!("create dir: {e}")))?;
        let ct = encrypt(passphrase, device.mnemonic().as_bytes())?;
        write_file_0600(&dev_path, &ct, WriteMode::CreateNew)?;
        device
    };

    let cert = if cert_path.exists() {
        let pt = decrypt_file(&cert_path, passphrase, "device certificate")?;
        let cert = DeviceCert::from_bytes(&pt)
            .map_err(|e| Error::Crypto(format!("stored device certificate is invalid: {e}")))?;
        if cert.device().peer_id() != device.peer_id() {
            return Err(Error::Verify(
                "stored device certificate is for a different device".into(),
            ));
        }
        if *cert.root() != root.peer_id() {
            return Err(Error::Verify(
                "stored device certificate is from a different root".into(),
            ));
        }
        if !cert.verify(root.public(), 0) {
            return Err(Error::Verify(
                "stored device certificate does not verify under the root".into(),
            ));
        }
        cert
    } else {
        let cert = root.authorize_device(device.public(), now + lifetime)?;
        let ct = encrypt(passphrase, &cert.to_bytes())?;
        write_file_0600(&cert_path, &ct, WriteMode::CreateNew)?;
        cert
    };

    let status = wire::cert_status(now, cert.not_after(), wire::DEVICE_RENEW_WINDOW.as_secs());
    let cert = if status == CertStatus::Valid {
        cert
    } else {
        let renewed = root.authorize_device(device.public(), now + lifetime)?;
        let ct = encrypt(passphrase, &renewed.to_bytes())?;
        write_file_0600(&cert_path, &ct, WriteMode::Replace)?;
        renewed
    };

    Ok(DeviceCreds {
        device,
        root: root.public().clone(),
        cert,
        revocation: None,
    })
}

/// The v3 dial ticket: `addr` plus our root and device PeerIds.
pub(crate) fn ticket_for(addr: &TicketAddr, creds: &DeviceCreds) -> Result<String> {
    encode_ticket(addr, &creds.root.peer_id().0, &creds.device.peer_id().0)
}

// ===========================================================================
// Live node (transport + sessions)
// ===========================================================================

/// Everything the UI observes from the node, as a single event stream.
#[derive(Clone, Debug)]
pub enum NodeEvent {
    /// Now accepting connections; `ticket` is the blob a peer dials (render as QR).
    Listening { ticket: String },
    /// The accept loop was stopped (listen toggle off, or accepting failed).
    ListeningStopped,
    /// A secure, authenticated session is up (fresh or resumed). `peer_id_hex`
    /// is the peer's DEVICE PeerId hex (the session key used by `send`);
    /// `root_fingerprint` is the peer's ROOT fingerprint and `safety_number`
    /// is derived from both roots (compare both out of band).
    PeerConnected {
        peer_id_hex: String,
        root_fingerprint: String,
        safety_number: String,
    },
    /// A dropped session was resumed without re-handshaking (ratchet preserved).
    Resumed {
        peer_id_hex: String,
        root_fingerprint: String,
        safety_number: String,
    },
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
    /// The peer failed authentication: a forged handshake, a bad resume proof,
    /// a bad certificate chain, or an identity that doesn't match the ticket.
    AuthFailed { peer_id_hex: String, message: String },
    /// Peer speaks another wire version ("the peer runs an incompatible Lattice version").
    VersionMismatch { peer_id_hex: String, message: String },
    /// The listener replied BUSY; the dialer retries with backoff.
    PeerBusy { peer_id_hex: String },
    /// connect() got a malformed or old-version ticket; nothing was dialed.
    BadTicket { message: String },
}

/// A loaded Lattice node. Build with [`LatticeNode::load`], subscribe via
/// [`next_event`](Self::next_event), then drive [`start_listening`](Self::start_listening)
/// / [`connect`](Self::connect). The transport binds lazily on first use.
pub struct LatticeNode {
    /// The ROOT identity (from the mnemonic): shown to the user, issues certs.
    root: Keypair,
    /// The DEVICE key + root-signed cert that sign handshakes.
    creds: Arc<DeviceCreds>,
    transport: Arc<Mutex<Option<Arc<IrohTransport>>>>,
    /// Live sessions by the peer's DEVICE PeerId.
    peers: Arc<Mutex<HashMap<PeerKey, mpsc::UnboundedSender<Vec<u8>>>>>,
    listen_task: Arc<Mutex<Option<AbortHandle>>>,
    /// The single active outbound dial loop (replaced on each `connect`).
    dial_task: Arc<Mutex<Option<AbortHandle>>>,
    /// Ratchet sessions kept across drops so a reconnecting peer can resume
    /// without a fresh handshake (the listener side of resumption). Locked only
    /// in synchronous sections.
    kept: std::sync::Mutex<KeptSessions>,
    /// Highest-seq verified revocation list per root (memory only), shared by
    /// the listener and dialer paths.
    cache: std::sync::Mutex<RevocationCache>,
    /// Inbound negotiations + sessions that may run at once; beyond it, BUSY.
    inbound: Arc<Semaphore>,
    events_tx: mpsc::UnboundedSender<NodeEvent>,
    events_rx: Mutex<Option<mpsc::UnboundedReceiver<NodeEvent>>>,
}

impl LatticeNode {
    /// Decrypt the stored root identity at `dir` with `passphrase`, load (or
    /// provision / renew) the device key and certificate, and build a node.
    /// No network yet — the transport binds on first `start_listening`/`connect`.
    pub fn load(dir: &str, passphrase: &str) -> Result<Arc<Self>> {
        validate_passphrase(passphrase)?;
        let mnemonic = load_mnemonic(dir, passphrase)?;
        let root = Keypair::from_mnemonic(CryptoSuite::Hybrid, &mnemonic)?;
        let creds = load_or_provision_device(dir, passphrase, &root, now_secs())?;
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        Ok(Arc::new(Self {
            root,
            creds: Arc::new(creds),
            transport: Arc::new(Mutex::new(None)),
            peers: Arc::new(Mutex::new(HashMap::new())),
            listen_task: Arc::new(Mutex::new(None)),
            dial_task: Arc::new(Mutex::new(None)),
            kept: std::sync::Mutex::new(KeptSessions::new()),
            cache: std::sync::Mutex::new(RevocationCache::new()),
            inbound: Arc::new(Semaphore::new(wire::MAX_LIVE_INBOUND)),
            events_tx,
            events_rx: Mutex::new(Some(events_rx)),
        }))
    }

    /// This node's stable ROOT PeerId, hex-encoded.
    pub fn peer_id_hex(&self) -> String {
        peer_hex(&self.root)
    }

    /// The ROOT fingerprint (`PeerId::fingerprint()`, 10 groups of 4 hex).
    pub fn fingerprint(&self) -> String {
        self.root.peer_id().fingerprint()
    }

    /// The 24-word BIP39 ROOT backup mnemonic. Gate behind biometric + explicit intent.
    pub fn mnemonic(&self) -> String {
        self.root.mnemonic().to_string()
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

    /// The v3 dial ticket for this node (binds the transport if needed):
    /// the iroh address plus our root and device PeerIds — small enough for a
    /// QR. The dialer checks our hello (device identity + cert chain) against it.
    pub async fn my_ticket(&self) -> Result<String> {
        let t = self.ensure_online().await?;
        ticket_for(&t.ticket_addr().await?, &self.creds)
    }

    /// Go online and start accepting inbound connections. Emits `Listening`
    /// with the ticket, then runs an abortable acceptor loop.
    pub fn start_listening(self: &Arc<Self>) {
        let node = Arc::clone(self);
        runtime().spawn(async move {
            let t = match node.ensure_online().await {
                Ok(t) => t,
                Err(e) => return node.emit_err(format!("go online: {e}")),
            };
            let ticket = match t.ticket_addr().await {
                Ok(addr) => ticket_for(&addr, &node.creds),
                Err(e) => Err(e),
            };
            match ticket {
                Ok(ticket) => node.emit(NodeEvent::Listening { ticket }),
                Err(e) => return node.emit_err(format!("ticket: {e}")),
            }

            // Replace any prior accept loop.
            if let Some(h) = node.listen_task.lock().await.take() {
                h.abort();
            }
            let n2 = Arc::clone(&node);
            let handle = runtime().spawn(async move { n2.accept_loop(t).await });
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
            node.emit(NodeEvent::ListeningStopped);
        });
    }

    /// Dial a peer by ticket and keep the session alive across drops: on a
    /// disconnect it re-dials with resume (falling back to a fresh handshake if
    /// the peer can't resume), with exponential backoff while unreachable.
    ///
    /// The ticket is parsed first, synchronously: a malformed or old-version
    /// ticket emits `BadTicket` and nothing else happens (no transport bind,
    /// the existing dial loop is left alone).
    pub fn connect(self: &Arc<Self>, ticket: String) {
        let parsed = match parse_ticket(&ticket) {
            Ok(p) => p,
            Err(e) => {
                return self.emit(NodeEvent::BadTicket {
                    message: err_text(&e),
                })
            }
        };
        let node = Arc::clone(self);
        runtime().spawn(async move {
            // Replace any existing dial loop so repeated taps don't stack
            // reconnect loops (which would race + spam transport timeouts).
            if let Some(h) = node.dial_task.lock().await.take() {
                h.abort();
            }
            let runner = Arc::clone(&node);
            let handle = runtime().spawn(async move { runner.dial_loop(ticket, parsed).await });
            *node.dial_task.lock().await = Some(handle.abort_handle());
        });
    }

    /// Send a UTF-8 message to a connected peer (by its DEVICE PeerId hex).
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

    // --- internals: listener ----------------------------------------------

    /// Acceptor: take each incoming attempt, apply the source / global flood
    /// limits and take a pending-accept slot before spawning anything.
    async fn accept_loop(self: Arc<Self>, t: Arc<IrohTransport>) {
        let pool = flood::SlotPool::new(wire::MAX_PENDING_ACCEPTS, wire::RESERVED_VERIFIED_SLOTS);
        let guard: Arc<std::sync::Mutex<ListenGuard>> = Arc::new(std::sync::Mutex::new(
            flood::FloodGuard::new(flood::MonotonicClock::new(), wire::listener_limits()),
        ));
        let busy = Arc::new(Semaphore::new(wire::MAX_BUSY_REPLIES));
        loop {
            let incoming = match t.accept_incoming().await {
                Ok(i) => i,
                Err(e) => {
                    self.emit_err(format!("accept failed: {e} — no longer accepting"));
                    self.emit(NodeEvent::ListeningStopped);
                    break;
                }
            };
            let src = wire::source_key(incoming.remote_source());
            let (node, guard_task, busy_task, t_task) = (
                Arc::clone(&self),
                Arc::clone(&guard),
                Arc::clone(&busy),
                Arc::clone(&t),
            );
            let events_tx = self.events_tx.clone();
            // On refusal `incoming` (owned by the unused closure) is dropped,
            // which refuses the attempt; the drop was already counted.
            let _ = wire::spawn_admitted_with(
                &guard,
                &pool,
                &src,
                move |line| {
                    let _ = events_tx.send(NodeEvent::Error { message: line });
                },
                move |slot| async move {
                    node.accept_task(incoming, slot, src, guard_task, busy_task, t_task)
                        .await
                },
            );
        }
    }

    /// One admitted inbound attempt: bounded `finish`, per-endpoint admission,
    /// slot classification, then dispatch (negotiate, busy reply, or drop).
    /// The pending-accept slot is held until this returns.
    async fn accept_task(
        self: Arc<Self>,
        incoming: IncomingConn,
        slot: flood::Slot,
        src: SourceKey,
        guard: Arc<std::sync::Mutex<ListenGuard>>,
        busy: Arc<Semaphore>,
        t: Arc<IrohTransport>,
    ) {
        let limit = match slot.kind() {
            flood::SlotKind::General => wire::NEGOTIATION_TIMEOUT,
            flood::SlotKind::Reserved => wire::PROVISIONAL_HANDSHAKE_TIMEOUT,
        };
        let conn = match wire::accept_within(limit, incoming.finish()).await {
            Ok(c) => c,
            Err(_) => {
                lock(&guard).record_failure(&src, None);
                self.note_drop(&guard, flood::DropReason::Failed);
                return;
            }
        };
        let ep = conn.remote_endpoint_id();
        let admitted = lock(&guard).admit_endpoint(&ep);
        let verified = match admitted {
            Ok(v) => v,
            Err(reason) => return self.note_drop(&guard, reason),
        };
        let Some(_slot) = slot.classify(verified) else {
            return self.note_drop(&guard, flood::DropReason::StrangerInReservedSlot);
        };
        match Arc::clone(&self.inbound).try_acquire_owned() {
            Ok(permit) => {
                let node = Arc::clone(&self);
                tokio::spawn(async move {
                    let _permit = permit; // held until the session ends
                    node.handle_incoming(conn, src, ep, guard, t).await;
                });
            }
            Err(_) => {
                // No room: a bounded one-byte busy reply, else drop `conn`.
                let _ = wire::spawn_bounded(&busy, async move {
                    let _ =
                        tokio::time::timeout(wire::NEGOTIATION_TIMEOUT, wire::reply_busy(conn))
                            .await;
                });
            }
        }
    }

    /// Responder: negotiate (resume or fresh + auth exchange), run the
    /// session, and keep the recovered ratchet for a future resume.
    async fn handle_incoming(
        self: Arc<Self>,
        conn: IrohConn,
        src: SourceKey,
        ep: [u8; 32],
        guard: Arc<std::sync::Mutex<ListenGuard>>,
        t: Arc<IrohTransport>,
    ) {
        let binding = channel_binding(&conn.remote_endpoint_id(), &t.endpoint_id_bytes());
        let mut claimed: Option<PeerId> = None;
        let mut resumed = false;
        let res = wire::negotiate_accept_tracked(
            conn,
            &self.creds,
            &self.kept,
            &binding,
            now_secs(),
            &self.cache,
            &mut claimed,
            wire::NEGOTIATION_TIMEOUT,
            &mut resumed,
        )
        .await;
        let (auth, cs) = match res {
            Ok(x) => x,
            Err(e) => {
                lock(&guard).record_failure(&src, Some(&ep));
                let peer_id_hex = claimed.map(|p| hex::encode(p.0)).unwrap_or_default();
                return match classify_failure(&e) {
                    FailureKind::Version => self.emit(NodeEvent::VersionMismatch {
                        peer_id_hex,
                        message: err_text(&e),
                    }),
                    FailureKind::Auth => self.emit(NodeEvent::AuthFailed {
                        peer_id_hex,
                        message: err_text(&e),
                    }),
                    _ => self.emit_err(format!("negotiation: {e}")),
                };
            }
        };
        // Only our own root counts as "verified" for slot reservation.
        let own_root = self.root.peer_id();
        let verified_root = (auth.root.peer_id() == own_root).then_some(own_root);
        lock(&guard).record_success(&src, &ep, verified_root);

        if resumed {
            let (root_fingerprint, safety_number) = self.trust_of(&auth);
            self.emit(NodeEvent::Resumed {
                peer_id_hex: hex::encode(auth.device.peer_id().0),
                root_fingerprint,
                safety_number,
            });
        }
        if let Some(session) = self.run_session(&auth, cs).await {
            // Keep for a future resume (least recently used are evicted).
            let _evicted = lock(&self.kept).insert(auth.device.peer_id(), KeptPeer { session, auth });
        }
    }

    // --- internals: dialer -------------------------------------------------

    /// Dialer reconnect loop for one ticket. Runs until aborted (a new
    /// `connect`) or a wire-version mismatch; each iteration dials, runs the
    /// session, then re-dials.
    async fn dial_loop(self: Arc<Self>, ticket: String, parsed: ParsedTicket) {
        let mut kept: Option<KeptPeer> = None;
        let mut backoff = 1u64;
        let ticket_device_hex = hex::encode(parsed.device_id);
        loop {
            match self.dial_once(&ticket, &parsed, &mut kept).await {
                Ok(peer_id_hex) => {
                    backoff = 1;
                    self.emit(NodeEvent::Reconnecting { peer_id_hex });
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
                Err(e) => match classify_failure(&e) {
                    FailureKind::Version => {
                        // The peer runs an incompatible version: retrying won't help.
                        return self.emit(NodeEvent::VersionMismatch {
                            peer_id_hex: ticket_device_hex,
                            message: err_text(&e),
                        });
                    }
                    FailureKind::Busy => self.emit(NodeEvent::PeerBusy {
                        peer_id_hex: ticket_device_hex.clone(),
                    }),
                    FailureKind::Auth => self.emit(NodeEvent::AuthFailed {
                        peer_id_hex: ticket_device_hex.clone(),
                        message: err_text(&e),
                    }),
                    FailureKind::Other => {
                        self.emit_err(format!("connect: {e} — retrying in {backoff}s"))
                    }
                },
            }
            tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
            backoff = (backoff * 2).min(30);
        }
    }

    /// One dial: connect, check the endpoint, negotiate (resume or fresh), run
    /// the session, stash the recovered ratchet into `kept` for the next
    /// attempt. Returns the peer's device hex id.
    async fn dial_once(
        &self,
        ticket: &str,
        parsed: &ParsedTicket,
        kept: &mut Option<KeptPeer>,
    ) -> Result<String> {
        let t = self.ensure_online().await?;
        let (dialed, conn) = t.connect_ticket(ticket).await?;
        // The ticket we dialed must be the one we parsed, and we must have
        // reached the endpoint it names.
        if dialed != *parsed {
            return Err(Error::Verify("ticket changed".into()));
        }
        check_endpoint(&parsed.endpoint_id, &conn.remote_endpoint_id())?;
        let binding = channel_binding(&t.endpoint_id_bytes(), &conn.remote_endpoint_id());
        let mut resumed = false;
        let (auth, cs) = wire::negotiate_dial_within_tracked(
            conn,
            &self.creds,
            &parsed.root_id,
            &parsed.device_id,
            kept,
            &binding,
            now_secs(),
            &self.cache,
            wire::NEGOTIATION_TIMEOUT,
            &mut resumed,
        )
        .await?;
        let peer_id_hex = hex::encode(auth.device.peer_id().0);
        if resumed {
            let (root_fingerprint, safety_number) = self.trust_of(&auth);
            self.emit(NodeEvent::Resumed {
                peer_id_hex: peer_id_hex.clone(),
                root_fingerprint,
                safety_number,
            });
        }
        let recovered = self.run_session(&auth, cs).await;
        *kept = recovered.map(|session| KeptPeer { session, auth });
        Ok(peer_id_hex)
    }

    // --- internals: session ------------------------------------------------

    /// The peer's root fingerprint and the safety number of both roots.
    fn trust_of(&self, auth: &PeerAuth) -> (String, String) {
        (
            auth.root.peer_id().fingerprint(),
            safety_number(&self.creds.root, &auth.root),
        )
    }

    /// Full-duplex pump over one session: a reader task decrypts inbound frames
    /// into events while this task encrypts outbound messages from the peer's
    /// channel. The ratchet is shared behind a brief-hold mutex.
    /// Returns the recovered [`SecureSession`] (if the ratchet survived the drop
    /// intact) so the caller can resume it on the next connection.
    async fn run_session(
        &self,
        auth: &PeerAuth,
        cs: ConnectedSession<IrohConn>,
    ) -> Option<SecureSession> {
        let key = auth.device.peer_id().0;
        let hex = hex::encode(key);

        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        self.peers.lock().await.insert(key, out_tx);
        let (root_fingerprint, safety_number) = self.trust_of(auth);
        self.emit(NodeEvent::PeerConnected {
            peer_id_hex: hex.clone(),
            root_fingerprint,
            safety_number,
        });

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
                    let opened = secure.lock().await.open(&frame);
                    match opened {
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
                        let sealed = secure.lock().await.seal(&bytes);
                        let frame = match sealed {
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
        self.emit(NodeEvent::PeerDisconnected { peer_id_hex: hex });
        // Reclaim sole ownership of the ratchet so a reconnect can resume it.
        Arc::try_unwrap(secure).ok().map(|m| m.into_inner())
    }

    fn emit(&self, e: NodeEvent) {
        let _ = self.events_tx.send(e);
    }

    fn emit_err(&self, message: String) {
        self.emit(NodeEvent::Error { message });
    }

    /// Count a dropped inbound attempt; surface the aggregated summary line
    /// (at most one per `DROP_WARN_INTERVAL`) as an `Error` event.
    fn note_drop(&self, guard: &std::sync::Mutex<ListenGuard>, reason: flood::DropReason) {
        if let Some(line) = wire::note_drop(guard, reason) {
            self.emit_err(line);
        }
    }
}

/// The user-facing text of an error: the inner message for verification and
/// transport errors (no "verification failed:" prefix), else its display.
fn err_text(e: &Error) -> String {
    match e {
        Error::Verify(m) | Error::Transport(m) | Error::Other(m) => m.clone(),
        e => e.to_string(),
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

    fn kp() -> Keypair {
        Keypair::generate(CryptoSuite::Hybrid).expect("keygen")
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
    fn store_identity_refuses_to_overwrite() {
        let dir = tmp_dir("no-overwrite");
        let _ = std::fs::remove_dir_all(&dir);
        let first = generate_identity().unwrap();
        store_identity(&dir, &first.mnemonic, "pass one").unwrap();
        let before = std::fs::read(identity_path(&dir)).unwrap();

        let second = generate_identity().unwrap();
        let err = store_identity(&dir, &second.mnemonic, "pass two").err().expect("must refuse");
        assert!(err.to_string().contains("refusing to overwrite"));
        assert_eq!(std::fs::read(identity_path(&dir)).unwrap(), before, "file untouched");
        let node = LatticeNode::load(&dir, "pass one").expect("original still loads");
        assert_eq!(node.peer_id_hex(), first.peer_id_hex);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_identity_writes_atomically_0600() {
        let dir = tmp_dir("atomic");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // A stale temp file from an earlier crash must not block or leak through.
        std::fs::write(identity_path(&dir).with_extension("age.tmp"), b"junk").unwrap();
        let id = generate_identity().unwrap();
        store_identity(&dir, &id.mnemonic, "a passphrase").unwrap();
        assert!(!identity_path(&dir).with_extension("age.tmp").exists(), "temp file renamed away");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(identity_path(&dir)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(LatticeNode::load(&dir, "a passphrase").is_ok());
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

    /// A fresh handshake pair (device keys, no transport): (a's session, b's session).
    fn session_pair(a: &Keypair, b: &Keypair) -> (SecureSession, SecureSession) {
        let (m1, pending) = SecureSession::initiate(a, b.public(), b"").unwrap();
        let (m2, sb) = SecureSession::respond(b, a.public(), b"", &m1).unwrap();
        (pending.finish(&m2).unwrap(), sb)
    }

    #[test]
    fn sealed_max_message_fits_frame() {
        let big = vec![0xabu8; MAX_MESSAGE_BYTES];
        let (alice, bob) = (kp(), kp());

        // First message on a fresh pair, from each side in turn.
        let (mut sa, _sb) = session_pair(&alice, &bob);
        assert!(sa.seal(&big).unwrap().len() <= MAX_FRAME_BYTES);
        let (_sa, mut sb) = session_pair(&alice, &bob);
        assert!(sb.seal(&big).unwrap().len() <= MAX_FRAME_BYTES);

        // After one message in each direction.
        let (mut sa, mut sb) = session_pair(&alice, &bob);
        let ct = sa.seal(b"ping").unwrap();
        sb.open(&ct).unwrap();
        let ct = sb.seal(b"pong").unwrap();
        sa.open(&ct).unwrap();
        assert!(sa.seal(&big).unwrap().len() <= MAX_FRAME_BYTES);
        assert!(sb.seal(&big).unwrap().len() <= MAX_FRAME_BYTES);
    }

    // --- root fingerprint ----------------------------------------------------

    #[test]
    fn generated_fingerprint_is_the_root_fingerprint() {
        let generated = generate_identity().unwrap();
        let root = Keypair::from_mnemonic(CryptoSuite::Hybrid, &generated.mnemonic).unwrap();
        assert_eq!(generated.fingerprint, root.peer_id().fingerprint());
        assert_eq!(generated.peer_id_hex, hex::encode(root.peer_id().0));
        let fp = &generated.fingerprint;
        assert_eq!(fp.len(), 49, "{fp}");
        let groups: Vec<&str> = fp.split(' ').collect();
        assert_eq!(groups.len(), 10, "{fp}");
        for g in groups {
            assert_eq!(g.len(), 4, "{fp}");
            assert!(
                g.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
                "{fp}"
            );
        }
        let summary = summarize_mnemonic(&generated.mnemonic).unwrap();
        assert_eq!(summary.fingerprint, generated.fingerprint);
    }

    // --- device key at rest --------------------------------------------------

    const PASS: &str = "device passphrase";
    const T0: u64 = 1_700_000_000;

    fn lifetime() -> u64 {
        wire::DEVICE_CERT_LIFETIME.as_secs()
    }

    fn window() -> u64 {
        wire::DEVICE_RENEW_WINDOW.as_secs()
    }

    fn fresh_dir(tag: &str) -> String {
        let dir = tmp_dir(tag);
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn read_both(dir: &str) -> (Vec<u8>, Vec<u8>) {
        (
            std::fs::read(device_path(dir)).unwrap(),
            std::fs::read(device_cert_path(dir)).unwrap(),
        )
    }

    #[test]
    fn device_provisioned_on_fresh_dir_0600_and_verifies() {
        let dir = fresh_dir("dev-fresh");
        let root = kp();
        let c = load_or_provision_device(&dir, PASS, &root, T0).unwrap();
        assert!(device_path(&dir).exists());
        assert!(device_cert_path(&dir).exists());
        assert!(!temp_path(&device_path(&dir)).exists());
        assert!(!temp_path(&device_cert_path(&dir)).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for p in [device_path(&dir), device_cert_path(&dir)] {
                let mode = std::fs::metadata(&p).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600, "{}", p.display());
            }
        }
        assert_ne!(c.device.peer_id(), root.peer_id());
        assert_eq!(c.root.peer_id(), root.peer_id());
        assert!(c.cert.verify(root.public(), T0));
        assert_eq!(c.cert.device().peer_id(), c.device.peer_id());
        assert_eq!(c.cert.not_after(), T0 + lifetime());
        assert!(c.revocation.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn device_reload_is_stable() {
        let dir = fresh_dir("dev-stable");
        let root = kp();
        let a = load_or_provision_device(&dir, PASS, &root, T0).unwrap();
        let before = read_both(&dir);
        let b = load_or_provision_device(&dir, PASS, &root, T0 + 60).unwrap();
        assert_eq!(a.device.peer_id(), b.device.peer_id());
        assert_eq!(a.cert.not_after(), b.cert.not_after());
        assert_eq!(read_both(&dir), before, "no renewal, nothing rewritten");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn device_cert_renews_at_window_boundary_and_when_expired() {
        let dir = fresh_dir("dev-renew");
        let root = kp();
        let first = load_or_provision_device(&dir, PASS, &root, T0).unwrap();
        let na = first.cert.not_after();

        // One second outside the window: not renewed.
        let now = na - window() - 1;
        let c = load_or_provision_device(&dir, PASS, &root, now).unwrap();
        assert_eq!(c.cert.not_after(), na);

        // Exactly at the window: renewed for a full lifetime from `now`.
        let now = na - window();
        let c = load_or_provision_device(&dir, PASS, &root, now).unwrap();
        assert_eq!(c.cert.not_after(), now + lifetime());
        assert_eq!(c.device.peer_id(), first.device.peer_id(), "same device key");
        // The renewal is persisted.
        let again = load_or_provision_device(&dir, PASS, &root, now).unwrap();
        assert_eq!(again.cert.not_after(), now + lifetime());

        // Expired: renewed.
        let na2 = again.cert.not_after();
        let now = na2 + 1;
        let c = load_or_provision_device(&dir, PASS, &root, now).unwrap();
        assert_eq!(c.cert.not_after(), now + lifetime());
        assert!(c.cert.verify(root.public(), now));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn device_wrong_passphrase_fails_and_leaves_files() {
        let dir = fresh_dir("dev-wrongpass");
        let root = kp();
        load_or_provision_device(&dir, PASS, &root, T0).unwrap();
        let before = read_both(&dir);
        assert!(load_or_provision_device(&dir, "another passphrase", &root, T0).is_err());
        // Even when a renewal would be due.
        let far = T0 + lifetime() + 10;
        assert!(load_or_provision_device(&dir, "another passphrase", &root, far).is_err());
        assert_eq!(read_both(&dir), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn device_corrupt_key_fails_closed() {
        let dir = fresh_dir("dev-corrupt");
        let root = kp();
        load_or_provision_device(&dir, PASS, &root, T0).unwrap();
        std::fs::write(device_path(&dir), b"not an age file").unwrap();
        assert!(load_or_provision_device(&dir, PASS, &root, T0).is_err());
        assert_eq!(std::fs::read(device_path(&dir)).unwrap(), b"not an age file");

        // Valid age, but not a mnemonic.
        std::fs::write(device_path(&dir), encrypt(PASS, b"not a mnemonic").unwrap()).unwrap();
        let before = std::fs::read(device_path(&dir)).unwrap();
        assert!(load_or_provision_device(&dir, PASS, &root, T0).is_err());
        assert_eq!(std::fs::read(device_path(&dir)).unwrap(), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn device_orphan_cert_fails_closed() {
        let dir = fresh_dir("dev-orphan");
        let root = kp();
        load_or_provision_device(&dir, PASS, &root, T0).unwrap();
        std::fs::remove_file(device_path(&dir)).unwrap();
        let cert_before = std::fs::read(device_cert_path(&dir)).unwrap();
        assert!(load_or_provision_device(&dir, PASS, &root, T0).is_err());
        assert!(!device_path(&dir).exists(), "no new device key provisioned");
        assert_eq!(std::fs::read(device_cert_path(&dir)).unwrap(), cert_before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn device_files_from_another_root_fail_closed() {
        let dir = fresh_dir("dev-otherroot");
        let (root, other) = (kp(), kp());
        load_or_provision_device(&dir, PASS, &root, T0).unwrap();
        let before = read_both(&dir);
        assert!(load_or_provision_device(&dir, PASS, &other, T0).is_err());
        assert_eq!(read_both(&dir), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn device_cert_for_another_device_fails_closed() {
        let dir = fresh_dir("dev-otherdev");
        let root = kp();
        load_or_provision_device(&dir, PASS, &root, T0).unwrap();
        let stranger = kp();
        let cert = root.authorize_device(stranger.public(), T0 + lifetime()).unwrap();
        std::fs::write(device_cert_path(&dir), encrypt(PASS, &cert.to_bytes()).unwrap()).unwrap();
        let before = read_both(&dir);
        assert!(load_or_provision_device(&dir, PASS, &root, T0).is_err());
        assert_eq!(read_both(&dir), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn device_missing_cert_is_reissued() {
        let dir = fresh_dir("dev-nocert");
        let root = kp();
        let a = load_or_provision_device(&dir, PASS, &root, T0).unwrap();
        std::fs::remove_file(device_cert_path(&dir)).unwrap();
        let b = load_or_provision_device(&dir, PASS, &root, T0 + 5).unwrap();
        assert_eq!(a.device.peer_id(), b.device.peer_id());
        assert_eq!(b.cert.not_after(), T0 + 5 + lifetime());
        assert!(device_cert_path(&dir).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn node_load_migrates_identity_only_install() {
        let dir = fresh_dir("dev-migrate");
        let id = generate_identity().unwrap();
        store_identity(&dir, &id.mnemonic, PASS).unwrap();
        assert!(!device_path(&dir).exists());
        let node = LatticeNode::load(&dir, PASS).expect("migration succeeds");
        assert!(device_path(&dir).exists());
        assert!(device_cert_path(&dir).exists());
        assert_eq!(node.peer_id_hex(), id.peer_id_hex);
        assert_eq!(node.fingerprint(), id.fingerprint);
        assert_ne!(node.creds.device.peer_id().0, node.root.peer_id().0);
        // A second load reuses the same device key.
        let device = node.creds.device.peer_id();
        drop(node);
        let node = LatticeNode::load(&dir, PASS).unwrap();
        assert_eq!(node.creds.device.peer_id(), device);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn node_load_wrong_passphrase_creates_no_device_files() {
        let dir = fresh_dir("dev-nofiles");
        let id = generate_identity().unwrap();
        store_identity(&dir, &id.mnemonic, PASS).unwrap();
        assert!(LatticeNode::load(&dir, "wrong passphrase").is_err());
        assert!(!device_path(&dir).exists());
        assert!(!device_cert_path(&dir).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- tickets -------------------------------------------------------------

    fn test_creds() -> DeviceCreds {
        let (root, device) = (kp(), kp());
        let cert = root.authorize_device(device.public(), T0).unwrap();
        DeviceCreds {
            device,
            root: root.public().clone(),
            cert,
            revocation: None,
        }
    }

    #[test]
    fn ticket_for_roundtrips_through_parse_ticket() {
        let ep = kp().public().ed25519_bytes();
        let addr = TicketAddr::from_parts(
            &ep,
            &["https://relay.example.org./"],
            &["192.0.2.1:4433".parse().unwrap()],
        )
        .unwrap();
        let c = test_creds();
        let t = parse_ticket(&ticket_for(&addr, &c).unwrap()).unwrap();
        assert_eq!(t.root_id, c.root.peer_id().0);
        assert_eq!(t.device_id, c.device.peer_id().0);
        assert_eq!(t.endpoint_id, ep);
    }

    /// A hex ticket whose first byte is the old version 2.
    fn v2_ticket() -> String {
        format!("02{}", "00".repeat(80))
    }

    #[test]
    fn parse_ticket_rejects_v2_with_version_message() {
        let e = parse_ticket(&v2_ticket()).unwrap_err();
        assert!(e.to_string().contains("version 2"), "{e}");
    }

    #[tokio::test]
    async fn connect_with_bad_tickets_emits_one_bad_ticket_and_stays_unbound() {
        let dir = fresh_dir("bad-ticket");
        let id = generate_identity().unwrap();
        store_identity(&dir, &id.mnemonic, PASS).unwrap();
        let node = LatticeNode::load(&dir, PASS).unwrap();

        for (ticket, needle) in [(v2_ticket(), "version 2"), ("not hex".to_string(), "hex")] {
            node.connect(ticket);
            let ev = tokio::time::timeout(std::time::Duration::from_secs(5), node.next_event())
                .await
                .expect("an event is emitted")
                .expect("stream open");
            match ev {
                NodeEvent::BadTicket { message } => {
                    assert!(message.contains(needle), "{message}")
                }
                other => panic!("expected BadTicket, got {other:?}"),
            }
            // Exactly one event, and nothing was dialed or bound.
            let more =
                tokio::time::timeout(std::time::Duration::from_millis(300), node.next_event()).await;
            assert!(more.is_err(), "unexpected extra event: {more:?}");
            assert!(node.transport.try_lock().unwrap().is_none(), "transport stays unbound");
            assert!(node.dial_task.try_lock().unwrap().is_none(), "no dial loop started");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
