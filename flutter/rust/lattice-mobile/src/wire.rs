//! The `lattice-net` wire protocol (WIRE_VERSION 2), ported item by item from
//! Lattice ece4d2d `examples/chat/src/bin/lattice-net.rs`.
//!
//! The wire bytes are identical to lattice-net, so a mobile node can dial a
//! lattice-net listener and vice versa:
//!
//! * dialer → listener (preamble):
//!   `[WIRE_VERSION] ‖ [mode] ‖ dialer_nonce[32] ‖ dialer device identity`
//!   (`mode` 0 = fresh with an all-zero nonce, 1 = resume with a random nonce).
//! * listener → dialer, always first: the hello
//!   `[LISTENER_HELLO] ‖ lp32(listener device identity) ‖ auth bundle`, checked
//!   by the dialer against the ticket's root and device ids before anything
//!   else is sent.
//! * listener → dialer, decision: `[DECISION_FRESH]` (signed handshake, then an
//!   auth-bundle exchange sealed by the new session: dialer's bundle first), or
//!   a resume challenge `[DECISION_CHALLENGE] ‖ listener_nonce[32] ‖
//!   listener_tag[32]`, answered by one 32-byte dialer tag frame.
//! * `[DECISION_BUSY]` when the listener has no room, and
//!   `[DECISION_VERSION, WIRE_VERSION]` to a preamble of another version.
//!
//! auth bundle = `lp32(root identity) ‖ lp32(device cert) ‖ lp32(revocation | empty)`
//! (u32 little-endian lengths). Handshakes and resume proofs use the DEVICE
//! keys and are bound to both iroh endpoint ids (`lattice-net-cb-v1`).
//!
//! Mobile differences from lattice-net (no wire changes): the kept sessions and
//! revocation cache are shared behind `std::sync::Mutex` (locked only in
//! synchronous sections, never across `.await`), the listener reports the
//! dialer's claimed device id for event attribution, and several inbound peers
//! may be live at once (`MAX_LIVE_INBOUND`) instead of a single-chat gate.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::HashMap;
use std::future::Future;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use lattice::prelude::*;
use lattice::session::{resume_nonce, ResumeRole};
use lattice::transport::IncomingSource;
use tokio::task::JoinHandle;

use crate::flood;

/// First byte of the dialer's preamble. Must differ from the old preamble's
/// first byte (`MODE_FRESH`/`MODE_RESUME`, 0/1) so an old dialer is recognised.
pub(crate) const WIRE_VERSION: u8 = 2;
pub(crate) const MODE_FRESH: u8 = 0;
pub(crate) const MODE_RESUME: u8 = 1;
pub(crate) const DECISION_FRESH: u8 = 0;
/// Legacy unauthenticated resume: no longer sent; a dialer receiving it errors.
pub(crate) const DECISION_RESUMED: u8 = 1;
pub(crate) const DECISION_CHALLENGE: u8 = 2;
/// Listener reply to a connection it has no room for.
pub(crate) const DECISION_BUSY: u8 = 3;
/// Listener reply `[DECISION_VERSION, WIRE_VERSION]` to an old/unknown preamble.
pub(crate) const DECISION_VERSION: u8 = 4;
/// Tag byte of the listener hello frame.
pub(crate) const LISTENER_HELLO: u8 = 5;
/// How long a freshly issued device certificate is valid.
pub(crate) const DEVICE_CERT_LIFETIME: Duration = Duration::from_secs(30 * 24 * 3600);
/// Renew when the certificate has at most this long left.
pub(crate) const DEVICE_RENEW_WINDOW: Duration = Duration::from_secs(7 * 24 * 3600);
/// Max accepted dialer preamble (bytes); checked before parsing.
pub(crate) const MAX_PREAMBLE_LEN: usize = 8 * 1024;
/// Max accepted listener hello (bytes); checked before parsing.
pub(crate) const MAX_LISTENER_HELLO_LEN: usize = 60 * 1024;
/// Max accepted auth bundle (bytes); checked before parsing.
pub(crate) const MAX_AUTH_BUNDLE_LEN: usize = 60 * 1024;
/// Bound on the in-memory revocation cache.
pub(crate) const MAX_CACHED_ROOTS: usize = 256;
/// Marker in wire-version errors; the dialer does not retry these.
pub(crate) const VERSION_ERR_MARK: &str = "wire version";
/// Upper bound on every pre-session step (preamble, hello, resume
/// challenge/response, handshake, auth exchange) on both sides.
pub(crate) const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(15);
/// `finish()` bound while holding a reserved slot.
pub(crate) const PROVISIONAL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Max concurrent busy-reply tasks; over the limit a connection is dropped.
pub(crate) const MAX_BUSY_REPLIES: usize = 8;
/// Max concurrent pending accepts (QUIC handshake + accept_bi).
pub(crate) const MAX_PENDING_ACCEPTS: usize = 8;
/// Of `MAX_PENDING_ACCEPTS`, slots a stranger can only hold provisionally.
pub(crate) const RESERVED_VERIFIED_SLOTS: usize = 2;
/// Max sessions the listener keeps for resume; least recently used are evicted.
pub(crate) const MAX_KEPT_SESSIONS: usize = 64;
/// Per source: IPv4 /32 or IPv6 /64.
pub(crate) const SOURCE_BURST: u32 = 4;
pub(crate) const SOURCE_REFILL: Duration = Duration::from_secs(2);
/// The one bucket shared by every relayed / unknown-source attempt.
pub(crate) const RELAYED_BURST: u32 = 16;
pub(crate) const RELAYED_REFILL: Duration = Duration::from_millis(250);
/// Per remote endpoint id.
pub(crate) const ENDPOINT_BURST: u32 = 4;
pub(crate) const ENDPOINT_REFILL: Duration = Duration::from_secs(2);
/// Global accept-rate cap (20/s sustained).
pub(crate) const GLOBAL_ACCEPT_BURST: u32 = 32;
pub(crate) const GLOBAL_ACCEPT_REFILL: Duration = Duration::from_millis(50);
pub(crate) const MAX_FAILURES_BEFORE_BAN: u32 = 8;
pub(crate) const FAILURE_WINDOW: Duration = Duration::from_secs(60);
pub(crate) const BAN_DURATION: Duration = Duration::from_secs(300);
pub(crate) const MAX_TRACKED_SOURCES: usize = 4096;
pub(crate) const MAX_TRACKED_ENDPOINTS: usize = 4096;
pub(crate) const MAX_VERIFIED_ENDPOINTS: usize = 256;
pub(crate) const MAX_ENDPOINTS_PER_VERIFIED_ROOT: usize = 4;
/// At most one dropped-connection summary line per this interval.
pub(crate) const DROP_WARN_INTERVAL: Duration = Duration::from_secs(10);
pub(crate) const NONCE_LEN: usize = 32;
pub(crate) const TAG_LEN: usize = 32;
/// Domain separator of the channel binding passed to the handshake and resume.
pub(crate) const CB_DOMAIN: &[u8] = b"lattice-net-cb-v1";
/// Mobile-only: max concurrent inbound negotiations+sessions before BUSY.
pub(crate) const MAX_LIVE_INBOUND: usize = 8;
/// Transport error text of a BUSY reply (dialer side).
pub(crate) const BUSY_ERR: &str = "listener is busy";

/// Lock a std mutex, recovering the data if another thread panicked. Callers
/// must never hold the guard across an `.await`.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Kept sessions (listener resume map).
// ---------------------------------------------------------------------------

/// Bounded map PeerId -> V with least-recently-used eviction. "Use" = insert
/// (a resumed or fresh session is removed and re-inserted after its session).
pub(crate) struct KeptSessions<V = KeptPeer> {
    map: HashMap<PeerId, (u64, V)>,
    tick: u64,
    cap: usize,
}

impl<V> KeptSessions<V> {
    pub(crate) fn new() -> Self {
        Self::with_cap(MAX_KEPT_SESSIONS)
    }

    pub(crate) fn with_cap(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            tick: 0,
            cap: cap.max(1),
        }
    }

    /// Does not refresh the tick: resume removes the entry anyway.
    pub(crate) fn get(&self, id: &PeerId) -> Option<&V> {
        self.map.get(id).map(|(_, v)| v)
    }

    pub(crate) fn remove(&mut self, id: &PeerId) -> Option<V> {
        self.map.remove(id).map(|(_, v)| v)
    }

    pub(crate) fn contains_key(&self, id: &PeerId) -> bool {
        self.map.contains_key(id)
    }

    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Insert/replace with a fresh tick; then evict the min-tick entry while
    /// len > cap. Returns the evicted ids (never `id` itself).
    pub(crate) fn insert(&mut self, id: PeerId, v: V) -> Vec<PeerId> {
        self.tick += 1;
        self.map.insert(id.clone(), (self.tick, v));
        let mut evicted = Vec::new();
        while self.map.len() > self.cap {
            let oldest = self
                .map
                .iter()
                .filter(|(k, _)| **k != id)
                .min_by_key(|(_, (t, _))| *t)
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    self.map.remove(&k);
                    evicted.push(k);
                }
                None => break,
            }
        }
        evicted
    }
}

impl<V> Default for KeptSessions<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V, const N: usize> From<[(PeerId, V); N]> for KeptSessions<V> {
    /// Inserts in array order.
    fn from(items: [(PeerId, V); N]) -> Self {
        let mut s = Self::new();
        for (id, v) in items {
            s.insert(id, v);
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Certificate expiry policy.
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum CertStatus {
    /// More than the renew window left.
    Valid,
    /// Still valid, but within the renew window.
    RenewSoon,
    /// `now > not_after`.
    Expired,
}

/// Pure expiry policy. `now == not_after` is still valid (`RenewSoon`).
pub(crate) fn cert_status(now: u64, not_after: u64, window: u64) -> CertStatus {
    if now > not_after {
        CertStatus::Expired
    } else if not_after - now <= window {
        CertStatus::RenewSoon
    } else {
        CertStatus::Valid
    }
}

// ---------------------------------------------------------------------------
// Credentials, revocation cache, auth bundle.
// ---------------------------------------------------------------------------

/// Our credentials: the device key that signs handshakes, our root identity
/// and the root-signed certificate for the device.
pub(crate) struct DeviceCreds {
    pub device: Keypair,
    pub root: PublicIdentity,
    pub cert: DeviceCert,
    /// Our own root's revocation list. Always `None` on mobile (we never issue one).
    pub revocation: Option<RevocationList>,
}

/// Parsed peer auth bundle (nothing verified yet).
pub(crate) struct AuthBundle {
    pub root: PublicIdentity,
    pub cert: DeviceCert,
    pub revocation: Option<RevocationList>,
}

/// What we verified about a peer.
#[derive(Clone, Debug)]
pub(crate) struct PeerAuth {
    pub root: PublicIdentity,
    pub device: PublicIdentity,
    pub cert_not_after: u64,
}

/// A kept session for resume (listener: map value keyed by device PeerId;
/// dialer: `Option`).
pub(crate) struct KeptPeer {
    pub session: SecureSession,
    pub auth: PeerAuth,
}

/// Bounded per-root cache of the highest-seq verified revocation list
/// (in memory only).
pub(crate) struct RevocationCache {
    lists: HashMap<PeerId, RevocationList>,
}

impl RevocationCache {
    pub(crate) fn new() -> Self {
        Self {
            lists: HashMap::new(),
        }
    }

    pub(crate) fn get(&self, root: &PeerId) -> Option<&RevocationList> {
        self.lists.get(root)
    }

    /// Store if no list for that root yet (and below `MAX_CACHED_ROOTS`) or if
    /// `list` supersedes the cached one. Returns true iff stored. The caller
    /// must only pass lists already verified under their root.
    pub(crate) fn observe(&mut self, list: RevocationList) -> bool {
        let root = list.root().clone();
        let store = match self.lists.get(&root) {
            Some(cached) => list.supersedes(cached),
            None => self.lists.len() < MAX_CACHED_ROOTS,
        };
        if store {
            self.lists.insert(root, list);
        }
        store
    }

    pub(crate) fn revokes(&self, root: &PeerId, device: &PeerId) -> bool {
        self.lists.get(root).is_some_and(|l| l.is_revoked(device))
    }

    pub(crate) fn len(&self) -> usize {
        self.lists.len()
    }
}

impl Default for RevocationCache {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn push_lp32(v: &mut Vec<u8>, x: &[u8]) {
    v.extend_from_slice(&(x.len() as u32).to_le_bytes());
    v.extend_from_slice(x);
}

/// Split one `u32le`-length-prefixed field off `rest`, bounds-checked.
pub(crate) fn take_lp32<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8]> {
    let all: &'a [u8] = rest;
    if all.len() < 4 {
        return Err(Error::Verify("truncated length prefix".into()));
    }
    let n = u32::from_le_bytes([all[0], all[1], all[2], all[3]]) as usize;
    let body = &all[4..];
    if n > body.len() {
        return Err(Error::Verify("length prefix exceeds input".into()));
    }
    let (head, tail) = body.split_at(n);
    *rest = tail;
    Ok(head)
}

fn vctx(what: &'static str) -> impl Fn(Error) -> Error {
    move |e| Error::Verify(format!("{what}: {e}"))
}

/// bundle = lp32(root identity) ‖ lp32(cert) ‖ lp32(revocation list | empty)
pub(crate) fn encode_auth_bundle(me: &DeviceCreds) -> Vec<u8> {
    let mut v = Vec::new();
    push_lp32(&mut v, &me.root.to_bytes());
    push_lp32(&mut v, &me.cert.to_bytes());
    match &me.revocation {
        Some(l) => push_lp32(&mut v, &l.to_bytes()),
        None => push_lp32(&mut v, &[]),
    }
    v
}

/// Length cap first, strict, no trailing bytes.
pub(crate) fn decode_auth_bundle(b: &[u8]) -> Result<AuthBundle> {
    if b.len() > MAX_AUTH_BUNDLE_LEN {
        return Err(Error::Verify(format!(
            "auth bundle too large: {} > {MAX_AUTH_BUNDLE_LEN}",
            b.len()
        )));
    }
    let mut rest = b;
    let root = PublicIdentity::from_bytes(take_lp32(&mut rest)?).map_err(vctx("bundle root"))?;
    let cert = DeviceCert::from_bytes(take_lp32(&mut rest)?).map_err(vctx("bundle cert"))?;
    let rev = take_lp32(&mut rest)?;
    let revocation = if rev.is_empty() {
        None
    } else {
        Some(RevocationList::from_bytes(rev).map_err(vctx("bundle revocation list"))?)
    };
    if !rest.is_empty() {
        return Err(Error::Verify("trailing bytes after auth bundle".into()));
    }
    Ok(AuthBundle {
        root,
        cert,
        revocation,
    })
}

/// Verify a peer's device → root → (not revoked) chain. On success the sent
/// list is observed into `cache`.
pub(crate) fn verify_peer_chain(
    b: &AuthBundle,
    peer_device: &PublicIdentity,
    now: u64,
    cache: &mut RevocationCache,
) -> Result<PeerAuth> {
    let device_id = peer_device.peer_id();
    let root_id = b.root.peer_id();
    if b.cert.device().peer_id() != device_id {
        return Err(Error::Verify(
            "peer chain: certificate is for a different device than the session peer".into(),
        ));
    }
    if !b.cert.verify(&b.root, now) {
        return Err(Error::Verify(
            "peer chain: certificate is invalid, expired, or not issued by the stated root".into(),
        ));
    }
    if let Some(l) = &b.revocation {
        if *l.root() != root_id {
            return Err(Error::Verify(
                "peer chain: revocation list is for a different root".into(),
            ));
        }
        if !l.verify(&b.root) {
            return Err(Error::Verify(
                "peer chain: revocation list signature is invalid".into(),
            ));
        }
        if l.is_revoked(&device_id) {
            return Err(Error::Verify(
                "peer chain: device is revoked by the root's list".into(),
            ));
        }
    }
    if cache.revokes(&root_id, &device_id) {
        return Err(Error::Verify(
            "peer chain: device is revoked by a cached list for its root".into(),
        ));
    }
    if let Some(l) = &b.revocation {
        cache.observe(l.clone());
    }
    Ok(PeerAuth {
        root: b.root.clone(),
        device: peer_device.clone(),
        cert_not_after: b.cert.not_after(),
    })
}

/// hello = [LISTENER_HELLO] ‖ lp32(device identity) ‖ auth bundle
pub(crate) fn encode_listener_hello(me: &DeviceCreds) -> Vec<u8> {
    let mut v = vec![LISTENER_HELLO];
    push_lp32(&mut v, &me.device.public().to_bytes());
    v.extend_from_slice(&encode_auth_bundle(me));
    v
}

/// Parse a listener hello, check its device/root PeerIds against the ticket,
/// then verify the chain.
pub(crate) fn verify_listener_hello(
    frame: &[u8],
    ticket_root: &[u8; 32],
    ticket_device: &[u8; 32],
    now: u64,
    cache: &mut RevocationCache,
) -> Result<PeerAuth> {
    if frame.len() > MAX_LISTENER_HELLO_LEN {
        return Err(Error::Verify(format!(
            "listener hello too large: {} > {MAX_LISTENER_HELLO_LEN}",
            frame.len()
        )));
    }
    if frame.first() != Some(&LISTENER_HELLO) {
        return Err(Error::Verify("not a listener hello".into()));
    }
    let mut rest = &frame[1..];
    let device =
        PublicIdentity::from_bytes(take_lp32(&mut rest)?).map_err(vctx("hello device"))?;
    let bundle = decode_auth_bundle(rest)?;
    if device.peer_id().0 != *ticket_device {
        return Err(Error::Verify(
            "listener's device is not the one named by the ticket".into(),
        ));
    }
    if bundle.root.peer_id().0 != *ticket_root {
        return Err(Error::Verify(
            "listener's root is not the one named by the ticket".into(),
        ));
    }
    verify_peer_chain(&bundle, &device, now, cache)
}

/// True iff the peer's cert is unexpired and the cache does not revoke it.
pub(crate) fn resume_allowed(auth: &PeerAuth, now: u64, cache: &RevocationCache) -> bool {
    now <= auth.cert_not_after && !cache.revokes(&auth.root.peer_id(), &auth.device.peer_id())
}

/// `CB_DOMAIN ‖ dialer_endpoint_id ‖ listener_endpoint_id` (81 bytes): binds a
/// session to the exact iroh endpoints of the connection that carries it.
pub(crate) fn channel_binding(dialer_ep: &[u8; 32], listener_ep: &[u8; 32]) -> Vec<u8> {
    let mut b = Vec::with_capacity(CB_DOMAIN.len() + 64);
    b.extend_from_slice(CB_DOMAIN);
    b.extend_from_slice(dialer_ep);
    b.extend_from_slice(listener_ep);
    b
}

/// Fail unless the connection reached the endpoint we expected.
pub(crate) fn check_endpoint(expected: &[u8; 32], remote: &[u8; 32]) -> Result<()> {
    if expected != remote {
        return Err(Error::Verify("endpoint id mismatch".into()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Listener negotiation.
// ---------------------------------------------------------------------------

/// Read the dialer's preamble and answer with our hello; resume a kept session
/// if asked, available, unexpired and not revoked, otherwise run a fresh
/// handshake plus the auth exchange. Returns the verified peer and the live
/// session. `binding` is the channel binding of this connection. `claimed` is
/// set to the dialer's device PeerId once its preamble parses.
pub(crate) async fn accept_or_resume<C: Connection>(
    conn: C,
    me: &DeviceCreds,
    sessions: &Mutex<KeptSessions>,
    binding: &[u8],
    now: u64,
    cache: &Mutex<RevocationCache>,
    claimed: &mut Option<PeerId>,
) -> Result<(PeerAuth, ConnectedSession<C>)> {
    let mut resumed = false;
    accept_or_resume_tracked(conn, me, sessions, binding, now, cache, claimed, &mut resumed).await
}

/// [`accept_or_resume`], also reporting whether the session was resumed.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn accept_or_resume_tracked<C: Connection>(
    mut conn: C,
    me: &DeviceCreds,
    sessions: &Mutex<KeptSessions>,
    binding: &[u8],
    now: u64,
    cache: &Mutex<RevocationCache>,
    claimed: &mut Option<PeerId>,
    resumed: &mut bool,
) -> Result<(PeerAuth, ConnectedSession<C>)> {
    *resumed = false;
    let preamble = conn.recv().await?;
    if preamble.len() > MAX_PREAMBLE_LEN {
        return Err(Error::Verify(format!(
            "preamble too long: {} > {MAX_PREAMBLE_LEN}",
            preamble.len()
        )));
    }
    if preamble.len() < 2 + NONCE_LEN {
        return Err(Error::Verify("short preamble".into()));
    }
    if preamble[0] != WIRE_VERSION {
        let _ = conn.send(&[DECISION_VERSION, WIRE_VERSION]).await;
        return Err(Error::Verify(format!(
            "peer uses an older lattice-net {VERSION_ERR_MARK}; both sides must upgrade"
        )));
    }
    let mode = preamble[1];
    let mut dialer_nonce = [0u8; NONCE_LEN];
    dialer_nonce.copy_from_slice(&preamble[2..2 + NONCE_LEN]);
    let peer = PublicIdentity::from_bytes(&preamble[2 + NONCE_LEN..])?;
    let peer_id = peer.peer_id();
    *claimed = Some(peer_id.clone());

    // Always send our hello first so the dialer can check us against its ticket.
    conn.send(&encode_listener_hello(me)).await?;

    if mode == MODE_RESUME {
        // Synchronous section: compute our proof under the locks, then release
        // them before any network I/O. Lock order is always sessions → cache
        // (no path takes them the other way round), so this cannot deadlock.
        let challenge: Option<([u8; NONCE_LEN], [u8; TAG_LEN])> = {
            let s = lock(sessions);
            match s.get(&peer_id) {
                Some(kept) if resume_allowed(&kept.auth, now, &lock(cache)) => {
                    let listener_nonce = resume_nonce()?;
                    let listener_tag = kept.session.resume_tag(
                        ResumeRole::Listener,
                        &peer,
                        me.device.public(),
                        &dialer_nonce,
                        &listener_nonce,
                        binding,
                    );
                    Some((listener_nonce, listener_tag))
                }
                // Kept but expired or revoked: require a fresh handshake.
                _ => None,
            }
        };
        if let Some((listener_nonce, listener_tag)) = challenge {
            // Prove we hold the session, then require the dialer's proof
            // *before* the session is removed from the map or used.
            let mut msg = Vec::with_capacity(1 + NONCE_LEN + TAG_LEN);
            msg.push(DECISION_CHALLENGE);
            msg.extend_from_slice(&listener_nonce);
            msg.extend_from_slice(&listener_tag);
            conn.send(&msg).await?;
            let tag = conn.recv().await?;
            // Last await done: re-fetch, verify and remove in one lock scope.
            let kept = {
                let mut s = lock(sessions);
                let entry = s
                    .get(&peer_id)
                    .ok_or_else(|| Error::Verify("kept session vanished during resume".into()))?;
                entry.session.verify_resume_tag(
                    ResumeRole::Dialer,
                    &peer,
                    me.device.public(),
                    &dialer_nonce,
                    &listener_nonce,
                    binding,
                    &tag,
                )?;
                s.remove(&peer_id)
                    .ok_or_else(|| Error::Verify("kept session vanished during resume".into()))?
            };
            *resumed = true;
            return Ok((kept.auth, ConnectedSession::resume(conn, kept.session)));
        }
    }
    // Fresh handshake (requested, or resume with no usable kept session).
    conn.send(&[DECISION_FRESH]).await?;
    let mut cs = ConnectedSession::accept(conn, &me.device, &peer, binding).await?;
    // Auth exchange, sealed by the new session: dialer's bundle first.
    let bundle = decode_auth_bundle(&cs.recv().await?)?;
    let auth = {
        let mut c = lock(cache);
        verify_peer_chain(&bundle, &peer, now, &mut c)?
    };
    cs.send(&encode_auth_bundle(me)).await?;
    // Only a fully authenticated session replaces the stale one for this peer.
    lock(sessions).remove(&peer_id);
    Ok((auth, cs))
}

/// `accept_or_resume` bounded by `limit` (preamble, hello, decision,
/// handshake and auth exchange all included). A timed-out future is dropped
/// mid-await; `accept_or_resume` only mutates `sessions` after its last
/// `.await`, so a timeout leaves the map unchanged (keep it that way).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn negotiate_accept<C: Connection>(
    conn: C,
    me: &DeviceCreds,
    sessions: &Mutex<KeptSessions>,
    binding: &[u8],
    now: u64,
    cache: &Mutex<RevocationCache>,
    claimed: &mut Option<PeerId>,
    limit: Duration,
) -> Result<(PeerAuth, ConnectedSession<C>)> {
    let mut resumed = false;
    negotiate_accept_tracked(
        conn,
        me,
        sessions,
        binding,
        now,
        cache,
        claimed,
        limit,
        &mut resumed,
    )
    .await
}

/// [`negotiate_accept`], also reporting whether the session was resumed.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn negotiate_accept_tracked<C: Connection>(
    conn: C,
    me: &DeviceCreds,
    sessions: &Mutex<KeptSessions>,
    binding: &[u8],
    now: u64,
    cache: &Mutex<RevocationCache>,
    claimed: &mut Option<PeerId>,
    limit: Duration,
    resumed: &mut bool,
) -> Result<(PeerAuth, ConnectedSession<C>)> {
    match tokio::time::timeout(
        limit,
        accept_or_resume_tracked(conn, me, sessions, binding, now, cache, claimed, resumed),
    )
    .await
    {
        // `resumed` is only set true right before an `Ok` return, so a timeout
        // leaves it false.
        Ok(r) => r,
        Err(_) => Err(Error::Transport(format!(
            "negotiation timed out after {limit:?}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Dialer negotiation.
// ---------------------------------------------------------------------------

/// Dialer-side negotiation after the transport connects: send the preamble,
/// verify the listener's hello against the ticket's ids, then either resume
/// the kept session (after a mutual proof) or run a fresh handshake plus the
/// auth exchange. A kept session that is expired/revoked (or for another peer)
/// is dropped *before* the preamble, so the dialer asks for a fresh session. On
/// `DECISION_FRESH`, `kept` is taken (cleared) before the fresh handshake runs.
/// On `DECISION_CHALLENGE`, `kept` is taken only after the listener's proof
/// verifies and the dialer's tag is sent. Busy, version, bad-hello and unknown
/// frames leave `kept` untouched. `binding` is the channel binding of this
/// connection.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn negotiate_dial<C: Connection>(
    conn: C,
    me: &DeviceCreds,
    ticket_root: &[u8; 32],
    ticket_device: &[u8; 32],
    kept: &mut Option<KeptPeer>,
    binding: &[u8],
    now: u64,
    cache: &Mutex<RevocationCache>,
) -> Result<(PeerAuth, ConnectedSession<C>)> {
    let mut resumed = false;
    negotiate_dial_tracked(
        conn,
        me,
        ticket_root,
        ticket_device,
        kept,
        binding,
        now,
        cache,
        &mut resumed,
    )
    .await
}

/// [`negotiate_dial`], also reporting whether the session was resumed.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn negotiate_dial_tracked<C: Connection>(
    mut conn: C,
    me: &DeviceCreds,
    ticket_root: &[u8; 32],
    ticket_device: &[u8; 32],
    kept: &mut Option<KeptPeer>,
    binding: &[u8],
    now: u64,
    cache: &Mutex<RevocationCache>,
    resumed: &mut bool,
) -> Result<(PeerAuth, ConnectedSession<C>)> {
    *resumed = false;
    if let Some(k) = kept.as_ref() {
        let other_peer =
            k.auth.device.peer_id().0 != *ticket_device || k.auth.root.peer_id().0 != *ticket_root;
        let allowed = resume_allowed(&k.auth, now, &lock(cache));
        if other_peer || !allowed {
            *kept = None;
        }
    }

    // Preamble: [WIRE_VERSION] ++ [mode] ++ dialer nonce ++ our device identity.
    let (mode, dialer_nonce) = if kept.is_some() {
        (MODE_RESUME, resume_nonce()?)
    } else {
        (MODE_FRESH, [0u8; NONCE_LEN])
    };
    let mut preamble = vec![WIRE_VERSION, mode];
    preamble.extend_from_slice(&dialer_nonce);
    preamble.extend_from_slice(&me.device.public().to_bytes());
    conn.send(&preamble).await?;

    // First frame: the listener's hello (or busy / a version complaint).
    let first = conn.recv().await?;
    let hello = match first.first().copied() {
        Some(DECISION_BUSY) => return Err(Error::Transport(BUSY_ERR.into())),
        Some(DECISION_VERSION) => {
            let theirs = first.get(1).copied().unwrap_or(0);
            return Err(Error::Verify(format!(
                "listener speaks lattice-net {VERSION_ERR_MARK} {theirs}, we speak {WIRE_VERSION}; both sides must upgrade"
            )));
        }
        // A bare old-style decision as the first frame: an old listener.
        Some(DECISION_FRESH) | Some(DECISION_RESUMED) | Some(DECISION_CHALLENGE) => {
            return Err(Error::Verify(format!(
                "peer uses an older lattice-net {VERSION_ERR_MARK}; both sides must upgrade"
            )));
        }
        Some(LISTENER_HELLO) => {
            let mut c = lock(cache);
            verify_listener_hello(&first, ticket_root, ticket_device, now, &mut c)?
        }
        _ => {
            return Err(Error::Verify(
                "unrecognised first frame from listener".into(),
            ))
        }
    };

    let decision = conn.recv().await?;
    match decision.first().copied() {
        Some(DECISION_FRESH) => {
            let _ = kept.take();
            let mut cs =
                ConnectedSession::initiate(conn, &me.device, &hello.device, binding).await?;
            // Auth exchange, sealed by the new session: ours first.
            cs.send(&encode_auth_bundle(me)).await?;
            let bundle = decode_auth_bundle(&cs.recv().await?)?;
            if bundle.root.peer_id() != hello.root.peer_id() {
                return Err(Error::Verify(
                    "auth bundle root differs from the root in the hello".into(),
                ));
            }
            let auth = {
                let mut c = lock(cache);
                verify_peer_chain(&bundle, &hello.device, now, &mut c)?
            };
            Ok((auth, cs))
        }
        Some(DECISION_CHALLENGE) => {
            let Some(k) = kept.as_ref() else {
                return Err(Error::Verify(
                    "peer sent a resume challenge but no session is kept".into(),
                ));
            };
            let allowed = resume_allowed(&k.auth, now, &lock(cache));
            if k.auth.device.peer_id() != hello.device.peer_id()
                || k.auth.root.peer_id() != hello.root.peer_id()
                || !allowed
            {
                return Err(Error::Verify(
                    "resume challenge from a peer that does not match the kept session".into(),
                ));
            }
            if decision.len() != 1 + NONCE_LEN + TAG_LEN {
                return Err(Error::Verify("malformed resume challenge".into()));
            }
            let mut listener_nonce = [0u8; NONCE_LEN];
            listener_nonce.copy_from_slice(&decision[1..1 + NONCE_LEN]);
            let listener_tag = &decision[1 + NONCE_LEN..];
            k.session.verify_resume_tag(
                ResumeRole::Listener,
                me.device.public(),
                &hello.device,
                &dialer_nonce,
                &listener_nonce,
                binding,
                listener_tag,
            )?;
            let dialer_tag = k.session.resume_tag(
                ResumeRole::Dialer,
                me.device.public(),
                &hello.device,
                &dialer_nonce,
                &listener_nonce,
                binding,
            );
            conn.send(&dialer_tag).await?;
            let k = kept
                .take()
                .ok_or_else(|| Error::Verify("kept session vanished during resume".into()))?;
            *resumed = true;
            Ok((k.auth, ConnectedSession::resume(conn, k.session)))
        }
        Some(DECISION_BUSY) => Err(Error::Transport(BUSY_ERR.into())),
        Some(DECISION_RESUMED) => Err(Error::Verify(
            "peer sent legacy unauthenticated resume decision".into(),
        )),
        _ => Err(Error::Verify("unrecognised resume decision".into())),
    }
}

/// `negotiate_dial` bounded by `limit`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn negotiate_dial_within<C: Connection>(
    conn: C,
    me: &DeviceCreds,
    ticket_root: &[u8; 32],
    ticket_device: &[u8; 32],
    kept: &mut Option<KeptPeer>,
    binding: &[u8],
    now: u64,
    cache: &Mutex<RevocationCache>,
    limit: Duration,
) -> Result<(PeerAuth, ConnectedSession<C>)> {
    let mut resumed = false;
    negotiate_dial_within_tracked(
        conn,
        me,
        ticket_root,
        ticket_device,
        kept,
        binding,
        now,
        cache,
        limit,
        &mut resumed,
    )
    .await
}

/// [`negotiate_dial_within`], also reporting whether the session was resumed.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn negotiate_dial_within_tracked<C: Connection>(
    conn: C,
    me: &DeviceCreds,
    ticket_root: &[u8; 32],
    ticket_device: &[u8; 32],
    kept: &mut Option<KeptPeer>,
    binding: &[u8],
    now: u64,
    cache: &Mutex<RevocationCache>,
    limit: Duration,
    resumed: &mut bool,
) -> Result<(PeerAuth, ConnectedSession<C>)> {
    match tokio::time::timeout(
        limit,
        negotiate_dial_tracked(
            conn,
            me,
            ticket_root,
            ticket_device,
            kept,
            binding,
            now,
            cache,
            resumed,
        ),
    )
    .await
    {
        // `resumed` is only set true right before an `Ok` return.
        Ok(r) => r,
        Err(_) => Err(Error::Transport(format!(
            "negotiation timed out after {limit:?}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Busy reply, bounded tasks.
// ---------------------------------------------------------------------------

/// Send exactly one frame `[DECISION_BUSY]` without reading anything from
/// `conn`, then drop it. Never touches identities or the session map.
pub(crate) async fn reply_busy<C: Connection>(mut conn: C) -> Result<()> {
    conn.send(&[DECISION_BUSY]).await?;
    // Best effort: give the transport a moment to flush before the drop.
    tokio::time::sleep(Duration::from_millis(250)).await;
    Ok(())
}

/// `fut` bounded by `limit`; on timeout returns a transport error and drops it.
pub(crate) async fn accept_within<F, T>(limit: Duration, fut: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    match tokio::time::timeout(limit, fut).await {
        Ok(r) => r,
        Err(_) => Err(Error::Transport(format!(
            "accept timed out after {limit:?}"
        ))),
    }
}

/// Spawn `fut` iff `sem` has a free permit (never waits). The permit moves into
/// the task and is released when the task ends (completion or abort). With no
/// permit, `fut` is dropped unpolled (dropping whatever it owns) and `None` is
/// returned.
pub(crate) fn spawn_bounded<F>(
    sem: &Arc<tokio::sync::Semaphore>,
    fut: F,
) -> Option<JoinHandle<F::Output>>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let permit = sem.clone().try_acquire_owned().ok()?;
    Some(tokio::spawn(async move {
        let _permit = permit;
        fut.await
    }))
}

// ---------------------------------------------------------------------------
// Flood admission.
// ---------------------------------------------------------------------------

/// Who an inbound attempt is attributed to for rate limiting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum SourceKey {
    /// A direct IPv4 source (/32).
    V4(Ipv4Addr),
    /// A direct IPv6 source, by its /64 prefix (first 8 bytes).
    V6Prefix([u8; 8]),
    /// Relayed or unknown: no usable client address, so all of them share one key.
    Relayed,
}

impl flood::SourceKind for SourceKey {
    fn is_shared(&self) -> bool {
        matches!(self, SourceKey::Relayed)
    }
}

/// IPv4 → /32; IPv4-mapped IPv6 → that IPv4; other IPv6 → /64; relayed or
/// unknown → the shared `Relayed` key.
pub(crate) fn source_key(src: IncomingSource) -> SourceKey {
    match src {
        IncomingSource::Direct(addr) => match addr.ip() {
            std::net::IpAddr::V4(ip) => SourceKey::V4(ip),
            std::net::IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                Some(v4) => SourceKey::V4(v4),
                None => {
                    let o = ip.octets();
                    SourceKey::V6Prefix([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]])
                }
            },
        },
        IncomingSource::Relayed | IncomingSource::Unknown => SourceKey::Relayed,
    }
}

/// The listener's flood limits, built only from the named consts.
pub(crate) fn listener_limits() -> flood::Limits {
    flood::Limits {
        source: flood::BucketParams {
            burst: SOURCE_BURST,
            refill_every: SOURCE_REFILL,
        },
        shared_source: flood::BucketParams {
            burst: RELAYED_BURST,
            refill_every: RELAYED_REFILL,
        },
        endpoint: flood::BucketParams {
            burst: ENDPOINT_BURST,
            refill_every: ENDPOINT_REFILL,
        },
        global: flood::BucketParams {
            burst: GLOBAL_ACCEPT_BURST,
            refill_every: GLOBAL_ACCEPT_REFILL,
        },
        ban: flood::BanParams {
            max_failures: MAX_FAILURES_BEFORE_BAN,
            window: FAILURE_WINDOW,
            ban_for: BAN_DURATION,
        },
        max_sources: MAX_TRACKED_SOURCES,
        max_endpoints: MAX_TRACKED_ENDPOINTS,
        max_verified: MAX_VERIFIED_ENDPOINTS,
        max_verified_per_root: MAX_ENDPOINTS_PER_VERIFIED_ROOT,
        warn_interval: DROP_WARN_INTERVAL,
    }
}

pub(crate) type ListenGuard = flood::FloodGuard<flood::MonotonicClock, SourceKey, [u8; 32], PeerId>;

/// Count a drop; returns the aggregated summary line if one is due.
pub(crate) fn note_drop<C: flood::Clock>(
    guard: &Mutex<flood::FloodGuard<C, SourceKey, [u8; 32], PeerId>>,
    reason: flood::DropReason,
) -> Option<String> {
    lock(guard).note_drop(reason)
}

/// Admission before any task is spawned: `guard.admit_source`, then
/// `pool.try_acquire`. On refusal the drop is counted, `make` is never called,
/// nothing is spawned and the reason is returned. On success `make(slot)` is
/// spawned on the current tokio runtime.
pub(crate) fn spawn_admitted<C, F, Fut>(
    guard: &Mutex<flood::FloodGuard<C, SourceKey, [u8; 32], PeerId>>,
    pool: &Arc<flood::SlotPool>,
    src: &SourceKey,
    make: F,
) -> std::result::Result<JoinHandle<Fut::Output>, flood::DropReason>
where
    C: flood::Clock,
    F: FnOnce(flood::Slot) -> Fut,
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    spawn_admitted_with(guard, pool, src, |_| {}, make)
}

/// [`spawn_admitted`], handing the aggregated drop summary line (when one is
/// due) to `on_drop_line` instead of discarding it.
pub(crate) fn spawn_admitted_with<C, L, F, Fut>(
    guard: &Mutex<flood::FloodGuard<C, SourceKey, [u8; 32], PeerId>>,
    pool: &Arc<flood::SlotPool>,
    src: &SourceKey,
    on_drop_line: L,
    make: F,
) -> std::result::Result<JoinHandle<Fut::Output>, flood::DropReason>
where
    C: flood::Clock,
    L: FnOnce(String),
    F: FnOnce(flood::Slot) -> Fut,
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    let admitted = lock(guard).admit_source(src);
    let slot = admitted.and_then(|()| pool.try_acquire().ok_or(flood::DropReason::NoSlot));
    match slot {
        Ok(slot) => Ok(tokio::spawn(make(slot))),
        Err(reason) => {
            if let Some(line) = note_drop(guard, reason) {
                on_drop_line(line);
            }
            Err(reason)
        }
    }
}

// ---------------------------------------------------------------------------
// Failure classification (dial loop / inbound reporting).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailureKind {
    /// Authentication failed (`Error::Verify`).
    Auth,
    /// The peer speaks another wire version (do not retry).
    Version,
    /// The listener replied BUSY (retry with backoff).
    Busy,
    /// Anything else (transport, timeout, …).
    Other,
}

/// Version (checked first: the message carries `VERSION_ERR_MARK`), then
/// BUSY (`Error::Transport(BUSY_ERR)`), then `Error::Verify` → Auth, else Other.
pub(crate) fn classify_failure(e: &Error) -> FailureKind {
    if e.to_string().contains(VERSION_ERR_MARK) {
        return FailureKind::Version;
    }
    match e {
        Error::Transport(m) if m == BUSY_ERR => FailureKind::Busy,
        Error::Verify(_) => FailureKind::Auth,
        _ => FailureKind::Other,
    }
}

// Ported from lattice-net's tests (Lattice ece4d2d), adapted to the shared
// `std::sync::Mutex` session map / cache and the listener's `claimed` out-param.
#[cfg(test)]
mod tests {
    use super::*;
    use lattice::identity::MAX_REVOKED;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// Largest frame body the transport accepts (`lattice_transport::MAX_FRAME_LEN`).
    const FRAME_CAP: usize = 65_536;
    const NOW: u64 = 1_000;
    const FAR: u64 = 1_000_000;
    const SHORT: Duration = Duration::from_millis(50);
    const MEDIUM: Duration = Duration::from_secs(5);

    type Sessions = Mutex<KeptSessions>;
    type Cache = Mutex<RevocationCache>;
    type Negotiated = Result<(PeerAuth, ConnectedSession<MemoryConn>)>;

    fn id() -> Keypair {
        Keypair::generate(CryptoSuite::Hybrid).unwrap()
    }

    /// Credentials for a fresh device under `root`, valid until `not_after`.
    fn creds_with(root: &Keypair, not_after: u64) -> DeviceCreds {
        let device = id();
        let cert = root.authorize_device(device.public(), not_after).unwrap();
        DeviceCreds {
            device,
            root: root.public().clone(),
            cert,
            revocation: None,
        }
    }

    /// Credentials under a brand-new root.
    fn creds() -> DeviceCreds {
        creds_with(&id(), FAR)
    }

    fn cache() -> Cache {
        Mutex::new(RevocationCache::new())
    }

    fn ids(c: &DeviceCreds) -> ([u8; 32], [u8; 32]) {
        (c.root.peer_id().0, c.device.peer_id().0)
    }

    fn auth_of(c: &DeviceCreds) -> PeerAuth {
        PeerAuth {
            root: c.root.clone(),
            device: c.device.public().clone(),
            cert_not_after: c.cert.not_after(),
        }
    }

    fn kept(session: SecureSession, peer: &DeviceCreds) -> KeptPeer {
        KeptPeer {
            session,
            auth: auth_of(peer),
        }
    }

    /// A fixed, valid channel binding for tests that don't care about its value.
    fn bnd() -> Vec<u8> {
        channel_binding(&[0xd1; 32], &[0x11; 32])
    }

    fn has(s: &Sessions, peer: &PeerId) -> bool {
        lock(s).contains_key(peer)
    }

    /// Connected in-memory pair: (dialer end, listener end).
    async fn pair() -> (MemoryConn, MemoryConn) {
        let net = MemoryNetwork::new();
        let (a, b) = (PeerId([1u8; 32]), PeerId([2u8; 32]));
        let ta = net.endpoint(a);
        let tb = net.endpoint(b.clone());
        let dial = ta.connect(&b).await.unwrap();
        let (_, listen) = tb.accept().await.unwrap();
        (dial, listen)
    }

    /// Alice (dialer) negotiates with `bob` (listener) using bob's ticket ids.
    async fn dial_to(
        conn: MemoryConn,
        alice: &DeviceCreds,
        bob: &DeviceCreds,
        kept: &mut Option<KeptPeer>,
        binding: &[u8],
        cache: &Cache,
    ) -> Negotiated {
        let (r, d) = ids(bob);
        negotiate_dial(conn, alice, &r, &d, kept, binding, NOW, cache).await
    }

    /// The listener side via the spec-named `accept_or_resume`.
    async fn accept(
        conn: MemoryConn,
        me: &DeviceCreds,
        sessions: &Sessions,
        binding: &[u8],
        now: u64,
        cache: &Cache,
    ) -> Negotiated {
        let mut claimed = None;
        accept_or_resume(conn, me, sessions, binding, now, cache, &mut claimed).await
    }

    /// `negotiate_accept` with a throwaway `claimed`.
    async fn accept_within_limit(
        conn: MemoryConn,
        me: &DeviceCreds,
        sessions: &Sessions,
        cache: &Cache,
        binding: &[u8],
        limit: Duration,
    ) -> Negotiated {
        let mut claimed = None;
        negotiate_accept(conn, me, sessions, binding, NOW, cache, &mut claimed, limit).await
    }

    /// A finished session pair: `a` initiated towards `b`. Returns (a's, b's).
    fn session_pair(a: &DeviceCreds, b: &DeviceCreds) -> (SecureSession, SecureSession) {
        let (m1, pending) = SecureSession::initiate(&a.device, b.device.public(), b"").unwrap();
        let (m2, sb) = SecureSession::respond(&b.device, a.device.public(), b"", &m1).unwrap();
        (pending.finish(&m2).unwrap(), sb)
    }

    /// Listener map holding a kept session for alice's device (responder = bob).
    fn stale(alice: &DeviceCreds, bob: &DeviceCreds) -> Sessions {
        let (s, _) = session_pair(bob, alice);
        Mutex::new(KeptSessions::from([(alice.device.peer_id(), kept(s, alice))]))
    }

    async fn send_preamble(conn: &mut MemoryConn, mode: u8, nonce: [u8; NONCE_LEN], who: &Keypair) {
        let mut p = vec![WIRE_VERSION, mode];
        p.extend_from_slice(&nonce);
        p.extend_from_slice(&who.public().to_bytes());
        conn.send(&p).await.unwrap();
    }

    async fn preamble(conn: &mut MemoryConn, mode: u8, who: &Keypair) {
        send_preamble(conn, mode, [0u8; NONCE_LEN], who).await;
    }

    fn resume_preamble(nonce: &[u8; NONCE_LEN], who: &Keypair) -> Vec<u8> {
        let mut p = vec![WIRE_VERSION, MODE_RESUME];
        p.extend_from_slice(nonce);
        p.extend_from_slice(&who.public().to_bytes());
        p
    }

    /// Genuine Alice–Bob pair: (alice, bob, alice's kept (of bob), bob's kept (of alice)).
    fn genuine() -> (DeviceCreds, DeviceCreds, KeptPeer, KeptPeer) {
        let (alice, bob) = (creds(), creds());
        let (a, b) = session_pair(&alice, &bob);
        let (ka, kb) = (kept(a, &bob), kept(b, &alice));
        (alice, bob, ka, kb)
    }

    fn kept_map(alice: &DeviceCreds, b: KeptPeer) -> Sessions {
        Mutex::new(KeptSessions::from([(alice.device.peer_id(), b)]))
    }

    // ---- fresh negotiation ----

    #[tokio::test]
    async fn fresh_dial_and_accept_two_roots() {
        let (alice, bob) = (creds(), creds());
        let sessions: Sessions = Mutex::new(KeptSessions::new());
        let (ca, cb) = (cache(), cache());
        let mut k = None;
        let (dial, listen) = pair().await;
        let bd = bnd();
        let (d, l) = tokio::join!(
            dial_to(dial, &alice, &bob, &mut k, &bd, &ca),
            accept(listen, &bob, &sessions, &bd, NOW, &cb)
        );
        let ((da, mut ds), (la, mut ls)) = (d.unwrap(), l.unwrap());
        assert_eq!(da.root.peer_id(), bob.root.peer_id());
        assert_eq!(da.device.peer_id(), bob.device.peer_id());
        assert_eq!(la.root.peer_id(), alice.root.peer_id());
        assert_eq!(la.device.peer_id(), alice.device.peer_id());
        assert_eq!(la.cert_not_after, FAR);
        assert_ne!(alice.root.peer_id(), bob.root.peer_id());
        ds.send(b"hello").await.unwrap();
        assert_eq!(ls.recv().await.unwrap(), b"hello");
        ls.send(b"world").await.unwrap();
        assert_eq!(ds.recv().await.unwrap(), b"world");
    }

    #[tokio::test]
    async fn claimed_is_set_to_dialer_device_and_tracked_reports_fresh() {
        let (alice, bob) = (creds(), creds());
        let sessions: Sessions = Mutex::new(KeptSessions::new());
        let (ca, cb) = (cache(), cache());
        let mut k = None;
        let (dial, listen) = pair().await;
        let bd = bnd();
        let (r, d) = ids(&bob);
        let mut claimed = None;
        let (mut rd, mut rl) = (true, true);
        let (dres, lres) = tokio::join!(
            negotiate_dial_within_tracked(
                dial, &alice, &r, &d, &mut k, &bd, NOW, &ca, MEDIUM, &mut rd
            ),
            negotiate_accept_tracked(
                listen, &bob, &sessions, &bd, NOW, &cb, &mut claimed, MEDIUM, &mut rl
            )
        );
        assert!(dres.is_ok() && lres.is_ok());
        assert_eq!(claimed, Some(alice.device.peer_id()));
        assert!(!rd && !rl, "a fresh session is not reported as resumed");
    }

    #[tokio::test]
    async fn forged_initiator_keeps_stale_session() {
        let (alice, bob, eve) = (creds(), creds(), creds());
        let sessions = stale(&alice, &bob);
        let (mut dial, listen) = pair().await;
        preamble(&mut dial, MODE_FRESH, &alice.device).await;
        let b = bnd();
        // Eve's handshake, claimed to come from Alice's device.
        let dialer = async {
            assert_eq!(dial.recv().await.unwrap()[0], LISTENER_HELLO);
            assert_eq!(dial.recv().await.unwrap(), [DECISION_FRESH]);
            ConnectedSession::initiate(dial, &eve.device, bob.device.public(), &b).await
        };
        let c = cache();
        let (d, r) = tokio::join!(dialer, accept(listen, &bob, &sessions, &b, NOW, &c));
        assert!(r.is_err());
        assert!(d.is_err());
        assert!(has(&sessions, &alice.device.peer_id()));
    }

    #[tokio::test]
    async fn genuine_fresh_handshake_replaces_stale_session() {
        let (alice, bob) = (creds(), creds());
        let sessions = stale(&alice, &bob);
        let (dial, listen) = pair().await;
        let b = bnd();
        let (ca, cb) = (cache(), cache());
        let mut k = None;
        let (d, r) = tokio::join!(
            dial_to(dial, &alice, &bob, &mut k, &b, &ca),
            accept(listen, &bob, &sessions, &b, NOW, &cb)
        );
        assert!(d.is_ok());
        assert!(r.is_ok());
        assert!(!has(&sessions, &alice.device.peer_id()));
    }

    #[tokio::test]
    async fn fresh_handshake_with_mismatched_bindings_fails() {
        let (alice, bob) = (creds(), creds());
        let sessions: Sessions = Mutex::new(KeptSessions::new());
        let (dial, listen) = pair().await;
        let b_dial = channel_binding(&[1u8; 32], &[2u8; 32]);
        let b_listen = channel_binding(&[1u8; 32], &[3u8; 32]);
        let mut k = None;
        let (ca, cb) = (cache(), cache());
        let (d, r) = tokio::join!(
            dial_to(dial, &alice, &bob, &mut k, &b_dial, &ca),
            accept(listen, &bob, &sessions, &b_listen, NOW, &cb)
        );
        assert!(matches!(r, Err(Error::Verify(_))));
        assert!(d.is_err());
        assert!(lock(&sessions).is_empty());
    }

    // ---- resume ----

    #[tokio::test]
    async fn genuine_resume_with_mutual_proof_succeeds() {
        let (alice, bob, a, b) = genuine();
        let sessions = kept_map(&alice, b);
        let mut k = Some(a);
        let (dial, listen) = pair().await;
        let bd = bnd();
        let (ca, cb) = (cache(), cache());
        let (d, l) = tokio::join!(
            dial_to(dial, &alice, &bob, &mut k, &bd, &ca),
            accept(listen, &bob, &sessions, &bd, NOW, &cb)
        );
        let ((da, mut d), (la, mut l)) = (d.unwrap(), l.unwrap());
        assert_eq!(da.device.peer_id(), bob.device.peer_id());
        assert_eq!(la.device.peer_id(), alice.device.peer_id());
        assert!(k.is_none());
        assert!(!has(&sessions, &alice.device.peer_id()));
        d.send(b"hello").await.unwrap();
        assert_eq!(l.recv().await.unwrap(), b"hello");
        l.send(b"world").await.unwrap();
        assert_eq!(d.recv().await.unwrap(), b"world");
    }

    #[tokio::test]
    async fn tracked_variants_report_resumed() {
        let (alice, bob, a, b) = genuine();
        let sessions = kept_map(&alice, b);
        let mut k = Some(a);
        let (dial, listen) = pair().await;
        let bd = bnd();
        let (ca, cb) = (cache(), cache());
        let (r, d) = ids(&bob);
        let mut claimed = None;
        let (mut rd, mut rl) = (false, false);
        let (dres, lres) = tokio::join!(
            negotiate_dial_within_tracked(
                dial, &alice, &r, &d, &mut k, &bd, NOW, &ca, MEDIUM, &mut rd
            ),
            negotiate_accept_tracked(
                listen, &bob, &sessions, &bd, NOW, &cb, &mut claimed, MEDIUM, &mut rl
            )
        );
        assert!(dres.is_ok() && lres.is_ok());
        assert!(rd && rl);
        assert_eq!(claimed, Some(alice.device.peer_id()));
    }

    #[tokio::test]
    async fn resume_with_mismatched_bindings_fails_and_keeps_state() {
        let (alice, bob, a, b) = genuine();
        let sessions = kept_map(&alice, b);
        let mut k = Some(a);
        let (dial, listen) = pair().await;
        let b_dial = channel_binding(&[1u8; 32], &[2u8; 32]);
        let b_listen = channel_binding(&[1u8; 32], &[3u8; 32]);
        let (ca, cb) = (cache(), cache());
        let (d, l) = tokio::join!(
            dial_to(dial, &alice, &bob, &mut k, &b_dial, &ca),
            accept(listen, &bob, &sessions, &b_listen, NOW, &cb)
        );
        assert!(d.is_err());
        assert!(l.is_err());
        assert!(k.is_some());
        assert!(has(&sessions, &alice.device.peer_id()));
    }

    #[tokio::test]
    async fn impostor_with_bogus_tag_cannot_resume() {
        let (alice, bob, _a, b) = genuine();
        let sessions = kept_map(&alice, b);
        let (mut eve, listen) = pair().await;
        eve.send(&resume_preamble(&[7u8; NONCE_LEN], &alice.device))
            .await
            .unwrap();
        eve.send(&[0xAA; TAG_LEN]).await.unwrap();
        let c = cache();
        let r = accept(listen, &bob, &sessions, &bnd(), NOW, &c).await;
        assert!(matches!(r, Err(Error::Verify(_))));
        assert!(has(&sessions, &alice.device.peer_id()));
        assert_eq!(eve.recv().await.unwrap()[0], LISTENER_HELLO);
        let reply = eve.recv().await.unwrap();
        assert_eq!(reply.len(), 1 + NONCE_LEN + TAG_LEN);
        assert_eq!(reply[0], DECISION_CHALLENGE);
    }

    #[tokio::test]
    async fn impostor_hanging_up_cannot_resume() {
        let (alice, bob, _a, b) = genuine();
        let sessions = kept_map(&alice, b);
        let (mut eve, listen) = pair().await;
        eve.send(&resume_preamble(&[7u8; NONCE_LEN], &alice.device))
            .await
            .unwrap();
        drop(eve);
        let c = cache();
        let r = accept(listen, &bob, &sessions, &bnd(), NOW, &c).await;
        assert!(r.is_err());
        assert!(has(&sessions, &alice.device.peer_id()));
    }

    #[test]
    fn resume_allowed_checks_expiry_and_cache() {
        let root = id();
        let c = creds_with(&root, 500);
        let auth = auth_of(&c);
        let mut cc = RevocationCache::new();
        assert!(resume_allowed(&auth, 500, &cc));
        assert!(!resume_allowed(&auth, 501, &cc));
        let list = root.revoke_devices(1, 0, &[c.device.peer_id()]).unwrap();
        assert!(cc.observe(list));
        assert!(!resume_allowed(&auth, 100, &cc));
    }

    #[tokio::test]
    async fn revoked_kept_session_is_not_resumed_listener_side() {
        let alice_root = id();
        let alice = creds_with(&alice_root, FAR);
        let bob = creds();
        let (b, _) = session_pair(&bob, &alice);
        let sessions = kept_map(&alice, kept(b, &alice));
        // Bob learns that alice's root revoked alice's device.
        let cb = cache();
        let list = alice_root
            .revoke_devices(1, 0, &[alice.device.peer_id()])
            .unwrap();
        assert!(lock(&cb).observe(list));

        let (mut eve, listen) = pair().await;
        eve.send(&resume_preamble(&[7u8; NONCE_LEN], &alice.device))
            .await
            .unwrap();
        let binding = bnd();
        let r = accept(listen, &bob, &sessions, &binding, NOW, &cb);
        let script = async {
            assert_eq!(eve.recv().await.unwrap()[0], LISTENER_HELLO);
            // No challenge: the listener demands a fresh handshake.
            assert_eq!(eve.recv().await.unwrap(), [DECISION_FRESH]);
            drop(eve);
        };
        let (r, ()) = tokio::join!(r, script);
        assert!(r.is_err());
        // The refused entry stays in the map and was never resumed.
        assert!(has(&sessions, &alice.device.peer_id()));
    }

    #[tokio::test]
    async fn dialer_drops_revoked_or_expired_kept_and_goes_fresh() {
        for expired in [false, true] {
            let bob_root = id();
            let (alice, bob) = (creds(), creds_with(&bob_root, 2_000));
            let (a, _b) = session_pair(&alice, &bob);
            let mut k = Some(kept(a, &bob));
            let ca = cache();
            let mut now = NOW;
            if expired {
                now = 2_001;
            } else {
                let list = bob_root
                    .revoke_devices(1, 0, &[bob.device.peer_id()])
                    .unwrap();
                assert!(lock(&ca).observe(list));
            }
            let (dial, mut listen) = pair().await;
            let script = async { listen.recv().await.unwrap() };
            let (r, d) = ids(&bob);
            let binding = bnd();
            let (res, p) = tokio::join!(
                negotiate_dial_within(dial, &alice, &r, &d, &mut k, &binding, now, &ca, SHORT),
                script
            );
            assert!(res.is_err());
            assert_eq!(p[0], WIRE_VERSION);
            assert_eq!(p[1], MODE_FRESH, "expired={expired}");
            assert!(k.is_none());
        }
    }

    #[tokio::test]
    async fn dialer_drops_kept_for_another_device() {
        let (alice, bob, carol) = (creds(), creds(), creds());
        let (a, _b) = session_pair(&alice, &bob);
        let mut k = Some(kept(a, &bob));
        let ca = cache();
        let (dial, mut listen) = pair().await;
        let script = async { listen.recv().await.unwrap() };
        let (r, d) = ids(&carol);
        let binding = bnd();
        let (res, p) = tokio::join!(
            negotiate_dial_within(dial, &alice, &r, &d, &mut k, &binding, NOW, &ca, SHORT),
            script
        );
        assert!(res.is_err());
        assert_eq!(p[1], MODE_FRESH);
        assert!(k.is_none());
    }

    #[tokio::test]
    async fn dialer_rejects_wrong_listener_tag_and_checks_preamble() {
        let (alice, bob, a, _b) = genuine();
        let mut k = Some(a);
        let (dial, mut listen) = pair().await;
        let hello = encode_listener_hello(&bob);
        let script = async {
            let p = listen.recv().await.unwrap();
            listen.send(&hello).await.unwrap();
            let mut reply = vec![DECISION_CHALLENGE];
            reply.extend_from_slice(&[3u8; NONCE_LEN]);
            reply.extend_from_slice(&[0xBB; TAG_LEN]);
            listen.send(&reply).await.unwrap();
            p
        };
        let bd = bnd();
        let c = cache();
        let (r, p) = tokio::join!(dial_to(dial, &alice, &bob, &mut k, &bd, &c), script);
        assert!(matches!(r, Err(Error::Verify(_))));
        assert!(k.is_some());
        // Resume preamble: [2, 1, nonce, identity].
        let ib = alice.device.public().to_bytes();
        assert_eq!(p[0], WIRE_VERSION);
        assert_eq!(p[1], MODE_RESUME);
        assert_eq!(p.len(), 2 + NONCE_LEN + ib.len());
        assert_eq!(&p[2 + NONCE_LEN..], &ib[..]);
        // The dialer sent no tag after the bad listener proof.
        let next = tokio::time::timeout(MEDIUM, listen.recv()).await.unwrap();
        assert!(next.is_err(), "no tag may be sent");
    }

    #[tokio::test]
    async fn dialer_rejects_malformed_challenge_length() {
        let (alice, bob, a, _b) = genuine();
        let mut k = Some(a);
        let (dial, mut listen) = pair().await;
        listen.send(&encode_listener_hello(&bob)).await.unwrap();
        let mut reply = vec![DECISION_CHALLENGE];
        reply.extend_from_slice(&[0u8; NONCE_LEN + TAG_LEN + 1]);
        listen.send(&reply).await.unwrap();
        let c = cache();
        let r = dial_to(dial, &alice, &bob, &mut k, &bnd(), &c).await;
        assert!(matches!(r, Err(Error::Verify(_))));
        assert!(k.is_some());
    }

    #[tokio::test]
    async fn dialer_rejects_legacy_resumed_decision() {
        let (alice, bob, a, _b) = genuine();
        let mut k = Some(a);
        let (dial, mut listen) = pair().await;
        listen.send(&encode_listener_hello(&bob)).await.unwrap();
        listen.send(&[DECISION_RESUMED]).await.unwrap();
        let c = cache();
        let r = dial_to(dial, &alice, &bob, &mut k, &bnd(), &c).await;
        assert!(matches!(r, Err(Error::Verify(_))));
        assert!(k.is_some());
    }

    #[tokio::test]
    async fn dialer_rejects_challenge_without_kept_session() {
        let (alice, bob) = (creds(), creds());
        let mut k = None;
        let (dial, mut listen) = pair().await;
        listen.send(&encode_listener_hello(&bob)).await.unwrap();
        let mut reply = vec![DECISION_CHALLENGE];
        reply.extend_from_slice(&[0u8; NONCE_LEN + TAG_LEN]);
        listen.send(&reply).await.unwrap();
        let c = cache();
        let r = dial_to(dial, &alice, &bob, &mut k, &bnd(), &c).await;
        assert!(matches!(r, Err(Error::Verify(_))));
    }

    #[tokio::test]
    async fn short_and_long_preambles_are_rejected() {
        let (alice, bob) = (creds(), creds());
        for n in [0usize, 1, 2, 33, MAX_PREAMBLE_LEN + 1] {
            let sessions = stale(&alice, &bob);
            let (mut dial, listen) = pair().await;
            dial.send(&vec![WIRE_VERSION; n]).await.unwrap();
            let c = cache();
            let r = accept(listen, &bob, &sessions, &bnd(), NOW, &c).await;
            assert!(matches!(r, Err(Error::Verify(_))), "len {n}");
            assert_eq!(lock(&sessions).len(), 1);
            assert!(has(&sessions, &alice.device.peer_id()));
        }
    }

    #[tokio::test]
    async fn fresh_dial_preamble_has_version_mode_and_zero_nonce() {
        let (alice, bob) = (creds(), creds());
        let mut k = None;
        let (dial, mut listen) = pair().await;
        let script = async {
            let p = listen.recv().await.unwrap();
            listen.send(&[0xFF]).await.unwrap(); // unknown first frame → dialer errors
            p
        };
        let bd = bnd();
        let c = cache();
        let (r, p) = tokio::join!(dial_to(dial, &alice, &bob, &mut k, &bd, &c), script);
        assert!(matches!(r, Err(Error::Verify(_))));
        let ib = alice.device.public().to_bytes();
        assert_eq!(p[0], WIRE_VERSION);
        assert_eq!(p[1], MODE_FRESH);
        assert!(p[2..2 + NONCE_LEN].iter().all(|b| *b == 0));
        assert_eq!(&p[2 + NONCE_LEN..], &ib[..]);
    }

    // ---- wire version ----

    #[tokio::test]
    async fn old_preamble_gets_version_reply_and_error() {
        let (alice, bob) = (creds(), creds());
        for mode in [MODE_FRESH, MODE_RESUME] {
            let sessions = stale(&alice, &bob);
            let (mut dial, listen) = pair().await;
            let mut p = vec![mode];
            p.extend_from_slice(&[0u8; NONCE_LEN]);
            p.extend_from_slice(&alice.device.public().to_bytes());
            dial.send(&p).await.unwrap();
            let c = cache();
            let r = accept(listen, &bob, &sessions, &bnd(), NOW, &c).await;
            match r {
                Err(e) => {
                    assert!(e.to_string().contains("version"), "{e}");
                    assert_eq!(classify_failure(&e), FailureKind::Version);
                }
                Ok(_) => panic!("old preamble accepted"),
            }
            assert_eq!(dial.recv().await.unwrap(), [DECISION_VERSION, WIRE_VERSION]);
            assert!(has(&sessions, &alice.device.peer_id()));
        }
        assert_ne!(WIRE_VERSION, MODE_FRESH);
        assert_ne!(WIRE_VERSION, MODE_RESUME);
    }

    #[tokio::test]
    async fn dialer_maps_version_and_old_decisions_to_version_error() {
        let (alice, bob, a, _b) = genuine();
        let mut k = Some(a);
        for first in [
            vec![DECISION_VERSION, 9],
            vec![DECISION_FRESH],
            vec![DECISION_RESUMED],
            vec![DECISION_CHALLENGE, 0, 0],
        ] {
            let (dial, mut listen) = pair().await;
            listen.send(&first).await.unwrap();
            let c = cache();
            let r = dial_to(dial, &alice, &bob, &mut k, &bnd(), &c).await;
            match r {
                Err(e) => {
                    assert!(e.to_string().contains("version"), "{e}");
                    assert_eq!(classify_failure(&e), FailureKind::Version);
                }
                Ok(_) => panic!("accepted"),
            }
            assert!(k.is_some());
        }
    }

    // ---- auth chain ----

    fn bundle_of(c: &DeviceCreds) -> AuthBundle {
        decode_auth_bundle(&encode_auth_bundle(c)).unwrap()
    }

    #[test]
    fn chain_accepts_genuine_and_observes_list() {
        let root = id();
        let mut c = creds_with(&root, FAR);
        c.revocation = Some(root.revoke_devices(4, 0, &[PeerId([9; 32])]).unwrap());
        let mut cc = RevocationCache::new();
        let auth = verify_peer_chain(&bundle_of(&c), c.device.public(), NOW, &mut cc).unwrap();
        assert_eq!(auth.root.peer_id(), root.peer_id());
        assert_eq!(auth.device.peer_id(), c.device.peer_id());
        assert_eq!(cc.get(&root.peer_id()).unwrap().seq(), 4);
    }

    #[test]
    fn chain_rejects_cert_for_other_device() {
        let root = id();
        let (a, other) = (creds_with(&root, FAR), creds_with(&root, FAR));
        let mut cc = RevocationCache::new();
        let r = verify_peer_chain(&bundle_of(&other), a.device.public(), NOW, &mut cc);
        assert!(matches!(r, Err(Error::Verify(_))));
    }

    #[test]
    fn chain_rejects_expired_cert() {
        let c = creds_with(&id(), 500);
        let mut cc = RevocationCache::new();
        assert!(verify_peer_chain(&bundle_of(&c), c.device.public(), 500, &mut cc).is_ok());
        let r = verify_peer_chain(&bundle_of(&c), c.device.public(), 501, &mut cc);
        assert!(matches!(r, Err(Error::Verify(_))));
    }

    #[test]
    fn chain_rejects_device_revoked_by_sent_list() {
        let root = id();
        let mut c = creds_with(&root, FAR);
        c.revocation = Some(root.revoke_devices(1, 0, &[c.device.peer_id()]).unwrap());
        let mut cc = RevocationCache::new();
        let r = verify_peer_chain(&bundle_of(&c), c.device.public(), NOW, &mut cc);
        assert!(matches!(r, Err(Error::Verify(_))));
        assert_eq!(cc.len(), 0, "a rejected bundle's list is not cached");
    }

    #[test]
    fn chain_rejects_device_revoked_by_cached_list_even_if_omitted() {
        let root = id();
        let c = creds_with(&root, FAR);
        let mut cc = RevocationCache::new();
        cc.observe(root.revoke_devices(2, 0, &[c.device.peer_id()]).unwrap());
        let r = verify_peer_chain(&bundle_of(&c), c.device.public(), NOW, &mut cc);
        assert!(matches!(r, Err(Error::Verify(_))));
    }

    #[test]
    fn chain_rejects_list_from_other_root_and_unrelated_bundles() {
        let root = id();
        let mut c = creds_with(&root, FAR);
        let other = id();
        c.revocation = Some(other.revoke_devices(1, 0, &[]).unwrap());
        let mut cc = RevocationCache::new();
        assert!(verify_peer_chain(&bundle_of(&c), c.device.public(), NOW, &mut cc).is_err());

        // Valid bundle for carol's own device, but the session peer is dave.
        let (carol, dave) = (creds(), creds());
        assert!(verify_peer_chain(&bundle_of(&carol), dave.device.public(), NOW, &mut cc).is_err());
    }

    #[test]
    fn chain_rejects_cert_signed_by_wrong_root() {
        let mut c = creds();
        c.root = id().public().clone(); // claims a root that did not sign the cert
        let mut cc = RevocationCache::new();
        let r = verify_peer_chain(&bundle_of(&c), c.device.public(), NOW, &mut cc);
        assert!(matches!(r, Err(Error::Verify(_))));
    }

    #[tokio::test]
    async fn bundle_for_wrong_device_rejected_and_sessions_unchanged() {
        let alice_root = id();
        let alice = creds_with(&alice_root, FAR);
        let other = creds_with(&alice_root, FAR);
        let bob = creds();
        let sessions = stale(&alice, &bob);
        let (mut dial, listen) = pair().await;
        preamble(&mut dial, MODE_FRESH, &alice.device).await;
        let bd = bnd();
        let script = async {
            assert_eq!(dial.recv().await.unwrap()[0], LISTENER_HELLO);
            assert_eq!(dial.recv().await.unwrap(), [DECISION_FRESH]);
            let mut cs = ConnectedSession::initiate(dial, &alice.device, bob.device.public(), &bd)
                .await
                .unwrap();
            // A genuine cert, but for a different device than the session peer.
            cs.send(&encode_auth_bundle(&other)).await.unwrap();
        };
        let c = cache();
        let (r, ()) = tokio::join!(accept(listen, &bob, &sessions, &bd, NOW, &c), script);
        assert!(matches!(r, Err(Error::Verify(_))));
        assert_eq!(lock(&sessions).len(), 1);
        assert!(has(&sessions, &alice.device.peer_id()));
    }

    #[test]
    fn bundle_size_caps() {
        // Oversized: rejected before parsing.
        assert!(decode_auth_bundle(&vec![0u8; MAX_AUTH_BUNDLE_LEN + 1]).is_err());
        // Trailing byte / truncation.
        let c = creds();
        let mut b = encode_auth_bundle(&c);
        assert!(decode_auth_bundle(&b).is_ok());
        assert!(decode_auth_bundle(&b[..b.len() - 1]).is_err());
        b.push(0);
        assert!(decode_auth_bundle(&b).is_err());
        // Length prefix larger than the input.
        assert!(decode_auth_bundle(&[0xff, 0xff, 0xff, 0x7f, 1, 2]).is_err());
        assert!(decode_auth_bundle(&[]).is_err());
    }

    #[test]
    fn bundle_layout_is_three_lp32_fields() {
        let c = creds();
        let b = encode_auth_bundle(&c);
        let mut rest = &b[..];
        assert_eq!(take_lp32(&mut rest).unwrap(), &c.root.to_bytes()[..]);
        assert_eq!(take_lp32(&mut rest).unwrap(), &c.cert.to_bytes()[..]);
        assert!(take_lp32(&mut rest).unwrap().is_empty(), "no revocation list is sent");
        assert!(rest.is_empty());
        // Hello = [5] ‖ lp32(device identity) ‖ bundle.
        let h = encode_listener_hello(&c);
        assert_eq!(h[0], LISTENER_HELLO);
        let mut rest = &h[1..];
        assert_eq!(take_lp32(&mut rest).unwrap(), &c.device.public().to_bytes()[..]);
        assert_eq!(rest, &b[..]);
    }

    #[test]
    fn maximal_bundle_and_hello_fit_caps_and_frames() {
        let root = id();
        let mut c = creds_with(&root, FAR);
        let many: Vec<PeerId> = (0..MAX_REVOKED)
            .map(|i| {
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
                PeerId(b)
            })
            .collect();
        c.revocation = Some(root.revoke_devices(1, 0, &many).unwrap());
        let bundle = encode_auth_bundle(&c);
        assert!(bundle.len() <= MAX_AUTH_BUNDLE_LEN, "{}", bundle.len());
        let parsed = decode_auth_bundle(&bundle).unwrap();
        assert_eq!(parsed.revocation.unwrap().revoked().len(), MAX_REVOKED);
        // Sealed by a session: must fit one transport frame.
        let peer = creds();
        let (mut s, _) = session_pair(&c, &peer);
        assert!(s.seal(&bundle).unwrap().len() <= FRAME_CAP);
        // The hello is a plain frame.
        let hello = encode_listener_hello(&c);
        assert!(hello.len() <= MAX_LISTENER_HELLO_LEN, "{}", hello.len());
        assert!(hello.len() <= FRAME_CAP);
        let (r, d) = ids(&c);
        let mut cc = RevocationCache::new();
        assert!(verify_listener_hello(&hello, &r, &d, NOW, &mut cc).is_ok());
    }

    // ---- listener hello ----

    #[test]
    fn hello_checks_against_ticket() {
        let root = id();
        let bob = creds_with(&root, FAR);
        let (r, d) = ids(&bob);
        let hello = encode_listener_hello(&bob);
        let mut cc = RevocationCache::new();
        let ok = verify_listener_hello(&hello, &r, &d, NOW, &mut cc).unwrap();
        assert_eq!(ok.device.peer_id(), bob.device.peer_id());
        assert_eq!(ok.root.peer_id(), root.peer_id());

        let verify_err = |frame: &[u8], r: &[u8; 32], d: &[u8; 32], now: u64| {
            let mut cc = RevocationCache::new();
            matches!(
                verify_listener_hello(frame, r, d, now, &mut cc),
                Err(Error::Verify(_))
            )
        };
        let mut wrong_dev = d;
        wrong_dev[0] ^= 1;
        assert!(verify_err(&hello, &r, &wrong_dev, NOW));
        let mut wrong_root = r;
        wrong_root[0] ^= 1;
        assert!(verify_err(&hello, &wrong_root, &d, NOW));
        // Expired.
        assert!(verify_err(&hello, &r, &d, FAR + 1));
        // Cert not signed by the stated root.
        let mut forged = creds_with(&root, FAR);
        forged.root = id().public().clone();
        let (fr, fd) = ids(&forged);
        assert!(verify_err(&encode_listener_hello(&forged), &fr, &fd, NOW));
        // Revoked by its own included list.
        let mut revoked = creds_with(&root, FAR);
        revoked.revocation = Some(
            root.revoke_devices(1, 0, &[revoked.device.peer_id()])
                .unwrap(),
        );
        let (rr, rd) = ids(&revoked);
        assert!(verify_err(&encode_listener_hello(&revoked), &rr, &rd, NOW));
        // Oversized, wrong tag, trailing garbage.
        assert!(verify_err(&vec![LISTENER_HELLO; MAX_LISTENER_HELLO_LEN + 1], &r, &d, NOW));
        let mut bad_tag = hello.clone();
        bad_tag[0] = 0;
        assert!(verify_err(&bad_tag, &r, &d, NOW));
        let mut trailing = hello.clone();
        trailing.push(0);
        assert!(verify_err(&trailing, &r, &d, NOW));
    }

    #[tokio::test]
    async fn bad_hello_leaves_kept_untouched() {
        let (alice, bob, a, _b) = genuine();
        let imposter = creds();
        let mut k = Some(a);
        // The listener answers with a hello for someone other than the ticket's peer.
        let (dial, mut listen) = pair().await;
        listen
            .send(&encode_listener_hello(&imposter))
            .await
            .unwrap();
        let c = cache();
        let r = dial_to(dial, &alice, &bob, &mut k, &bnd(), &c).await;
        assert!(matches!(r, Err(Error::Verify(_))));
        assert!(k.is_some());

        // Oversized hello.
        let (dial, mut listen) = pair().await;
        listen
            .send(&vec![LISTENER_HELLO; MAX_LISTENER_HELLO_LEN + 1])
            .await
            .unwrap();
        let r = dial_to(dial, &alice, &bob, &mut k, &bnd(), &c).await;
        assert!(matches!(r, Err(Error::Verify(_))));
        assert!(k.is_some());
    }

    #[tokio::test]
    async fn dialer_sends_nothing_before_the_hello_check_passes() {
        let (alice, bob) = (creds(), creds());
        // (a) same root, different device than the ticket names.
        let root = id();
        let named = creds_with(&root, FAR);
        let other_device = creds_with(&root, FAR);
        let (tr, td) = ids(&named);
        let hello_a = encode_listener_hello(&other_device);
        // (b) the right device, but the ticket names a different root.
        let (_, bd) = ids(&bob);
        let wrong_root = id().peer_id().0;
        let hello_b = encode_listener_hello(&bob);

        for (hello, ticket_root, ticket_device) in [(hello_a, tr, td), (hello_b, wrong_root, bd)] {
            let (dial, mut listen) = pair().await;
            listen.send(&hello).await.unwrap();
            listen.send(&[DECISION_FRESH]).await.unwrap();
            let mut k = None;
            let c = cache();
            let r = negotiate_dial(
                dial,
                &alice,
                &ticket_root,
                &ticket_device,
                &mut k,
                &bnd(),
                NOW,
                &c,
            )
            .await;
            assert!(matches!(r, Err(Error::Verify(_))));
            // The dialer end is dropped now: exactly the preamble was sent.
            let first = tokio::time::timeout(MEDIUM, listen.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(first[0], WIRE_VERSION);
            let next = tokio::time::timeout(MEDIUM, listen.recv()).await.unwrap();
            assert!(next.is_err());
        }
    }

    // ---- negotiation timeouts, busy reply ----

    #[test]
    fn negotiation_constants() {
        assert_eq!(NEGOTIATION_TIMEOUT, Duration::from_secs(15));
        assert_eq!(WIRE_VERSION, 2);
        assert_eq!((MODE_FRESH, MODE_RESUME), (0, 1));
        assert_eq!(
            (DECISION_FRESH, DECISION_RESUMED, DECISION_CHALLENGE, DECISION_BUSY, DECISION_VERSION),
            (0, 1, 2, 3, 4)
        );
        assert_eq!(LISTENER_HELLO, 5);
        assert_eq!(MAX_CACHED_ROOTS, 256);
        assert_eq!(MAX_PREAMBLE_LEN, 8 * 1024);
        assert_eq!(MAX_LISTENER_HELLO_LEN, 60 * 1024);
        assert_eq!(MAX_AUTH_BUNDLE_LEN, 60 * 1024);
        assert_eq!((NONCE_LEN, TAG_LEN), (32, 32));
        assert_eq!(CB_DOMAIN, b"lattice-net-cb-v1");
        assert_eq!(VERSION_ERR_MARK, "wire version");
        assert_eq!(DEVICE_CERT_LIFETIME, Duration::from_secs(30 * 24 * 3600));
        assert_eq!(DEVICE_RENEW_WINDOW, Duration::from_secs(7 * 24 * 3600));
        assert_eq!(MAX_LIVE_INBOUND, 8);
    }

    #[tokio::test]
    async fn silent_dialer_times_out_and_keeps_sessions() {
        let (alice, bob) = (creds(), creds());
        let sessions = stale(&alice, &bob);
        let (_dial, listen) = pair().await;
        let c = cache();
        let r = accept_within_limit(listen, &bob, &sessions, &c, &bnd(), SHORT).await;
        assert!(matches!(r, Err(Error::Transport(_))));
        assert_eq!(lock(&sessions).len(), 1);
        assert!(has(&sessions, &alice.device.peer_id()));
    }

    #[tokio::test]
    async fn resume_without_tag_times_out_and_session_still_resumes() {
        let (alice, bob, a, b) = genuine();
        let sessions = kept_map(&alice, b);
        let (mut eve, listen) = pair().await;
        eve.send(&resume_preamble(&[7u8; NONCE_LEN], &alice.device))
            .await
            .unwrap();
        let c = cache();
        let r = accept_within_limit(listen, &bob, &sessions, &c, &bnd(), SHORT).await;
        assert!(matches!(r, Err(Error::Transport(_))));
        assert!(has(&sessions, &alice.device.peer_id()));
        drop(eve);

        // A genuine resume on a new pair still works.
        let mut k = Some(a);
        let (dial, listen) = pair().await;
        let bd = bnd();
        let ca = cache();
        let (d, l) = tokio::join!(
            dial_to(dial, &alice, &bob, &mut k, &bd, &ca),
            accept(listen, &bob, &sessions, &bd, NOW, &c)
        );
        assert!(d.is_ok());
        assert!(l.is_ok());
    }

    #[tokio::test]
    async fn fresh_without_msg1_times_out_and_keeps_sessions() {
        let (alice, bob) = (creds(), creds());
        let sessions = stale(&alice, &bob);
        let (mut dial, listen) = pair().await;
        preamble(&mut dial, MODE_FRESH, &alice.device).await;
        let c = cache();
        let r = accept_within_limit(listen, &bob, &sessions, &c, &bnd(), SHORT).await;
        assert!(matches!(r, Err(Error::Transport(_))));
        assert_eq!(lock(&sessions).len(), 1);
        assert!(has(&sessions, &alice.device.peer_id()));
    }

    #[tokio::test]
    async fn handshake_without_auth_bundle_times_out_and_keeps_sessions() {
        let (alice, bob) = (creds(), creds());
        let sessions = stale(&alice, &bob);
        let (mut dial, listen) = pair().await;
        preamble(&mut dial, MODE_FRESH, &alice.device).await;
        let bd = bnd();
        let script = async {
            let _ = dial.recv().await.unwrap();
            let _ = dial.recv().await.unwrap();
            let _cs = ConnectedSession::initiate(dial, &alice.device, bob.device.public(), &bd)
                .await
                .unwrap();
            // Handshake done; never send the auth bundle.
            std::future::pending::<()>().await;
        };
        let c = cache();
        let r = tokio::select! {
            r = accept_within_limit(listen, &bob, &sessions, &c, &bd, MEDIUM) => r,
            _ = script => unreachable!(),
        };
        assert!(matches!(r, Err(Error::Transport(_))));
        assert_eq!(lock(&sessions).len(), 1);
        assert!(has(&sessions, &alice.device.peer_id()));
    }

    #[tokio::test]
    async fn silent_listener_times_out_and_keeps_kept() {
        let (alice, bob, a, _b) = genuine();
        let mut k = Some(a);
        let (dial, _listen) = pair().await;
        let (r, d) = ids(&bob);
        let c = cache();
        let res = negotiate_dial_within(dial, &alice, &r, &d, &mut k, &bnd(), NOW, &c, SHORT).await;
        assert!(matches!(res, Err(Error::Transport(_))));
        assert!(k.is_some());
    }

    #[tokio::test]
    async fn listener_silent_after_hello_times_out_and_keeps_kept() {
        let (alice, bob, a, _b) = genuine();
        let mut k = Some(a);
        let (dial, mut listen) = pair().await;
        listen.send(&encode_listener_hello(&bob)).await.unwrap();
        let (r, d) = ids(&bob);
        let c = cache();
        let res = negotiate_dial_within(dial, &alice, &r, &d, &mut k, &bnd(), NOW, &c, SHORT).await;
        assert!(matches!(res, Err(Error::Transport(_))));
        assert!(k.is_some());
    }

    #[tokio::test]
    async fn listener_silent_at_auth_bundle_times_out_dialer_side() {
        let (alice, bob) = (creds(), creds());
        let (dial, mut listen) = pair().await;
        let bd = bnd();
        let hello = encode_listener_hello(&bob);
        let script = async {
            let p = listen.recv().await.unwrap();
            let who = PublicIdentity::from_bytes(&p[2 + NONCE_LEN..]).unwrap();
            listen.send(&hello).await.unwrap();
            listen.send(&[DECISION_FRESH]).await.unwrap();
            let _cs = ConnectedSession::accept(listen, &bob.device, &who, &bd)
                .await
                .unwrap();
            // Handshake done; never send our bundle.
            std::future::pending::<()>().await;
        };
        let (r, d) = ids(&bob);
        let mut k = None;
        let c = cache();
        let res = tokio::select! {
            res = negotiate_dial_within(dial, &alice, &r, &d, &mut k, &bd, NOW, &c, MEDIUM) => res,
            _ = script => unreachable!(),
        };
        assert!(matches!(res, Err(Error::Transport(_))));
        assert!(k.is_none());
    }

    #[tokio::test]
    async fn busy_listener_is_an_error_and_keeps_kept() {
        let (alice, bob, a, _b) = genuine();
        let mut k = Some(a);
        let (dial, mut listen) = pair().await;
        listen.send(&[DECISION_BUSY]).await.unwrap();
        let c = cache();
        let r = dial_to(dial, &alice, &bob, &mut k, &bnd(), &c).await;
        match r {
            Err(e) => {
                assert!(matches!(&e, Error::Transport(m) if m == BUSY_ERR));
                assert_eq!(classify_failure(&e), FailureKind::Busy);
            }
            Ok(_) => panic!("busy accepted"),
        }
        assert!(k.is_some());

        let (dial, mut listen) = pair().await;
        listen.send(&[DECISION_BUSY]).await.unwrap();
        let (r, d) = ids(&bob);
        let res = negotiate_dial_within(dial, &alice, &r, &d, &mut k, &bnd(), NOW, &c, SHORT).await;
        assert!(matches!(res, Err(Error::Transport(_))));
        assert!(k.is_some());

        let mut none = None;
        let (dial, mut listen) = pair().await;
        listen.send(&[DECISION_BUSY]).await.unwrap();
        let r = dial_to(dial, &alice, &bob, &mut none, &bnd(), &c).await;
        assert!(matches!(r, Err(Error::Transport(_))));
        assert!(none.is_none());
    }

    #[tokio::test]
    async fn busy_as_decision_after_hello_is_busy_and_keeps_kept() {
        let (alice, bob, a, _b) = genuine();
        let mut k = Some(a);
        let (dial, mut listen) = pair().await;
        listen.send(&encode_listener_hello(&bob)).await.unwrap();
        listen.send(&[DECISION_BUSY]).await.unwrap();
        let c = cache();
        let r = dial_to(dial, &alice, &bob, &mut k, &bnd(), &c).await;
        match r {
            Err(e) => assert_eq!(classify_failure(&e), FailureKind::Busy),
            Ok(_) => panic!("busy accepted"),
        }
        assert!(k.is_some());
    }

    #[tokio::test]
    async fn reply_busy_sends_one_byte_and_closes() {
        let alice = creds();
        let (mut dial, listen) = pair().await;
        preamble(&mut dial, MODE_FRESH, &alice.device).await; // stays unread
        reply_busy(listen).await.unwrap();
        assert_eq!(dial.recv().await.unwrap(), [DECISION_BUSY]);
        assert!(dial.recv().await.is_err());
    }

    #[test]
    fn classify_failure_maps_kinds() {
        let v = Error::Verify(format!("listener speaks lattice-net {VERSION_ERR_MARK} 9"));
        assert_eq!(classify_failure(&v), FailureKind::Version);
        assert_eq!(classify_failure(&Error::Transport(BUSY_ERR.into())), FailureKind::Busy);
        assert_eq!(classify_failure(&Error::Verify("bad proof".into())), FailureKind::Auth);
        assert_eq!(classify_failure(&Error::Transport("timed out".into())), FailureKind::Other);
        assert_eq!(classify_failure(&Error::Other("x".into())), FailureKind::Other);
        assert_eq!(classify_failure(&Error::Verify(BUSY_ERR.into())), FailureKind::Auth);
    }

    #[test]
    fn lock_recovers_from_poison() {
        let m = Arc::new(Mutex::new(5u8));
        let m2 = Arc::clone(&m);
        let _ = std::thread::spawn(move || {
            let _g = m2.lock().unwrap();
            panic!("poison the mutex");
        })
        .join();
        assert!(m.is_poisoned());
        assert_eq!(*lock(&m), 5);
    }

    // ---- bounded accept path ----

    fn sem(n: usize) -> Arc<tokio::sync::Semaphore> {
        Arc::new(tokio::sync::Semaphore::new(n))
    }

    #[test]
    fn listener_limits_are_set() {
        assert_eq!(MAX_BUSY_REPLIES, 8);
        assert_eq!(MAX_PENDING_ACCEPTS, 8);
        assert_eq!(NEGOTIATION_TIMEOUT, Duration::from_secs(15));
    }

    #[test]
    fn flood_limits_are_set() {
        assert_eq!(RESERVED_VERIFIED_SLOTS, 2);
        const { assert!(RESERVED_VERIFIED_SLOTS < MAX_PENDING_ACCEPTS) };
        assert_eq!(PROVISIONAL_HANDSHAKE_TIMEOUT, Duration::from_secs(5));
        assert!(PROVISIONAL_HANDSHAKE_TIMEOUT < NEGOTIATION_TIMEOUT);
        assert_eq!((SOURCE_BURST, SOURCE_REFILL), (4, Duration::from_secs(2)));
        assert_eq!(
            (RELAYED_BURST, RELAYED_REFILL),
            (16, Duration::from_millis(250))
        );
        assert_eq!(
            (ENDPOINT_BURST, ENDPOINT_REFILL),
            (4, Duration::from_secs(2))
        );
        assert_eq!(
            (GLOBAL_ACCEPT_BURST, GLOBAL_ACCEPT_REFILL),
            (32, Duration::from_millis(50))
        );
        assert_eq!(MAX_FAILURES_BEFORE_BAN, 8);
        assert_eq!(FAILURE_WINDOW, Duration::from_secs(60));
        assert_eq!(BAN_DURATION, Duration::from_secs(300));
        assert_eq!(MAX_TRACKED_SOURCES, 4096);
        assert_eq!(MAX_TRACKED_ENDPOINTS, 4096);
        assert_eq!(MAX_VERIFIED_ENDPOINTS, 256);
        assert_eq!(MAX_ENDPOINTS_PER_VERIFIED_ROOT, 4);
        assert_eq!(DROP_WARN_INTERVAL, Duration::from_secs(10));
        let l = listener_limits();
        assert_eq!(l.source.burst, SOURCE_BURST);
        assert_eq!(l.source.refill_every, SOURCE_REFILL);
        assert_eq!(l.shared_source.burst, RELAYED_BURST);
        assert_eq!(l.endpoint.burst, ENDPOINT_BURST);
        assert_eq!(l.global.burst, GLOBAL_ACCEPT_BURST);
        assert_eq!(l.global.refill_every, GLOBAL_ACCEPT_REFILL);
        assert_eq!(l.ban.max_failures, MAX_FAILURES_BEFORE_BAN);
        assert_eq!(l.ban.window, FAILURE_WINDOW);
        assert_eq!(l.ban.ban_for, BAN_DURATION);
        assert_eq!(l.max_sources, MAX_TRACKED_SOURCES);
        assert_eq!(l.max_endpoints, MAX_TRACKED_ENDPOINTS);
        assert_eq!(l.max_verified, MAX_VERIFIED_ENDPOINTS);
        assert_eq!(l.max_verified_per_root, MAX_ENDPOINTS_PER_VERIFIED_ROOT);
        assert_eq!(l.warn_interval, DROP_WARN_INTERVAL);
    }

    // ---- spawn_admitted ----

    type TestGuard = Mutex<flood::FloodGuard<flood::FakeClock, SourceKey, [u8; 32], PeerId>>;

    fn test_guard(l: flood::Limits) -> TestGuard {
        Mutex::new(flood::FloodGuard::new(flood::FakeClock::new(), l))
    }

    fn src1() -> SourceKey {
        SourceKey::V4(Ipv4Addr::new(1, 2, 3, 4))
    }

    /// Try to admit with a `make` that records whether it was called.
    fn try_admit(
        guard: &TestGuard,
        pool: &Arc<flood::SlotPool>,
        src: &SourceKey,
    ) -> (
        std::result::Result<JoinHandle<u8>, flood::DropReason>,
        bool,
    ) {
        let called = Arc::new(AtomicBool::new(false));
        let flag = called.clone();
        let r = spawn_admitted(guard, pool, src, move |slot| {
            flag.store(true, Ordering::SeqCst);
            async move {
                let _slot = slot;
                std::future::pending::<u8>().await
            }
        });
        (r, called.load(Ordering::SeqCst))
    }

    #[tokio::test]
    async fn over_limit_path_spawns_nothing() {
        // source banned
        let guard = test_guard(listener_limits());
        let pool = flood::SlotPool::new(MAX_PENDING_ACCEPTS, RESERVED_VERIFIED_SLOTS);
        for _ in 0..MAX_FAILURES_BEFORE_BAN {
            lock(&guard).record_failure(&src1(), None);
        }
        let (r, called) = try_admit(&guard, &pool, &src1());
        assert_eq!(r.err(), Some(flood::DropReason::SourceBanned));
        assert!(!called);
        assert_eq!(pool.in_use(), (0, 0));

        // source rate-limited
        let mut l = listener_limits();
        l.source.burst = 1;
        let guard = test_guard(l);
        let (first, called) = try_admit(&guard, &pool, &src1());
        let first = first.expect("first attempt admitted");
        assert!(called);
        assert_eq!(pool.in_use(), (1, 0));
        let (r, called) = try_admit(&guard, &pool, &src1());
        assert_eq!(r.err(), Some(flood::DropReason::SourceRateLimited));
        assert!(!called);
        assert_eq!(pool.in_use(), (1, 0));
        first.abort();
        let _ = first.await;
        assert_eq!(pool.in_use(), (0, 0));

        // global bucket empty
        let mut l = listener_limits();
        l.global.burst = 0;
        let guard = test_guard(l);
        let (r, called) = try_admit(&guard, &pool, &src1());
        assert_eq!(r.err(), Some(flood::DropReason::GlobalRateLimited));
        assert!(!called);
        assert_eq!(pool.in_use(), (0, 0));

        // no free slot
        let guard = test_guard(listener_limits());
        let tiny = flood::SlotPool::new(1, 0);
        let (held, _) = try_admit(&guard, &tiny, &src1());
        let held = held.expect("one slot free");
        let (r, called) = try_admit(&guard, &tiny, &src1());
        assert_eq!(r.err(), Some(flood::DropReason::NoSlot));
        assert!(!called);
        assert_eq!(tiny.in_use(), (1, 0));
        held.abort();
        let _ = held.await;
        assert_eq!(tiny.in_use(), (0, 0));
    }

    #[tokio::test]
    async fn admitted_path_runs_make_once_and_releases_slot() {
        let guard = test_guard(listener_limits());
        let pool = flood::SlotPool::new(MAX_PENDING_ACCEPTS, RESERVED_VERIFIED_SLOTS);
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let h = spawn_admitted(&guard, &pool, &src1(), move |slot| {
            c.fetch_add(1, Ordering::SeqCst);
            async move {
                let _slot = slot;
                7u8
            }
        })
        .expect("admitted");
        assert_eq!(h.await.unwrap(), 7);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(pool.in_use(), (0, 0));
    }

    #[tokio::test]
    async fn spawn_admitted_with_hands_out_the_drop_summary() {
        let mut l = listener_limits();
        l.global.burst = 0;
        let guard = test_guard(l);
        let pool = flood::SlotPool::new(MAX_PENDING_ACCEPTS, RESERVED_VERIFIED_SLOTS);
        let mut line = None;
        let r = spawn_admitted_with(
            &guard,
            &pool,
            &src1(),
            |l| line = Some(l),
            |slot| async move {
                let _slot = slot;
            },
        );
        assert_eq!(r.err(), Some(flood::DropReason::GlobalRateLimited));
        let line = line.expect("first drop produces a summary line");
        assert!(line.contains("dropped 1 incoming connection(s)"), "{line}");
        assert!(line.contains("global_rate_limited=1"), "{line}");
        // Within the interval the next drop is only counted.
        let mut again = None;
        let _ = spawn_admitted_with(&guard, &pool, &src1(), |l| again = Some(l), |slot| async move {
            let _slot = slot;
        });
        assert!(again.is_none());
    }

    #[test]
    fn source_key_maps_addresses() {
        let direct = |s: &str| IncomingSource::Direct(s.parse().unwrap());
        assert_eq!(
            source_key(direct("1.2.3.4:5")),
            SourceKey::V4(Ipv4Addr::new(1, 2, 3, 4))
        );
        assert_eq!(
            source_key(direct("[::ffff:1.2.3.4]:5")),
            SourceKey::V4(Ipv4Addr::new(1, 2, 3, 4))
        );
        let a = source_key(direct("[2001:db8:1:2:aaaa::1]:5"));
        let b = source_key(direct("[2001:db8:1:2:bbbb::9]:7"));
        let c = source_key(direct("[2001:db8:1:3::1]:5"));
        assert_eq!(
            a,
            SourceKey::V6Prefix([0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02])
        );
        assert_eq!(a, b);
        assert_ne!(a, c);
        for s in [IncomingSource::Relayed, IncomingSource::Unknown] {
            let k = source_key(s);
            assert_eq!(k, SourceKey::Relayed);
            assert!(flood::SourceKind::is_shared(&k));
        }
        assert!(!flood::SourceKind::is_shared(&a));
    }

    #[tokio::test]
    async fn spawn_bounded_without_permit_never_polls() {
        let (mut dial, listen) = pair().await;
        let polled = Arc::new(AtomicBool::new(false));
        let flag = polled.clone();
        let s = sem(0);
        let h = spawn_bounded(&s, async move {
            flag.store(true, Ordering::SeqCst);
            let _own = listen;
        });
        assert!(h.is_none());
        assert!(!polled.load(Ordering::SeqCst));
        // The owned connection was dropped: the peer sees a closed channel.
        assert!(dial.recv().await.is_err());
    }

    #[tokio::test]
    async fn spawn_bounded_caps_tasks_and_releases_on_abort() {
        const N: usize = 3;
        let s = sem(N);
        let mut handles = Vec::new();
        for _ in 0..N {
            let h = spawn_bounded(&s, std::future::pending::<()>());
            handles.push(h.expect("permit available"));
        }
        assert!(spawn_bounded(&s, std::future::pending::<()>()).is_none());
        for h in &handles {
            h.abort();
        }
        for h in handles {
            let _ = h.await;
        }
        assert_eq!(s.available_permits(), N);
    }

    #[tokio::test]
    async fn spawn_bounded_releases_permit_on_completion() {
        let s = sem(2);
        let h = spawn_bounded(&s, async { 7 }).unwrap();
        assert_eq!(h.await.unwrap(), 7);
        assert_eq!(s.available_permits(), 2);
    }

    #[tokio::test]
    async fn accept_within_times_out() {
        let r = tokio::time::timeout(
            Duration::from_secs(5),
            accept_within(SHORT, std::future::pending::<Result<()>>()),
        )
        .await
        .expect("accept_within must not hang");
        assert!(matches!(r, Err(Error::Transport(_))));
    }

    #[tokio::test]
    async fn accept_within_passes_results_through() {
        assert_eq!(accept_within(SHORT, async { Ok(5) }).await.unwrap(), 5);
        let r = accept_within(SHORT, async { Err::<(), _>(Error::Verify("x".into())) }).await;
        assert!(matches!(r, Err(Error::Verify(_))));
    }

    #[tokio::test]
    async fn pending_accept_does_not_block_another() {
        let s = sem(2);
        let a = spawn_bounded(
            &s,
            accept_within(SHORT, std::future::pending::<Result<()>>()),
        )
        .unwrap();
        let b = spawn_bounded(&s, accept_within(SHORT, async { Ok(()) })).unwrap();
        // B finishes while A is still waiting for its timeout.
        assert!(b.await.unwrap().is_ok());
        assert!(matches!(a.await.unwrap(), Err(Error::Transport(_))));
        assert_eq!(s.available_permits(), 2);
    }

    // ---- channel binding ----

    #[test]
    fn channel_binding_layout_and_asymmetry() {
        let (d, l) = ([1u8; 32], [2u8; 32]);
        let b = channel_binding(&d, &l);
        assert!(b.starts_with(b"lattice-net-cb-v1"));
        assert_eq!(b.len(), 81);
        assert_eq!(&b[17..49], &d);
        assert_eq!(&b[49..], &l);
        assert_ne!(channel_binding(&l, &d), b);
        let mut d2 = d;
        d2[0] ^= 1;
        let mut l2 = l;
        l2[31] ^= 1;
        assert_ne!(channel_binding(&d2, &l), b);
        assert_ne!(channel_binding(&d, &l2), b);
    }

    #[test]
    fn check_endpoint_matches_only_equal_ids() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert!(check_endpoint(&a, &a).is_ok());
        assert!(matches!(check_endpoint(&a, &b), Err(Error::Verify(_))));
    }

    // ---- revocation cache ----

    #[test]
    fn cache_observe_rules() {
        let root = id();
        let mut cc = RevocationCache::new();
        let l1 = root.revoke_devices(1, 0, &[PeerId([1; 32])]).unwrap();
        let l1b = root.revoke_devices(1, 5, &[PeerId([2; 32])]).unwrap();
        let l2 = root.revoke_devices(2, 0, &[PeerId([3; 32])]).unwrap();
        let l0 = root.revoke_devices(0, 0, &[]).unwrap();
        assert!(cc.observe(l1));
        assert!(!cc.observe(l1b), "equal seq: first one wins");
        assert!(!cc.observe(l0));
        assert!(cc.revokes(&root.peer_id(), &PeerId([1; 32])));
        assert!(cc.observe(l2));
        assert!(!cc.revokes(&root.peer_id(), &PeerId([1; 32])));
        assert!(cc.revokes(&root.peer_id(), &PeerId([3; 32])));
        assert_eq!(cc.get(&root.peer_id()).unwrap().seq(), 2);
        assert_eq!(cc.len(), 1);
    }

    #[test]
    fn cache_is_bounded_but_accepts_newer_for_known_roots() {
        let mut cc = RevocationCache::new();
        let first = Keypair::generate(CryptoSuite::Classical).unwrap();
        assert!(cc.observe(first.revoke_devices(1, 0, &[]).unwrap()));
        for _ in 1..MAX_CACHED_ROOTS {
            let k = Keypair::generate(CryptoSuite::Classical).unwrap();
            assert!(cc.observe(k.revoke_devices(1, 0, &[]).unwrap()));
        }
        let extra = Keypair::generate(CryptoSuite::Classical).unwrap();
        assert!(!cc.observe(extra.revoke_devices(1, 0, &[]).unwrap()));
        assert!(cc.get(&extra.peer_id()).is_none());
        assert!(cc.observe(first.revoke_devices(2, 0, &[]).unwrap()));
        assert_eq!(cc.len(), MAX_CACHED_ROOTS);
    }

    // ---- expiry policy ----

    #[test]
    fn cert_status_boundaries() {
        let (na, w) = (10_000u64, 100u64);
        assert_eq!(cert_status(na, na, w), CertStatus::RenewSoon);
        assert_eq!(cert_status(na + 1, na, w), CertStatus::Expired);
        assert_eq!(cert_status(na - w, na, w), CertStatus::RenewSoon);
        assert_eq!(cert_status(na - w - 1, na, w), CertStatus::Valid);
    }

    // ---- kept sessions ----

    fn pidn(n: u8) -> PeerId {
        PeerId([n; 32])
    }

    #[test]
    fn kept_sessions_evict_least_recently_used() {
        let mut s: KeptSessions<u8> = KeptSessions::with_cap(4);
        let mut evicted = Vec::new();
        for n in 1..=6u8 {
            evicted.extend(s.insert(pidn(n), n));
        }
        assert_eq!(s.len(), 4);
        assert_eq!(evicted, vec![pidn(1), pidn(2)]);
        assert!(!s.contains_key(&pidn(1)) && !s.contains_key(&pidn(2)));
        assert!((3..=6).all(|n| s.contains_key(&pidn(n))));
        // Re-inserting 3 refreshes it; inserting 7 then evicts 4, not 3.
        assert!(s.insert(pidn(3), 33).is_empty());
        assert_eq!(s.get(&pidn(3)), Some(&33));
        assert_eq!(s.insert(pidn(7), 7), vec![pidn(4)]);
        assert!(s.contains_key(&pidn(3)));
        assert_eq!(s.remove(&pidn(3)), Some(33));
        assert!(!s.is_empty());
    }

    #[test]
    fn kept_sessions_production_cap() {
        assert_eq!(MAX_KEPT_SESSIONS, 64);
        let mut s = KeptSessions::<u8>::new();
        assert_eq!(s.cap, 64);
        for n in 0..(MAX_KEPT_SESSIONS + 10) as u8 {
            s.insert(pidn(n), n);
        }
        assert_eq!(s.len(), MAX_KEPT_SESSIONS);
        for n in 0..(MAX_KEPT_SESSIONS + 10) as u8 {
            assert_eq!(s.contains_key(&pidn(n)), n >= 10, "{n}");
        }
    }
}
