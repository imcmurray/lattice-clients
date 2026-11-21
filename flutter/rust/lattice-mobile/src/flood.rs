// Copied from Lattice ece4d2d `examples/chat/src/bin/lattice-net/flood.rs`
// (lattice-net connection-flood limiter); keep in sync.

//! Connection-flood limiter for the `lattice-net` listener.
//!
//! Pure and `std`-only: no iroh, tokio or lattice types. It is generic over a
//! [`Clock`] and over the source / endpoint / root key types, so it is tested
//! with a fake clock. Pieces:
//!
//! * [`TokenBucket`] — integer milli-token bucket, no floating point.
//! * [`KeyedLimiter`] — bounded per-key buckets, failure counting and bans.
//! * [`VerifiedEndpoints`] — bounded memory of endpoint ids that authenticated
//!   with a verified root.
//! * [`DropLog`] — aggregates dropped attempts into one summary per interval.
//! * [`FloodGuard`] — the above combined in the order the listener needs.
//! * [`SlotPool`] — pending-accept slots, some reserved for verified peers.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// Lock a std mutex, recovering the data if another thread panicked.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Clocks
// ---------------------------------------------------------------------------

/// Monotonic time since an arbitrary origin.
pub(crate) trait Clock: Send {
    fn now(&self) -> Duration;
}

/// `Instant`-based clock (never goes backwards, unaffected by wall-clock jumps).
pub(crate) struct MonotonicClock {
    start: Instant,
}

impl MonotonicClock {
    pub(crate) fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for MonotonicClock {
    fn now(&self) -> Duration {
        self.start.elapsed()
    }
}

/// Test clock advanced by hand.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct FakeClock(Arc<std::sync::atomic::AtomicU64>);

#[cfg(test)]
impl FakeClock {
    pub(crate) fn new() -> Self {
        Self(Arc::new(std::sync::atomic::AtomicU64::new(0)))
    }

    pub(crate) fn advance(&self, d: Duration) {
        self.0
            .fetch_add(d.as_millis() as u64, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
impl Clock for FakeClock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}

// ---------------------------------------------------------------------------
// Token bucket
// ---------------------------------------------------------------------------

const MILLI: u64 = 1000;

#[derive(Clone, Copy, Debug)]
pub(crate) struct BucketParams {
    /// Capacity in tokens; also the initial fill. 0 never allows.
    pub burst: u32,
    /// One token is added per this much time. Zero means always full.
    pub refill_every: Duration,
}

/// Integer token bucket (state in milli-tokens).
pub(crate) struct TokenBucket {
    milli: u64,
    last: Duration,
}

impl TokenBucket {
    pub(crate) fn full(p: &BucketParams, now: Duration) -> Self {
        Self {
            milli: u64::from(p.burst) * MILLI,
            last: now,
        }
    }

    /// Refill (integer arithmetic, capped at `burst`), then take one token if available.
    pub(crate) fn try_take(&mut self, p: &BucketParams, now: Duration) -> bool {
        let cap = u64::from(p.burst) * MILLI;
        if p.refill_every.is_zero() {
            self.milli = cap;
        } else if now > self.last {
            let elapsed = (now - self.last).as_nanos();
            let add = elapsed * u128::from(MILLI) / p.refill_every.as_nanos();
            self.milli = u128::from(self.milli)
                .saturating_add(add)
                .min(u128::from(cap)) as u64;
            self.last = now;
        }
        if self.milli >= MILLI {
            self.milli -= MILLI;
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Keyed limiter
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub(crate) struct BanParams {
    pub max_failures: u32,
    pub window: Duration,
    pub ban_for: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Allowed,
    RateLimited,
    Banned,
}

struct Entry {
    bucket: TokenBucket,
    last_seen: Duration,
    failures: u32,
    window_start: Duration,
    banned_until: Option<Duration>,
}

impl Entry {
    fn banned(&self, now: Duration) -> bool {
        self.banned_until.is_some_and(|until| until > now)
    }
}

/// Bounded per-key buckets + failure counting + bans; least-recently-seen eviction.
pub(crate) struct KeyedLimiter<K> {
    bucket: BucketParams,
    ban: BanParams,
    cap: usize,
    map: HashMap<K, Entry>,
}

impl<K: Hash + Eq + Clone> KeyedLimiter<K> {
    pub(crate) fn new(bucket: BucketParams, ban: BanParams, cap: usize) -> Self {
        Self {
            bucket,
            ban,
            cap: cap.max(1),
            map: HashMap::new(),
        }
    }

    /// Get or create the entry for `key`, evicting the least recently seen
    /// entry first if the table is full. Refreshes `last_seen`.
    fn touch(&mut self, key: &K, now: Duration) -> &mut Entry {
        if !self.map.contains_key(key) {
            if self.map.len() >= self.cap {
                let oldest = self
                    .map
                    .iter()
                    .min_by_key(|(_, e)| e.last_seen)
                    .map(|(k, _)| k.clone());
                if let Some(k) = oldest {
                    self.map.remove(&k);
                }
            }
            self.map.insert(
                key.clone(),
                Entry {
                    bucket: TokenBucket::full(&self.bucket, now),
                    last_seen: now,
                    failures: 0,
                    window_start: now,
                    banned_until: None,
                },
            );
        }
        let e = self.map.get_mut(key).expect("entry present");
        e.last_seen = now;
        e
    }

    pub(crate) fn check(&mut self, key: &K, now: Duration) -> Verdict {
        let params = self.bucket;
        let e = self.touch(key, now);
        if e.banned(now) {
            Verdict::Banned
        } else if e.bucket.try_take(&params, now) {
            Verdict::Allowed
        } else {
            Verdict::RateLimited
        }
    }

    pub(crate) fn is_banned(&self, key: &K, now: Duration) -> bool {
        self.map.get(key).is_some_and(|e| e.banned(now))
    }

    /// Count a failure; true iff this call started a ban.
    pub(crate) fn record_failure(&mut self, key: &K, now: Duration) -> bool {
        let ban = self.ban;
        let e = self.touch(key, now);
        if e.banned(now) {
            return false;
        }
        if now.saturating_sub(e.window_start) > ban.window {
            e.failures = 0;
            e.window_start = now;
        }
        e.failures = e.failures.saturating_add(1);
        if e.failures >= ban.max_failures {
            e.banned_until = Some(now.saturating_add(ban.ban_for));
            e.failures = 0;
            true
        } else {
            false
        }
    }

    /// Clear failures and any ban (does not create an entry).
    pub(crate) fn record_success(&mut self, key: &K) {
        if let Some(e) = self.map.get_mut(key) {
            e.failures = 0;
            e.banned_until = None;
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    pub(crate) fn contains(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }
}

// ---------------------------------------------------------------------------
// Verified endpoints
// ---------------------------------------------------------------------------

/// Endpoint ids recently seen for verified roots. Bounded globally and per root.
pub(crate) struct VerifiedEndpoints<E, R> {
    map: HashMap<E, (R, Duration)>,
    cap: usize,
    per_root: usize,
}

impl<E: Hash + Eq + Clone, R: Eq + Clone> VerifiedEndpoints<E, R> {
    pub(crate) fn new(cap: usize, per_root: usize) -> Self {
        Self {
            map: HashMap::new(),
            cap: cap.max(1),
            per_root: per_root.max(1),
        }
    }

    /// Record `ep` as verified for `root`. Re-noting refreshes `last_seen` and root.
    pub(crate) fn note(&mut self, ep: E, root: R, now: Duration) {
        self.map.remove(&ep);
        let same_root = self.map.iter().filter(|(_, (r, _))| *r == root);
        if same_root.clone().count() >= self.per_root {
            let oldest = same_root
                .min_by_key(|(_, (_, seen))| *seen)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                self.map.remove(&k);
            }
        }
        if self.map.len() >= self.cap {
            let oldest = self
                .map
                .iter()
                .min_by_key(|(_, (_, seen))| *seen)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                self.map.remove(&k);
            }
        }
        self.map.insert(ep, (root, now));
    }

    pub(crate) fn is_verified(&self, ep: &E) -> bool {
        self.map.contains_key(ep)
    }

    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }
}

// ---------------------------------------------------------------------------
// Drop log
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum DropReason {
    SourceBanned,
    SourceRateLimited,
    GlobalRateLimited,
    NoSlot,
    EndpointBanned,
    EndpointRateLimited,
    StrangerInReservedSlot,
    Failed,
}

impl DropReason {
    const ALL: [DropReason; 8] = [
        DropReason::SourceBanned,
        DropReason::SourceRateLimited,
        DropReason::GlobalRateLimited,
        DropReason::NoSlot,
        DropReason::EndpointBanned,
        DropReason::EndpointRateLimited,
        DropReason::StrangerInReservedSlot,
        DropReason::Failed,
    ];

    fn index(self) -> usize {
        Self::ALL.iter().position(|r| *r == self).unwrap_or(0)
    }

    fn name(self) -> &'static str {
        match self {
            DropReason::SourceBanned => "source_banned",
            DropReason::SourceRateLimited => "source_rate_limited",
            DropReason::GlobalRateLimited => "global_rate_limited",
            DropReason::NoSlot => "no_free_slot",
            DropReason::EndpointBanned => "endpoint_banned",
            DropReason::EndpointRateLimited => "endpoint_rate_limited",
            DropReason::StrangerInReservedSlot => "stranger_in_reserved_slot",
            DropReason::Failed => "handshake_failed",
        }
    }
}

/// Aggregated, rate-limited drop warning.
pub(crate) struct DropLog {
    counts: [u64; 8],
    last_print: Option<Duration>,
    interval: Duration,
}

impl DropLog {
    pub(crate) fn new(interval: Duration) -> Self {
        Self {
            counts: [0; 8],
            last_print: None,
            interval,
        }
    }

    /// Count `reason`; returns `Some(summary line)` iff nothing was printed yet
    /// or `now >= last_print + interval`. The summary covers every count since
    /// the last line (including this one) and resets them.
    pub(crate) fn record(&mut self, reason: DropReason, now: Duration) -> Option<String> {
        self.counts[reason.index()] += 1;
        let due = match self.last_print {
            None => true,
            Some(last) => now >= last.saturating_add(self.interval),
        };
        if !due {
            return None;
        }
        let window = self
            .last_print
            .map_or(Duration::ZERO, |l| now.saturating_sub(l));
        let total: u64 = self.counts.iter().sum();
        let parts: Vec<String> = DropReason::ALL
            .iter()
            .filter(|r| self.counts[r.index()] > 0)
            .map(|r| format!("{}={}", r.name(), self.counts[r.index()]))
            .collect();
        self.counts = [0; 8];
        self.last_print = Some(now);
        Some(format!(
            "[lattice-net] ⚠ dropped {total} incoming connection(s) in the last {}s: {}",
            window.as_secs(),
            parts.join(", ")
        ))
    }

    /// Counted but not yet reported.
    pub(crate) fn pending(&self) -> u64 {
        self.counts.iter().sum()
    }
}

// ---------------------------------------------------------------------------
// Flood guard
// ---------------------------------------------------------------------------

/// Is this source key shared by many unrelated peers (e.g. "relayed")?
pub(crate) trait SourceKind {
    fn is_shared(&self) -> bool;
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub source: BucketParams,
    pub shared_source: BucketParams,
    pub endpoint: BucketParams,
    pub global: BucketParams,
    pub ban: BanParams,
    pub max_sources: usize,
    pub max_endpoints: usize,
    pub max_verified: usize,
    pub max_verified_per_root: usize,
    pub warn_interval: Duration,
}

pub(crate) struct FloodGuard<C: Clock, S, E, R> {
    clock: C,
    shared_params: BucketParams,
    global_params: BucketParams,
    sources: KeyedLimiter<S>,
    shared: TokenBucket,
    endpoints: KeyedLimiter<E>,
    global: TokenBucket,
    verified: VerifiedEndpoints<E, R>,
    drops: DropLog,
}

impl<C: Clock, S: Hash + Eq + Clone + SourceKind, E: Hash + Eq + Clone, R: Eq + Clone>
    FloodGuard<C, S, E, R>
{
    pub(crate) fn new(clock: C, limits: Limits) -> Self {
        let now = clock.now();
        Self {
            shared_params: limits.shared_source,
            global_params: limits.global,
            sources: KeyedLimiter::new(limits.source, limits.ban, limits.max_sources),
            shared: TokenBucket::full(&limits.shared_source, now),
            endpoints: KeyedLimiter::new(limits.endpoint, limits.ban, limits.max_endpoints),
            global: TokenBucket::full(&limits.global, now),
            verified: VerifiedEndpoints::new(limits.max_verified, limits.max_verified_per_root),
            drops: DropLog::new(limits.warn_interval),
            clock,
        }
    }

    /// Before the QUIC handshake. Order: (non-shared) source ban → source bucket
    /// (shared keys: the single shared bucket) → global bucket.
    pub(crate) fn admit_source(&mut self, src: &S) -> Result<(), DropReason> {
        let now = self.clock.now();
        if src.is_shared() {
            if !self.shared.try_take(&self.shared_params, now) {
                return Err(DropReason::SourceRateLimited);
            }
        } else {
            match self.sources.check(src, now) {
                Verdict::Allowed => {}
                Verdict::Banned => return Err(DropReason::SourceBanned),
                Verdict::RateLimited => return Err(DropReason::SourceRateLimited),
            }
        }
        if self.global.try_take(&self.global_params, now) {
            Ok(())
        } else {
            Err(DropReason::GlobalRateLimited)
        }
    }

    /// After `finish` (endpoint id known). Order: endpoint ban → endpoint bucket.
    /// `Ok(true)` iff `ep` is a recorded verified endpoint.
    pub(crate) fn admit_endpoint(&mut self, ep: &E) -> Result<bool, DropReason> {
        let now = self.clock.now();
        match self.endpoints.check(ep, now) {
            Verdict::Allowed => Ok(self.verified.is_verified(ep)),
            Verdict::Banned => Err(DropReason::EndpointBanned),
            Verdict::RateLimited => Err(DropReason::EndpointRateLimited),
        }
    }

    pub(crate) fn is_verified(&self, ep: &E) -> bool {
        self.verified.is_verified(ep)
    }

    /// Failure of handshake/accept/negotiation. Shared source keys are never
    /// failure-tracked or banned.
    pub(crate) fn record_failure(&mut self, src: &S, ep: Option<&E>) {
        let now = self.clock.now();
        if !src.is_shared() {
            self.sources.record_failure(src, now);
        }
        if let Some(ep) = ep {
            self.endpoints.record_failure(ep, now);
        }
    }

    /// Successful auth: clear failures/bans for `src` (non-shared) and `ep`; if
    /// `verified_root` is `Some`, note `ep` as verified for that root.
    pub(crate) fn record_success(&mut self, src: &S, ep: &E, verified_root: Option<R>) {
        let now = self.clock.now();
        if !src.is_shared() {
            self.sources.record_success(src);
        }
        self.endpoints.record_success(ep);
        if let Some(root) = verified_root {
            self.verified.note(ep.clone(), root, now);
        }
    }

    /// Count a drop; `Some(line)` when the rate-limited summary is due.
    pub(crate) fn note_drop(&mut self, reason: DropReason) -> Option<String> {
        let now = self.clock.now();
        self.drops.record(reason, now)
    }

    pub(crate) fn sources_len(&self) -> usize {
        self.sources.len()
    }

    pub(crate) fn endpoints_len(&self) -> usize {
        self.endpoints.len()
    }
}

// ---------------------------------------------------------------------------
// Slot pool
// ---------------------------------------------------------------------------

/// Pending-accept slots: `total`, of which `reserved` only verified peers may keep.
pub(crate) struct SlotPool {
    general_cap: usize,
    reserved_cap: usize,
    in_use: Mutex<(usize, usize)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SlotKind {
    General,
    Reserved,
}

/// A held slot; dropping it releases it.
pub(crate) struct Slot {
    pool: Arc<SlotPool>,
    kind: SlotKind,
}

impl SlotPool {
    /// `reserved` is clamped to `total`.
    pub(crate) fn new(total: usize, reserved: usize) -> Arc<Self> {
        let reserved_cap = reserved.min(total);
        Arc::new(Self {
            general_cap: total - reserved_cap,
            reserved_cap,
            in_use: Mutex::new((0, 0)),
        })
    }

    /// A general slot if one is free; else a reserved slot (provisional); else `None`.
    pub(crate) fn try_acquire(self: &Arc<Self>) -> Option<Slot> {
        let mut g = lock(&self.in_use);
        let kind = if g.0 < self.general_cap {
            g.0 += 1;
            SlotKind::General
        } else if g.1 < self.reserved_cap {
            g.1 += 1;
            SlotKind::Reserved
        } else {
            return None;
        };
        Some(Slot {
            pool: self.clone(),
            kind,
        })
    }

    /// `(general, reserved)` slots currently held.
    pub(crate) fn in_use(&self) -> (usize, usize) {
        *lock(&self.in_use)
    }
}

impl Slot {
    pub(crate) fn kind(&self) -> SlotKind {
        self.kind
    }

    /// After the endpoint id is known: a Reserved slot held by a non-verified
    /// peer is released and `None` is returned; otherwise the slot is returned.
    pub(crate) fn classify(self, verified: bool) -> Option<Slot> {
        if self.kind == SlotKind::Reserved && !verified {
            None // `self` drops here and frees the reserved slot
        } else {
            Some(self)
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut g = lock(&self.pool.in_use);
        match self.kind {
            SlotKind::General => g.0 = g.0.saturating_sub(1),
            SlotKind::Reserved => g.1 = g.1.saturating_sub(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn bp(burst: u32, every_ms: u64) -> BucketParams {
        BucketParams {
            burst,
            refill_every: ms(every_ms),
        }
    }

    fn bans(max_failures: u32) -> BanParams {
        BanParams {
            max_failures,
            window: ms(60_000),
            ban_for: ms(300_000),
        }
    }

    // ---- 1, 2: bucket ----

    #[test]
    fn bucket_allows_exactly_burst() {
        let p = bp(3, 1000);
        let mut b = TokenBucket::full(&p, ms(0));
        for _ in 0..3 {
            assert!(b.try_take(&p, ms(0)));
        }
        assert!(!b.try_take(&p, ms(0)));
    }

    #[test]
    fn bucket_refills_one_per_interval_and_caps() {
        let p = bp(3, 1000);
        let mut b = TokenBucket::full(&p, ms(0));
        for _ in 0..3 {
            assert!(b.try_take(&p, ms(0)));
        }
        assert!(!b.try_take(&p, ms(999)));
        assert!(b.try_take(&p, ms(1000)));
        assert!(!b.try_take(&p, ms(1000)));
        // a long wait restores at most `burst`
        let mut taken = 0;
        while b.try_take(&p, ms(11_000)) {
            taken += 1;
            assert!(taken <= 3);
        }
        assert_eq!(taken, 3);
    }

    #[test]
    fn bucket_edge_cases() {
        let none = bp(0, 1000);
        let mut b = TokenBucket::full(&none, ms(0));
        assert!(!b.try_take(&none, ms(10_000)));
        let always = bp(1, 0);
        let mut b = TokenBucket::full(&always, ms(0));
        assert!(b.try_take(&always, ms(0)));
        assert!(b.try_take(&always, ms(0)));
        // time going backwards refills nothing
        let p = bp(1, 1000);
        let mut b = TokenBucket::full(&p, ms(5000));
        assert!(b.try_take(&p, ms(5000)));
        assert!(!b.try_take(&p, ms(1000)));
    }

    // ---- 3: per key ----

    #[test]
    fn limiter_rate_limits_per_key() {
        let mut l = KeyedLimiter::new(bp(2, 1000), bans(5), 10);
        assert_eq!(l.check(&"a", ms(0)), Verdict::Allowed);
        assert_eq!(l.check(&"a", ms(0)), Verdict::Allowed);
        assert_eq!(l.check(&"a", ms(0)), Verdict::RateLimited);
        assert_eq!(l.check(&"b", ms(0)), Verdict::Allowed);
    }

    // ---- 4–7: bans ----

    #[test]
    fn ban_after_k_failures_consumes_no_token() {
        let mut l = KeyedLimiter::new(bp(2, 1000), bans(3), 10);
        assert!(!l.record_failure(&"a", ms(0)));
        assert!(!l.record_failure(&"a", ms(1)));
        assert!(!l.is_banned(&"a", ms(2)));
        assert!(l.record_failure(&"a", ms(2)));
        assert!(l.is_banned(&"a", ms(3)));
        assert_eq!(l.check(&"a", ms(3)), Verdict::Banned);
        assert_eq!(l.check(&"a", ms(4)), Verdict::Banned);
        // After the ban the full burst is still there.
        let after = ms(2 + 300_000);
        assert_eq!(l.check(&"a", after), Verdict::Allowed);
        assert_eq!(l.check(&"a", after), Verdict::Allowed);
        assert_eq!(l.check(&"a", after), Verdict::RateLimited);
    }

    #[test]
    fn ban_expires_exactly_at_ban_for() {
        let mut l = KeyedLimiter::new(bp(5, 1000), bans(1), 10);
        assert!(l.record_failure(&"a", ms(1000)));
        assert!(l.is_banned(&"a", ms(1000 + 300_000 - 1)));
        assert!(!l.is_banned(&"a", ms(1000 + 300_000)));
        assert_eq!(l.check(&"a", ms(1000 + 300_000)), Verdict::Allowed);
    }

    #[test]
    fn failure_window_resets() {
        let mut l = KeyedLimiter::new(bp(5, 1000), bans(3), 10);
        assert!(!l.record_failure(&"a", ms(0)));
        assert!(!l.record_failure(&"a", ms(1)));
        assert!(!l.record_failure(&"a", ms(60_002)));
        assert!(!l.is_banned(&"a", ms(60_003)));
    }

    #[test]
    fn success_clears_failures_and_bans() {
        let mut l = KeyedLimiter::new(bp(5, 1000), bans(3), 10);
        l.record_failure(&"a", ms(0));
        l.record_failure(&"a", ms(1));
        l.record_success(&"a");
        assert!(!l.record_failure(&"a", ms(2)));
        assert!(!l.record_failure(&"a", ms(3)));
        assert!(!l.is_banned(&"a", ms(4)));
        assert!(l.record_failure(&"a", ms(4)));
        assert!(l.is_banned(&"a", ms(5)));
        l.record_success(&"a");
        assert!(!l.is_banned(&"a", ms(5)));
    }

    // ---- 8: bounded table ----

    #[test]
    fn table_is_bounded_with_lru_eviction() {
        const N: usize = 4;
        let mut l = KeyedLimiter::new(bp(5, 1000), bans(3), N);
        for k in 0..N as u32 {
            l.check(&k, ms(u64::from(k)));
        }
        // refresh key 0 so it is no longer the least recently seen
        l.check(&0, ms(10));
        for (i, k) in (N as u32..N as u32 + 2).enumerate() {
            l.check(&k, ms(20 + i as u64));
        }
        assert_eq!(l.len(), N);
        assert!(l.contains(&0), "recently seen key kept");
        assert!(!l.contains(&1) && !l.contains(&2), "oldest evicted");
        assert!(l.contains(&3) && l.contains(&(N as u32 + 1)));
        // record_failure on a new key also respects the cap
        l.record_failure(&99, ms(100));
        assert_eq!(l.len(), N);
        assert!(l.contains(&99));
    }

    // ---- 9: verified endpoints ----

    #[test]
    fn verified_endpoints_bounds() {
        let mut v: VerifiedEndpoints<u32, u8> = VerifiedEndpoints::new(5, 2);
        v.note(1, 1, ms(1));
        v.note(2, 1, ms(2));
        v.note(10, 2, ms(3));
        assert!(v.is_verified(&1) && v.is_verified(&2) && v.is_verified(&10));
        assert!(!v.is_verified(&3));
        // third endpoint for root 1 evicts root 1's oldest, not root 2's
        v.note(3, 1, ms(4));
        assert!(!v.is_verified(&1));
        assert!(v.is_verified(&2) && v.is_verified(&3) && v.is_verified(&10));
        // re-noting refreshes
        v.note(2, 1, ms(5));
        v.note(4, 1, ms(6));
        assert!(v.is_verified(&2) && v.is_verified(&4) && !v.is_verified(&3));
        // global cap
        for i in 0..20u32 {
            v.note(100 + i, (i % 10) as u8 + 10, ms(10 + u64::from(i)));
        }
        assert_eq!(v.len(), 5);
        assert!(v.is_verified(&119));
    }

    // ---- 10, 11: slots ----

    fn full_general(pool: &Arc<SlotPool>) -> Vec<Slot> {
        (0..6)
            .map(|_| {
                let s = pool.try_acquire().unwrap();
                assert_eq!(s.kind(), SlotKind::General);
                s
            })
            .collect()
    }

    #[test]
    fn reserved_slots_not_kept_by_strangers() {
        let pool = SlotPool::new(8, 2);
        let general = full_general(&pool);
        let r1 = pool.try_acquire().unwrap();
        let r2 = pool.try_acquire().unwrap();
        assert_eq!(r1.kind(), SlotKind::Reserved);
        assert_eq!(r2.kind(), SlotKind::Reserved);
        assert!(pool.try_acquire().is_none());
        assert_eq!(pool.in_use(), (6, 2));
        assert!(r1.classify(false).is_none());
        assert_eq!(pool.in_use(), (6, 1));
        assert!(r2.classify(false).is_none());
        assert_eq!(pool.in_use(), (6, 0));
        // a general slot is kept even for a stranger
        let mut it = general.into_iter();
        let g = it.next().unwrap().classify(false).unwrap();
        assert_eq!(g.kind(), SlotKind::General);
        assert_eq!(pool.in_use(), (6, 0));
    }

    #[test]
    fn reserved_slots_kept_by_verified_and_drop_releases_kind() {
        let pool = SlotPool::new(8, 2);
        let general = full_general(&pool);
        let r = pool.try_acquire().unwrap();
        let r = r.classify(true).expect("verified keeps reserved");
        assert_eq!(r.kind(), SlotKind::Reserved);
        assert_eq!(pool.in_use(), (6, 1));
        drop(r);
        assert_eq!(pool.in_use(), (6, 0));
        drop(general);
        assert_eq!(pool.in_use(), (0, 0));
        assert_eq!(SlotPool::new(2, 5).in_use(), (0, 0));
        let clamped = SlotPool::new(2, 5);
        assert_eq!(clamped.try_acquire().unwrap().kind(), SlotKind::Reserved);
    }

    // ---- 12, 13: guard ----

    #[derive(Clone, PartialEq, Eq, Hash, Debug)]
    enum K {
        Ip(u32),
        Shared,
    }

    impl SourceKind for K {
        fn is_shared(&self) -> bool {
            matches!(self, K::Shared)
        }
    }

    fn limits(global: BucketParams, source: BucketParams, max_failures: u32) -> Limits {
        Limits {
            source,
            shared_source: bp(2, 1000),
            endpoint: bp(2, 1000),
            global,
            ban: bans(max_failures),
            max_sources: 100,
            max_endpoints: 100,
            max_verified: 10,
            max_verified_per_root: 2,
            warn_interval: ms(10_000),
        }
    }

    type G = FloodGuard<FakeClock, K, u32, u8>;

    #[test]
    fn global_cap_limits_across_many_sources() {
        let clock = FakeClock::new();
        let mut g: G = FloodGuard::new(clock.clone(), limits(bp(3, 1000), bp(5, 1000), 5));
        let ok = (0..10)
            .filter(|i| g.admit_source(&K::Ip(*i)).is_ok())
            .count();
        assert_eq!(ok, 3);
        assert_eq!(
            g.admit_source(&K::Ip(50)),
            Err(DropReason::GlobalRateLimited)
        );
        clock.advance(ms(1000));
        assert!(g.admit_source(&K::Ip(51)).is_ok());
        assert_eq!(
            g.admit_source(&K::Ip(52)),
            Err(DropReason::GlobalRateLimited)
        );
    }

    #[test]
    fn check_order_source_before_global_and_shared_never_banned() {
        let clock = FakeClock::new();
        let mut g: G = FloodGuard::new(clock.clone(), limits(bp(3, 1000), bp(1, 1000), 2));
        let a = K::Ip(1);
        g.record_failure(&a, None);
        g.record_failure(&a, None);
        assert_eq!(g.admit_source(&a), Err(DropReason::SourceBanned));
        assert_eq!(g.admit_source(&K::Ip(2)), Ok(()));
        assert_eq!(
            g.admit_source(&K::Ip(2)),
            Err(DropReason::SourceRateLimited)
        );
        // neither refusal consumed a global token: two more sources still fit
        assert_eq!(g.admit_source(&K::Ip(3)), Ok(()));
        assert_eq!(g.admit_source(&K::Ip(4)), Ok(()));
        assert_eq!(
            g.admit_source(&K::Ip(5)),
            Err(DropReason::GlobalRateLimited)
        );

        // shared key: failures never ban it; the shared bucket limits it
        let mut g: G = FloodGuard::new(clock, limits(bp(100, 1000), bp(1, 1000), 2));
        for _ in 0..100 {
            g.record_failure(&K::Shared, None);
        }
        assert_eq!(g.sources_len(), 0, "shared keys are not failure-tracked");
        assert_eq!(g.admit_source(&K::Shared), Ok(()));
        assert_eq!(g.admit_source(&K::Shared), Ok(()));
        assert_eq!(
            g.admit_source(&K::Shared),
            Err(DropReason::SourceRateLimited)
        );
    }

    #[test]
    fn endpoint_admission_verification_and_bans() {
        let clock = FakeClock::new();
        let mut g: G = FloodGuard::new(clock.clone(), limits(bp(100, 1000), bp(5, 1000), 2));
        assert_eq!(g.admit_endpoint(&7), Ok(false));
        g.record_success(&K::Ip(1), &7, Some(9));
        assert!(g.is_verified(&7));
        assert_eq!(g.admit_endpoint(&7), Ok(true));
        assert_eq!(g.admit_endpoint(&7), Err(DropReason::EndpointRateLimited));
        g.record_failure(&K::Ip(1), Some(&8));
        g.record_failure(&K::Ip(1), Some(&8));
        assert_eq!(g.admit_endpoint(&8), Err(DropReason::EndpointBanned));
        assert_eq!(g.endpoints_len(), 2);
        // success without a verified root does not verify
        g.record_success(&K::Ip(1), &8, None);
        assert!(!g.is_verified(&8));
        assert_eq!(g.admit_endpoint(&8), Ok(false));
    }

    // ---- 14: drop log ----

    #[test]
    fn drop_log_aggregates() {
        let mut d = DropLog::new(ms(10_000));
        let mut lines = 0;
        for i in 0..1000 {
            let r = if i % 2 == 0 {
                DropReason::NoSlot
            } else {
                DropReason::Failed
            };
            if d.record(r, ms(0)).is_some() {
                lines += 1;
                assert_eq!(i, 0, "only the first record prints");
            }
        }
        assert_eq!(lines, 1);
        assert_eq!(d.pending(), 999);
        assert!(d.record(DropReason::NoSlot, ms(9_999)).is_none());
        let line = d.record(DropReason::GlobalRateLimited, ms(10_000)).unwrap();
        assert!(
            line.contains("dropped 1001 incoming connection(s)"),
            "{line}"
        );
        assert!(line.contains("global_rate_limited=1"), "{line}");
        assert!(!line.contains("source_banned"), "{line}");
        assert_eq!(d.pending(), 0);
        assert!(d.record(DropReason::Failed, ms(10_001)).is_none());
        assert_eq!(d.pending(), 1);
    }
}
