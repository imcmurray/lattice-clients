// User-readable texts for peer trust and connection-failure events. Pure Dart:
// no widgets, no native calls (constructing `LatticeEvent` values needs no
// `RustLib.init`).
import 'rust/api/node.dart';

/// Shown next to every connected peer: nothing is verified automatically.
const String kUnverifiedPeer = 'Unverified — compare the safety number out of band';

/// The core of the wire-version-mismatch text.
const String kVersionMismatch = 'The peer runs an incompatible Lattice version';

/// A short, readable form of a hex peer id: the first 8 hex chars plus "…".
String shortPeerId(String hex) => hex.length <= 12 ? hex : '${hex.substring(0, 8)}…';

/// User-readable console text for AuthFailed / VersionMismatch / PeerBusy /
/// BadTicket; null for any other event.
String? failureText(LatticeEvent e) => switch (e) {
      LatticeEvent_AuthFailed(:final peerIdHex, :final message) =>
        'Authentication failed${_who(peerIdHex)}: $message',
      LatticeEvent_VersionMismatch(:final peerIdHex, :final message) =>
        '$kVersionMismatch${_who(peerIdHex)} — update both apps ($message)',
      LatticeEvent_PeerBusy(:final peerIdHex) =>
        'The peer${_who(peerIdHex)} is busy — retrying automatically with backoff',
      LatticeEvent_BadTicket(:final message) =>
        'That ticket cannot be used ($message) — ask your peer for a new ticket',
      _ => null,
    };

String _who(String peerIdHex) => peerIdHex.isEmpty ? '' : ' · ${shortPeerId(peerIdHex)}';
