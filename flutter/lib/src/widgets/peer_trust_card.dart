import 'package:flutter/material.dart';

import '../peer_text.dart';
import '../theme.dart';

/// Trust details for one connected peer: its short device id, the peer's ROOT
/// fingerprint and the safety number of both roots, always marked unverified
/// (compare out of band; nothing is verified automatically).
///
/// Every value is shown in full and wraps across lines on narrow screens —
/// nothing is truncated or ellipsized. Uses platform monospace fonts (no
/// runtime font fetching) so it renders the same in widget tests.
class PeerTrustCard extends StatelessWidget {
  const PeerTrustCard({
    super.key,
    required this.peerIdHex,
    required this.rootFingerprint,
    required this.safetyNumber,
  });

  /// The peer's DEVICE PeerId hex (the session key).
  final String peerIdHex;

  /// The peer's ROOT fingerprint (10 groups of 4 hex).
  final String rootFingerprint;

  /// The safety number of both roots (12 groups of 5 digits).
  final String safetyNumber;

  static TextStyle _mono(double size, Color color, {FontWeight weight = FontWeight.w500}) =>
      TextStyle(
        fontFamily: 'monospace',
        fontFamilyFallback: const ['Menlo', 'Consolas', 'Roboto Mono'],
        fontSize: size,
        color: color,
        fontWeight: weight,
        letterSpacing: 0.2,
        height: 1.35,
      );

  Widget _label(String text) => Padding(
        padding: const EdgeInsets.only(top: 10, bottom: 4),
        child: Text(
          text.toUpperCase(),
          style: _mono(10.5, Lx.muted, weight: FontWeight.w700).copyWith(letterSpacing: 1.4),
        ),
      );

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: Lx.raised,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: Lx.line),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Icon(Icons.shield_outlined, size: 18, color: Lx.violet),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  'Peer ${shortPeerId(peerIdHex)}',
                  style: _mono(12.5, Lx.text, weight: FontWeight.w700),
                ),
              ),
            ],
          ),
          _label('Root fingerprint'),
          Text(rootFingerprint, softWrap: true, style: _mono(14, Lx.violet)),
          _label('Safety number'),
          Text(safetyNumber, softWrap: true, style: _mono(14, Lx.text)),
          const SizedBox(height: 10),
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Icon(Icons.warning_amber_rounded, size: 16, color: Lx.amber),
              const SizedBox(width: 6),
              Expanded(
                child: Text(
                  kUnverifiedPeer,
                  softWrap: true,
                  style: const TextStyle(color: Lx.amber, fontSize: 12.5, height: 1.35),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}
