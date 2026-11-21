import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:lattice_node/src/peer_text.dart';
import 'package:lattice_node/src/widgets/peer_trust_card.dart';

// 10 groups of 4 hex.
const _fingerprint = '0a1b 2c3d 4e5f 6071 8293 a4b5 c6d7 e8f9 0123 4567';
// 12 groups of 5 digits.
const _safety =
    '12345 67890 11223 34455 66778 89900 13579 24680 97531 86420 11111 22222';
const _peer = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';

Future<void> _pump(WidgetTester tester, Size size) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1.0;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  await tester.pumpWidget(
    const MaterialApp(
      home: Scaffold(
        body: SingleChildScrollView(
          child: Padding(
            padding: EdgeInsets.all(16),
            child: PeerTrustCard(
              peerIdHex: _peer,
              rootFingerprint: _fingerprint,
              safetyNumber: _safety,
            ),
          ),
        ),
      ),
    ),
  );
  await tester.pump();
}

void main() {
  for (final (name, size) in const [
    ('desktop 1280x720', Size(1280, 720)),
    ('phone 375x640', Size(375, 640)),
  ]) {
    testWidgets('PeerTrustCard shows everything in full at $name', (tester) async {
      await _pump(tester, size);

      // No overflow / layout exceptions were thrown.
      expect(tester.takeException(), isNull);

      // Full root fingerprint (all 10 groups) and full safety number (all 12).
      expect(find.text(_fingerprint), findsOneWidget);
      expect(find.text(_safety), findsOneWidget);
      expect(_fingerprint.split(' ').length, 10);
      expect(_safety.split(' ').length, 12);
      expect(find.text(kUnverifiedPeer), findsOneWidget);

      // Short device id is shown, never the full 64 chars.
      expect(find.textContaining('abcdef01'), findsOneWidget);

      // Nothing is truncated or ellipsized.
      for (final t in tester.widgetList<Text>(find.byType(Text))) {
        expect(t.overflow == null || t.overflow == TextOverflow.clip || t.overflow == TextOverflow.visible, isTrue,
            reason: 'Text "${t.data}" must not use ellipsis/fade');
        expect(t.maxLines, isNull, reason: 'Text "${t.data}" must not be line-limited');
      }
      for (final e in tester.renderObjectList<RenderParagraph>(find.byType(RichText))) {
        expect(e.didExceedMaxLines, isFalse);
      }

      // Everything fits horizontally in the viewport.
      final card = tester.getRect(find.byType(PeerTrustCard));
      expect(card.left, greaterThanOrEqualTo(0));
      expect(card.right, lessThanOrEqualTo(size.width));
      for (final s in [_fingerprint, _safety, kUnverifiedPeer]) {
        final r = tester.getRect(find.text(s));
        expect(r.right, lessThanOrEqualTo(size.width), reason: s);
        expect(r.left, greaterThanOrEqualTo(0), reason: s);
      }
    });
  }

  testWidgets('PeerTrustCard has no "mark verified" action', (tester) async {
    await _pump(tester, const Size(375, 640));
    expect(find.byType(ElevatedButton), findsNothing);
    expect(find.byType(TextButton), findsNothing);
    expect(find.byType(OutlinedButton), findsNothing);
    expect(find.byType(FilledButton), findsNothing);
    expect(find.textContaining(RegExp('mark verified', caseSensitive: false)), findsNothing);
  });
}
