import 'package:flutter_test/flutter_test.dart';
import 'package:lattice_node/src/peer_text.dart';
import 'package:lattice_node/src/rust/api/node.dart';

void main() {
  const peer = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

  test('constants carry the agreed wording', () {
    expect(kUnverifiedPeer, 'Unverified — compare the safety number out of band');
    expect(kVersionMismatch, 'The peer runs an incompatible Lattice version');
  });

  test('AuthFailed starts with "Authentication failed" and includes the message', () {
    final t = failureText(const LatticeEvent.authFailed(peerIdHex: peer, message: 'bad cert chain'));
    expect(t, isNotNull);
    expect(t, startsWith('Authentication failed'));
    expect(t, contains('bad cert chain'));
  });

  test('AuthFailed with an empty peer id (unattributed) still reads well', () {
    final t = failureText(const LatticeEvent.authFailed(peerIdHex: '', message: 'forged'));
    expect(t, startsWith('Authentication failed'));
    expect(t, contains('forged'));
  });

  test('VersionMismatch contains kVersionMismatch', () {
    final t = failureText(const LatticeEvent.versionMismatch(peerIdHex: peer, message: 'wire version 3'));
    expect(t, isNotNull);
    expect(t, contains(kVersionMismatch));
  });

  test('PeerBusy says busy and that the app is retrying', () {
    final t = failureText(const LatticeEvent.peerBusy(peerIdHex: peer));
    expect(t, isNotNull);
    expect(t!.toLowerCase(), contains('busy'));
    expect(t.toLowerCase(), contains('retrying'));
  });

  test('BadTicket mentions the ticket and asks for a new one', () {
    final t = failureText(const LatticeEvent.badTicket(message: 'old ticket version 2'));
    expect(t, isNotNull);
    expect(t!.toLowerCase(), contains('ticket'));
    expect(t.toLowerCase(), contains('new ticket'));
    expect(t, contains('old ticket version 2'));
  });

  test('the four failure texts are distinct', () {
    final texts = <String?>[
      failureText(const LatticeEvent.authFailed(peerIdHex: peer, message: 'm')),
      failureText(const LatticeEvent.versionMismatch(peerIdHex: peer, message: 'm')),
      failureText(const LatticeEvent.peerBusy(peerIdHex: peer)),
      failureText(const LatticeEvent.badTicket(message: 'm')),
    ];
    expect(texts.every((t) => t != null && t.isNotEmpty), isTrue);
    expect(texts.toSet().length, 4);
  });

  test('null for Message, Listening and PeerConnected (and other events)', () {
    expect(failureText(const LatticeEvent.message(peerIdHex: peer, body: 'hi')), isNull);
    expect(failureText(const LatticeEvent.listening(ticket: 'abcd')), isNull);
    expect(
      failureText(const LatticeEvent.peerConnected(
        peerIdHex: peer,
        rootFingerprint: 'aaaa bbbb',
        safetyNumber: '11111 22222',
      )),
      isNull,
    );
    expect(
      failureText(const LatticeEvent.resumed(
        peerIdHex: peer,
        rootFingerprint: 'aaaa bbbb',
        safetyNumber: '11111 22222',
      )),
      isNull,
    );
    expect(failureText(const LatticeEvent.listeningStopped()), isNull);
    expect(failureText(const LatticeEvent.reconnecting(peerIdHex: peer)), isNull);
    expect(failureText(const LatticeEvent.peerDisconnected(peerIdHex: peer)), isNull);
    expect(failureText(const LatticeEvent.error(message: 'x')), isNull);
    expect(failureText(const LatticeEvent.link(peerIdHex: peer, direct: true, rttMs: 5)), isNull);
  });
}
