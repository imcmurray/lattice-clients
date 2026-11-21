import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../peer_text.dart';
import '../rust/api/node.dart';
import '../services.dart';
import '../theme.dart';
import '../validation.dart';
import 'app_controller.dart';

enum LogKind { info, signal, peer, message, error }

class LogLine {
  LogLine(this.kind, this.text, this.at);
  final LogKind kind;
  final String text;
  final DateTime at;

  Color get color => switch (kind) {
        LogKind.signal => Lx.teal,
        LogKind.peer => Lx.violet,
        LogKind.message => Lx.text,
        LogKind.error => Lx.danger,
        LogKind.info => Lx.muted,
      };
}

/// Live link health for one peer: direct-vs-relay path and RTT (ms).
class PeerLink {
  const PeerLink({required this.direct, this.rttMs});
  final bool direct;
  final int? rttMs;
}

/// What the user can compare out of band for one connected peer: the peer's
/// ROOT fingerprint and the safety number of both roots. Never auto-verified
/// and never persisted.
class PeerTrust {
  const PeerTrust({required this.rootFingerprint, required this.safetyNumber});
  final String rootFingerprint;
  final String safetyNumber;
}

class DashboardState {
  const DashboardState({
    this.listening = false,
    this.ticket,
    this.peers = const <String>{},
    this.links = const <String, PeerLink>{},
    this.trust = const <String, PeerTrust>{},
    this.log = const <LogLine>[],
  });

  final bool listening;
  final String? ticket;

  /// Connected peers by DEVICE PeerId hex (the session key used by `send`).
  final Set<String> peers;
  final Map<String, PeerLink> links;

  /// Trust details per connected peer (DEVICE PeerId hex); removed on disconnect.
  final Map<String, PeerTrust> trust;
  final List<LogLine> log;

  DashboardState copyWith({
    bool? listening,
    String? ticket,
    Set<String>? peers,
    Map<String, PeerLink>? links,
    Map<String, PeerTrust>? trust,
    List<LogLine>? log,
  }) =>
      DashboardState(
        listening: listening ?? this.listening,
        ticket: ticket ?? this.ticket,
        peers: peers ?? this.peers,
        links: links ?? this.links,
        trust: trust ?? this.trust,
        log: log ?? this.log,
      );
}

final dashboardProvider =
    NotifierProvider<DashboardController, DashboardState>(DashboardController.new);

class DashboardController extends Notifier<DashboardState> {
  Node? _node;

  @override
  DashboardState build() {
    final stage = ref.watch(appControllerProvider);
    if (stage is! StageUnlocked) {
      _node = null;
      return const DashboardState();
    }
    _node = stage.node;
    final sub = stage.node.events().listen(_onEvent);
    ref.onDispose(sub.cancel);
    // Seed the console via the returned state — `state` isn't readable until
    // build() returns, so we can't call _log() here.
    return DashboardState(
      log: [LogLine(LogKind.info, 'Identity loaded · ${stage.identity.fingerprint}', DateTime.now())],
    );
  }

  void _onEvent(LatticeEvent e) {
    switch (e) {
      case LatticeEvent_Listening(:final ticket):
        state = state.copyWith(listening: true, ticket: ticket);
        _log(LogKind.signal, 'Online · accepting connections');
        _syncForegroundService();
      case LatticeEvent_ListeningStopped():
        state = state.copyWith(listening: false);
        _log(LogKind.signal, 'Stopped listening');
        _syncForegroundService();
      case LatticeEvent_PeerConnected(
          :final peerIdHex,
          :final rootFingerprint,
          :final safetyNumber,
        ):
        state = state.copyWith(
          peers: {...state.peers, peerIdHex},
          trust: {
            ...state.trust,
            peerIdHex: PeerTrust(rootFingerprint: rootFingerprint, safetyNumber: safetyNumber),
          },
        );
        _log(
          LogKind.peer,
          'Secure session up · ${_short(peerIdHex)} · root $rootFingerprint · '
          'safety number $safetyNumber (unverified)',
        );
        _syncForegroundService();
        NotificationService.notifyBackground(
            'Peer connected', '${_short(peerIdHex)} · secure session up');
      case LatticeEvent_Resumed(
          :final peerIdHex,
          :final rootFingerprint,
          :final safetyNumber,
        ):
        state = state.copyWith(trust: {
          ...state.trust,
          peerIdHex: PeerTrust(rootFingerprint: rootFingerprint, safetyNumber: safetyNumber),
        });
        _log(LogKind.signal, 'Resumed without re-handshake · ${_short(peerIdHex)}');
      case LatticeEvent_Reconnecting(:final peerIdHex):
        _log(LogKind.info, 'Reconnecting to ${_short(peerIdHex)}…');
      case LatticeEvent_Link(:final peerIdHex, :final direct, :final rttMs):
        state = state.copyWith(links: {
          ...state.links,
          peerIdHex: PeerLink(direct: direct, rttMs: rttMs),
        });
      case LatticeEvent_PeerDisconnected(:final peerIdHex):
        state = state.copyWith(
          peers: {...state.peers}..remove(peerIdHex),
          links: {...state.links}..remove(peerIdHex),
          trust: {...state.trust}..remove(peerIdHex),
        );
        _log(LogKind.peer, 'Session closed · ${_short(peerIdHex)}');
        _syncForegroundService();
      case LatticeEvent_Message(:final peerIdHex, :final body):
        _log(LogKind.message, '${_short(peerIdHex)} » $body');
        NotificationService.notifyBackground('Message · ${_short(peerIdHex)}', body);
      case LatticeEvent_AuthFailed() ||
            LatticeEvent_VersionMismatch() ||
            LatticeEvent_PeerBusy() ||
            LatticeEvent_BadTicket():
        _log(LogKind.error, failureText(e) ?? e.toString());
      case LatticeEvent_Error(:final message):
        _log(LogKind.error, message);
    }
  }

  void toggleListen() {
    final node = _node;
    if (node == null) return;
    if (state.listening) {
      node.stopListening();
    } else {
      _log(LogKind.info, 'Going online (contacting relay)…');
      node.startListening();
    }
    // FGS state is reconciled from events (listening / peer connected).
  }

  /// Run the foreground service whenever the node needs to stay alive in the
  /// background — listening, or holding at least one live peer session (so a
  /// dialer-only connection survives backgrounding too).
  void _syncForegroundService() {
    if (state.listening || state.peers.isNotEmpty) {
      ForegroundService.start();
    } else {
      ForegroundService.stop();
    }
  }

  Future<String?> ticketForShare() async {
    final node = _node;
    if (node == null) return null;
    try {
      final t = await node.myTicket();
      state = state.copyWith(ticket: t);
      return t;
    } catch (e) {
      _log(LogKind.error, 'Ticket failed: $e');
      return null;
    }
  }

  void connect(String ticket) {
    final node = _node;
    final t = ticket.trim();
    if (node == null || t.isEmpty) return;
    // Go online when we dial: a listening node makes iroh actively maintain its
    // relay link (to stay reachable), which keeps the connection warm in the
    // background — the difference between a dialer-only node (relay idles out,
    // no background delivery) and a listener (stays reachable, notifications fire).
    if (!state.listening) {
      _log(LogKind.info, 'Going online…');
      node.startListening();
    }
    _log(LogKind.info, 'Dialing peer…');
    node.connect(ticket: t);
  }

  Future<void> send(String peerIdHex, String body) async {
    final node = _node;
    if (node == null || body.isEmpty) return;
    final tooLarge = messageSizeError(body, maxMessageBytes());
    if (tooLarge != null) {
      _log(LogKind.error, tooLarge);
      return;
    }
    try {
      await node.send(peerIdHex: peerIdHex, body: body);
      _log(LogKind.message, 'you » $body');
    } catch (e) {
      _log(LogKind.error, 'Send failed: $e');
    }
  }

  void clearLog() => state = state.copyWith(log: const []);

  void _log(LogKind kind, String text) {
    final next = [...state.log, LogLine(kind, text, DateTime.now())];
    // Bound the console.
    state = state.copyWith(log: next.length > 300 ? next.sublist(next.length - 300) : next);
  }

  String _short(String hex) => shortPeerId(hex);
}
