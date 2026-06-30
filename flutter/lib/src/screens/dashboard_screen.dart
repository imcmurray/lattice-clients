import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:share_plus/share_plus.dart';

import '../state/dashboard_controller.dart';
import '../theme.dart';
import '../widgets/lattice_mesh.dart';
import '../widgets/ui.dart';
import 'scan_screen.dart';

class DashboardScreen extends ConsumerWidget {
  const DashboardScreen({super.key, required this.identity});

  bool get _scanSupported =>
      !kIsWeb &&
      (defaultTargetPlatform == TargetPlatform.android ||
          defaultTargetPlatform == TargetPlatform.iOS);
  final dynamic identity; // IdentitySummary

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(dashboardProvider);
    final ctrl = ref.read(dashboardProvider.notifier);
    final peerId = identity.peerIdHex as String;
    final fingerprint = identity.fingerprint as String;

    return Scaffold(
      body: LatticeMesh(
        active: state.listening,
        child: SafeArea(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Center(
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 760),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    _IdentityHeader(
                      fingerprint: fingerprint,
                      peerId: peerId,
                      listening: state.listening,
                      onToggle: ctrl.toggleListen,
                      onShowTicket: () => _showTicket(context, ctrl, state.ticket),
                    ),
                    const SizedBox(height: 12),
                    _ConnectBar(
                      onConnect: ctrl.connect,
                      onScan: _scanSupported
                          ? () async {
                              final t = await Navigator.of(context).push<String>(
                                MaterialPageRoute(builder: (_) => const ScanScreen()),
                              );
                              if (t != null) ctrl.connect(t);
                            }
                          : null,
                    ),
                    if (state.peers.isNotEmpty) ...[
                      const SizedBox(height: 12),
                      _LinksBar(peers: state.peers, links: state.links),
                    ],
                    const SizedBox(height: 12),
                    Expanded(child: _Console(log: state.log, onClear: ctrl.clearLog)),
                    if (state.peers.isNotEmpty) ...[
                      const SizedBox(height: 12),
                      _SendBar(peers: state.peers, onSend: ctrl.send),
                    ],
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  Future<void> _showTicket(
      BuildContext context, DashboardController ctrl, String? current) async {
    final ticket = current ?? await ctrl.ticketForShare();
    if (ticket == null || !context.mounted) return;
    await showDialog<void>(
      context: context,
      builder: (_) => _TicketDialog(ticket: ticket),
    );
  }
}

class _IdentityHeader extends StatelessWidget {
  const _IdentityHeader({
    required this.fingerprint,
    required this.peerId,
    required this.listening,
    required this.onToggle,
    required this.onShowTicket,
  });

  final String fingerprint;
  final String peerId;
  final bool listening;
  final VoidCallback onToggle;
  final VoidCallback onShowTicket;

  @override
  Widget build(BuildContext context) {
    return Panel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.hub_outlined, color: Lx.violet, size: 20),
              const SizedBox(width: 8),
              Text('Lattice Node', style: Theme.of(context).textTheme.titleMedium),
              const Spacer(),
              PowerToggle(on: listening, busy: false, onChanged: onToggle),
            ],
          ),
          const SizedBox(height: 16),
          const SectionLabel('Fingerprint', color: Lx.violet),
          const SizedBox(height: 6),
          Text(fingerprint, style: mono(size: 22, color: Lx.text, weight: FontWeight.w700)),
          const SizedBox(height: 12),
          const SectionLabel('PeerId'),
          CopyableValue(
            value: peerId,
            display: groupHex(peerId),
            style: mono(size: 12, color: Lx.muted),
            toast: 'PeerId copied',
          ),
          const SizedBox(height: 8),
          Align(
            alignment: Alignment.centerLeft,
            child: OutlinedButton.icon(
              onPressed: onShowTicket,
              icon: const Icon(Icons.ios_share_rounded, size: 18),
              label: Text(listening ? 'Share connect ticket' : 'Go online to share a ticket',
                  overflow: TextOverflow.ellipsis),
            ),
          ),
        ],
      ),
    );
  }
}

class _ConnectBar extends StatefulWidget {
  const _ConnectBar({required this.onConnect, this.onScan});
  final void Function(String ticket) onConnect;
  final VoidCallback? onScan;
  @override
  State<_ConnectBar> createState() => _ConnectBarState();
}

class _ConnectBarState extends State<_ConnectBar> {
  final _ctrl = TextEditingController();

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  Future<void> _paste() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    if (data?.text != null) _ctrl.text = data!.text!.trim();
  }

  void _submit() {
    widget.onConnect(_ctrl.text);
    _ctrl.clear();
  }

  @override
  Widget build(BuildContext context) {
    return Panel(
      padding: const EdgeInsets.all(14),
      child: Row(
        children: [
          Expanded(
            child: TextField(
              controller: _ctrl,
              style: mono(size: 12),
              onSubmitted: (_) => _submit(),
              decoration: const InputDecoration(
                isDense: true,
                border: InputBorder.none,
                hintText: 'Paste a peer ticket to connect…',
              ),
            ),
          ),
          IconButton(
            tooltip: 'Paste',
            onPressed: _paste,
            icon: const Icon(Icons.content_paste_rounded, color: Lx.muted, size: 18),
          ),
          if (widget.onScan != null)
            IconButton(
              tooltip: 'Scan QR',
              onPressed: widget.onScan,
              icon: const Icon(Icons.qr_code_scanner_rounded, color: Lx.teal, size: 20),
            ),
          FilledButton(onPressed: _submit, child: const Text('Connect')),
        ],
      ),
    );
  }
}

/// Per-peer link health: a chip per connected peer showing direct-vs-relay
/// (teal vs amber) and the live RTT.
class _LinksBar extends StatelessWidget {
  const _LinksBar({required this.peers, required this.links});
  final Set<String> peers;
  final Map<String, PeerLink> links;

  @override
  Widget build(BuildContext context) {
    return Panel(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      child: Wrap(
        spacing: 8,
        runSpacing: 8,
        children: [for (final p in peers) _chip(p, links[p])],
      ),
    );
  }

  Widget _chip(String peer, PeerLink? link) {
    final direct = link?.direct ?? false;
    final color = link == null ? Lx.muted : (direct ? Lx.teal : Lx.amber);
    final kind = link == null ? 'connecting' : (direct ? 'direct' : 'relay');
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
      decoration: BoxDecoration(
        color: Lx.raisedHi,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: Lx.line),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 7,
            height: 7,
            decoration: BoxDecoration(color: color, shape: BoxShape.circle),
          ),
          const SizedBox(width: 8),
          Text('${peer.substring(0, 8)}…', style: mono(size: 11, color: Lx.text)),
          const SizedBox(width: 8),
          Text(kind, style: mono(size: 11, color: color)),
          if (link?.rttMs != null) ...[
            const SizedBox(width: 6),
            Text('· ${link!.rttMs}ms', style: mono(size: 11, color: Lx.muted)),
          ],
        ],
      ),
    );
  }
}

class _Console extends StatelessWidget {
  const _Console({required this.log, required this.onClear});
  final List<LogLine> log;
  final VoidCallback onClear;

  String _ts(DateTime t) =>
      '${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')}:${t.second.toString().padLeft(2, '0')}';

  @override
  Widget build(BuildContext context) {
    return Panel(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              const SectionLabel('Event console'),
              const Spacer(),
              if (log.isNotEmpty)
                InkWell(
                  onTap: onClear,
                  child: Text('clear', style: mono(size: 11, color: Lx.muted)),
                ),
            ],
          ),
          const SizedBox(height: 8),
          const Divider(color: Lx.line, height: 1),
          Expanded(
            child: log.isEmpty
                ? Center(
                    child: Text('No activity yet — go online to start.',
                        style: mono(size: 12, color: Lx.muted)))
                : ListView.builder(
                    reverse: true,
                    padding: const EdgeInsets.only(top: 10),
                    itemCount: log.length,
                    itemBuilder: (_, i) {
                      final line = log[log.length - 1 - i];
                      return Padding(
                        padding: const EdgeInsets.symmetric(vertical: 3),
                        child: Row(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(_ts(line.at), style: mono(size: 11, color: Lx.muted)),
                            const SizedBox(width: 12),
                            Expanded(
                              child: Text(line.text,
                                  style: mono(size: 12.5, color: line.color)),
                            ),
                          ],
                        ),
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }
}

class _SendBar extends StatefulWidget {
  const _SendBar({required this.peers, required this.onSend});
  final Set<String> peers;
  final Future<void> Function(String peer, String body) onSend;
  @override
  State<_SendBar> createState() => _SendBarState();
}

class _SendBarState extends State<_SendBar> {
  final _ctrl = TextEditingController();
  String? _peer;

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final peers = widget.peers.toList();
    _peer ??= peers.first;
    if (!peers.contains(_peer)) _peer = peers.first;

    return Panel(
      padding: const EdgeInsets.all(14),
      child: Row(
        children: [
          DropdownButton<String>(
            value: _peer,
            dropdownColor: Lx.raisedHi,
            underline: const SizedBox.shrink(),
            style: mono(size: 12),
            items: [
              for (final p in peers)
                DropdownMenuItem(value: p, child: Text('${p.substring(0, 8)}…')),
            ],
            onChanged: (v) => setState(() => _peer = v),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: TextField(
              controller: _ctrl,
              style: mono(size: 12),
              onSubmitted: (_) => _send(),
              decoration: const InputDecoration(
                isDense: true,
                border: InputBorder.none,
                hintText: 'Encrypted message…',
              ),
            ),
          ),
          IconButton(
            onPressed: _send,
            icon: const Icon(Icons.send_rounded, color: Lx.teal, size: 20),
          ),
        ],
      ),
    );
  }

  void _send() {
    final peer = _peer;
    if (peer == null || _ctrl.text.trim().isEmpty) return;
    widget.onSend(peer, _ctrl.text.trim());
    _ctrl.clear();
  }
}

/// The PQ-hybrid ticket carries kilobytes of public keys, so it cannot fit in a
/// QR code — it's shared as copyable text.
class _TicketDialog extends ConsumerWidget {
  const _TicketDialog({required this.ticket});
  final String ticket;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // Auto-dismiss once a peer connects — the ticket has done its job.
    ref.listen<int>(dashboardProvider.select((s) => s.peers.length), (prev, next) {
      if ((prev ?? 0) < next) {
        Navigator.of(context).maybePop();
      }
    });
    return Dialog(
      backgroundColor: Lx.raised,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 520),
        child: Padding(
          padding: const EdgeInsets.all(22),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const SectionLabel('Connect ticket', color: Lx.teal),
              const SizedBox(height: 14),
              Center(
                child: Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Colors.white,
                    borderRadius: BorderRadius.circular(14),
                  ),
                  child: QrImageView(
                    data: ticket,
                    version: QrVersions.auto,
                    size: 220,
                    backgroundColor: Colors.white,
                  ),
                ),
              ),
              const SizedBox(height: 14),
              Text(
                'Scan this from the other device — or share / copy the text below.',
                style: Theme.of(context).textTheme.bodySmall?.copyWith(color: Lx.muted, height: 1.4),
              ),
              const SizedBox(height: 12),
              Container(
                constraints: const BoxConstraints(maxHeight: 120),
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Lx.surface,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: Lx.line),
                ),
                child: SingleChildScrollView(
                  child: SelectableText(ticket, style: mono(size: 10, color: Lx.muted)),
                ),
              ),
              const SizedBox(height: 16),
              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  TextButton.icon(
                    onPressed: () => SharePlus.instance.share(
                      ShareParams(text: ticket, subject: 'Lattice connect ticket'),
                    ),
                    icon: const Icon(Icons.ios_share_rounded, size: 16, color: Lx.teal),
                    label: Text('Share', style: mono(size: 12, color: Lx.teal)),
                  ),
                  TextButton.icon(
                    onPressed: () {
                      Clipboard.setData(ClipboardData(text: ticket));
                      ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(content: Text('Ticket copied'), duration: Duration(seconds: 1)),
                      );
                    },
                    icon: const Icon(Icons.content_copy_rounded, size: 16, color: Lx.teal),
                    label: Text('Copy', style: mono(size: 12, color: Lx.teal)),
                  ),
                  const SizedBox(width: 8),
                  FilledButton(
                    onPressed: () => Navigator.of(context).pop(),
                    child: const Text('Done'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}
