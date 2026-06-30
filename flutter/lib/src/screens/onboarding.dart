import 'dart:math';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../rust/api/node.dart';
import '../state/app_controller.dart';
import '../theme.dart';
import '../widgets/lattice_mesh.dart';
import '../widgets/ui.dart';

/// Shared frame for onboarding/lock screens: mesh background + centered column.
class OnboardScaffold extends StatelessWidget {
  const OnboardScaffold({super.key, required this.child, this.onBack});

  final Widget child;
  final VoidCallback? onBack;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: LatticeMesh(
        active: false,
        child: SafeArea(
          child: Stack(
            children: [
              if (onBack != null)
                Positioned(
                  top: 8,
                  left: 8,
                  child: IconButton(
                    onPressed: onBack,
                    icon: const Icon(Icons.arrow_back_rounded, color: Lx.muted),
                  ),
                ),
              Center(
                child: SingleChildScrollView(
                  padding: const EdgeInsets.all(28),
                  child: ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 560),
                    child: child,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class Wordmark extends StatelessWidget {
  const Wordmark({super.key, this.subtitle = 'post-quantum hybrid · peer-to-peer'});
  final String subtitle;

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        const Icon(Icons.hub_outlined, size: 52, color: Lx.violet),
        const SizedBox(height: 14),
        Text('Lattice Node', style: Theme.of(context).textTheme.headlineMedium),
        const SizedBox(height: 6),
        SectionLabel(subtitle, color: Lx.teal),
      ],
    );
  }
}

/// Step machine for first run.
class OnboardingFlow extends StatefulWidget {
  const OnboardingFlow({super.key});
  @override
  State<OnboardingFlow> createState() => _OnboardingFlowState();
}

enum _Step { welcome, generate, recover }

class _OnboardingFlowState extends State<OnboardingFlow> {
  _Step _step = _Step.welcome;

  @override
  Widget build(BuildContext context) {
    switch (_step) {
      case _Step.welcome:
        return _Welcome(
          onGenerate: () => setState(() => _step = _Step.generate),
          onRecover: () => setState(() => _step = _Step.recover),
        );
      case _Step.generate:
        return GenerateScreen(onBack: () => setState(() => _step = _Step.welcome));
      case _Step.recover:
        return RecoverScreen(onBack: () => setState(() => _step = _Step.welcome));
    }
  }
}

class _Welcome extends StatelessWidget {
  const _Welcome({required this.onGenerate, required this.onRecover});
  final VoidCallback onGenerate;
  final VoidCallback onRecover;

  @override
  Widget build(BuildContext context) {
    return OnboardScaffold(
      child: Column(
        children: [
          const SizedBox(height: 12),
          const Wordmark(),
          const SizedBox(height: 28),
          Text(
            'A private control harness for the Lattice peer-to-peer network. '
            'Your identity is a post-quantum keypair that lives only on this '
            'device — no account, no server.',
            textAlign: TextAlign.center,
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(color: Lx.muted, height: 1.5),
          ),
          const SizedBox(height: 32),
          SizedBox(
            width: double.infinity,
            child: FilledButton(onPressed: onGenerate, child: const Text('Create a new identity')),
          ),
          const SizedBox(height: 12),
          SizedBox(
            width: double.infinity,
            child: OutlinedButton(onPressed: onRecover, child: const Text('Recover from a recovery phrase')),
          ),
        ],
      ),
    );
  }
}

/// Generate → reveal the 24-word phrase → confirm a few words → commit.
class GenerateScreen extends ConsumerStatefulWidget {
  const GenerateScreen({super.key, required this.onBack});
  final VoidCallback onBack;
  @override
  ConsumerState<GenerateScreen> createState() => _GenerateScreenState();
}

class _GenerateScreenState extends ConsumerState<GenerateScreen> {
  NewIdentity? _identity;
  String? _error;
  bool _revealed = false;
  bool _confirming = false;

  @override
  void initState() {
    super.initState();
    _generate();
  }

  Future<void> _generate() async {
    try {
      final id = await generateIdentity();
      if (mounted) setState(() => _identity = id);
    } catch (e) {
      if (mounted) setState(() => _error = '$e');
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_error != null) {
      return OnboardScaffold(onBack: widget.onBack, child: _ErrorBlock(_error!));
    }
    final id = _identity;
    if (id == null) {
      return const OnboardScaffold(child: _Busy('Generating your post-quantum identity…'));
    }
    if (_confirming) {
      return _ConfirmWords(
        mnemonic: id.mnemonic,
        onBack: () => setState(() => _confirming = false),
        onConfirmed: () => ref.read(appControllerProvider.notifier).commitIdentity(id.mnemonic),
      );
    }

    final words = id.mnemonic.split(RegExp(r'\s+'));
    return OnboardScaffold(
      onBack: widget.onBack,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const SectionLabel('Your recovery phrase', color: Lx.violet),
          const SizedBox(height: 8),
          Text('Write these 24 words down in order and keep them offline. '
              'They are the only way to recover this identity.',
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(color: Lx.muted, height: 1.5)),
          const SizedBox(height: 16),
          Stack(
            children: [
              _WordGrid(words: words),
              if (!_revealed)
                Positioned.fill(
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(16),
                    child: _BlurCover(onReveal: () => setState(() => _revealed = true)),
                  ),
                ),
            ],
          ),
          const SizedBox(height: 12),
          Align(
            alignment: Alignment.centerLeft,
            child: CopyableValue(
              value: id.mnemonic,
              display: 'Copy phrase',
              style: mono(size: 12, color: Lx.muted),
              toast: 'Recovery phrase copied',
            ),
          ),
          const SizedBox(height: 20),
          FilledButton(
            onPressed: _revealed ? () => setState(() => _confirming = true) : null,
            child: const Text("I've saved it — continue"),
          ),
        ],
      ),
    );
  }
}

class _ConfirmWords extends StatefulWidget {
  const _ConfirmWords({required this.mnemonic, required this.onBack, required this.onConfirmed});
  final String mnemonic;
  final VoidCallback onBack;
  final VoidCallback onConfirmed;
  @override
  State<_ConfirmWords> createState() => _ConfirmWordsState();
}

class _ConfirmWordsState extends State<_ConfirmWords> {
  late final List<String> _words = widget.mnemonic.split(RegExp(r'\s+'));
  late final List<int> _ask = _pickIndices();
  late final Map<int, TextEditingController> _ctrls = {
    for (final i in _ask) i: TextEditingController(),
  };
  String? _error;

  List<int> _pickIndices() {
    final rng = Random();
    final idx = <int>{};
    while (idx.length < 3 && idx.length < _words.length) {
      idx.add(rng.nextInt(_words.length));
    }
    return idx.toList()..sort();
  }

  void _check() {
    final ok = _ask.every((i) =>
        _ctrls[i]!.text.trim().toLowerCase() == _words[i].toLowerCase());
    if (ok) {
      widget.onConfirmed();
    } else {
      setState(() => _error = "That doesn't match. Check your written copy.");
    }
  }

  @override
  void dispose() {
    for (final c in _ctrls.values) {
      c.dispose();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return OnboardScaffold(
      onBack: widget.onBack,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const SectionLabel('Confirm your phrase', color: Lx.violet),
          const SizedBox(height: 8),
          Text('Enter the requested words to confirm you saved them.',
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(color: Lx.muted)),
          const SizedBox(height: 16),
          for (final i in _ask)
            Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: TextField(
                controller: _ctrls[i],
                style: mono(),
                decoration: InputDecoration(
                  labelText: 'Word #${i + 1}',
                  filled: true,
                  fillColor: Lx.raised,
                  enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                    borderSide: const BorderSide(color: Lx.line),
                  ),
                ),
              ),
            ),
          if (_error != null) ...[
            const SizedBox(height: 4),
            Text(_error!, style: const TextStyle(color: Lx.danger)),
          ],
          const SizedBox(height: 12),
          FilledButton(onPressed: _check, child: const Text('Confirm & secure identity')),
        ],
      ),
    );
  }
}

class RecoverScreen extends ConsumerStatefulWidget {
  const RecoverScreen({super.key, required this.onBack});
  final VoidCallback onBack;
  @override
  ConsumerState<RecoverScreen> createState() => _RecoverScreenState();
}

class _RecoverScreenState extends ConsumerState<RecoverScreen> {
  final _ctrl = TextEditingController();
  String? _error;
  bool _busy = false;

  Future<void> _recover() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await ref.read(appControllerProvider.notifier).recover(_ctrl.text);
      // On success the app stage advances; this screen is replaced.
    } catch (e) {
      if (mounted) {
        setState(() {
          _busy = false;
          _error = 'That phrase is not a valid Lattice identity.';
        });
      }
    }
  }

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return OnboardScaffold(
      onBack: widget.onBack,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          const SectionLabel('Recover identity', color: Lx.violet),
          const SizedBox(height: 8),
          Text('Enter your 24-word recovery phrase, separated by spaces.',
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(color: Lx.muted)),
          const SizedBox(height: 16),
          TextField(
            controller: _ctrl,
            maxLines: 4,
            style: mono(size: 14),
            decoration: InputDecoration(
              hintText: 'word1 word2 word3 …',
              filled: true,
              fillColor: Lx.raised,
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(12),
                borderSide: const BorderSide(color: Lx.line),
              ),
            ),
          ),
          if (_error != null) ...[
            const SizedBox(height: 10),
            Text(_error!, style: const TextStyle(color: Lx.danger)),
          ],
          const SizedBox(height: 20),
          FilledButton(
            onPressed: _busy ? null : _recover,
            child: _busy
                ? const SizedBox(height: 18, width: 18, child: CircularProgressIndicator(strokeWidth: 2))
                : const Text('Recover & secure identity'),
          ),
        ],
      ),
    );
  }
}

/// The lock screen for a returning user (StageLocked).
class UnlockScreen extends ConsumerWidget {
  const UnlockScreen({super.key, required this.biometric});
  final bool biometric;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return OnboardScaffold(
      child: Column(
        children: [
          const SizedBox(height: 12),
          const Wordmark(subtitle: 'identity locked'),
          const SizedBox(height: 28),
          Text(
            biometric
                ? 'Authenticate to unlock your identity and bring the node up.'
                : 'Unlock your identity to bring the node up.',
            textAlign: TextAlign.center,
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(color: Lx.muted, height: 1.5),
          ),
          const SizedBox(height: 28),
          SizedBox(
            width: double.infinity,
            child: FilledButton.icon(
              onPressed: () => ref.read(appControllerProvider.notifier).unlock(),
              icon: Icon(biometric ? Icons.fingerprint_rounded : Icons.lock_open_rounded),
              label: Text(biometric ? 'Unlock with biometrics' : 'Unlock'),
            ),
          ),
        ],
      ),
    );
  }
}

// --- small pieces ----------------------------------------------------------

class _WordGrid extends StatelessWidget {
  const _WordGrid({required this.words});
  final List<String> words;

  @override
  Widget build(BuildContext context) {
    return Panel(
      child: Wrap(
        spacing: 10,
        runSpacing: 10,
        children: [
          for (var i = 0; i < words.length; i++)
            ConstrainedBox(
              constraints: const BoxConstraints(minWidth: 110),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text('${i + 1}'.padLeft(2, '0'),
                      style: mono(size: 11, color: Lx.muted)),
                  const SizedBox(width: 8),
                  Text(words[i], style: mono(size: 13, color: Lx.text)),
                ],
              ),
            ),
        ],
      ),
    );
  }
}

class _BlurCover extends StatelessWidget {
  const _BlurCover({required this.onReveal});
  final VoidCallback onReveal;

  @override
  Widget build(BuildContext context) {
    return Container(
      color: Lx.raisedHi.withValues(alpha: 0.96),
      alignment: Alignment.center,
      child: TextButton.icon(
        onPressed: onReveal,
        icon: const Icon(Icons.visibility_rounded, color: Lx.teal),
        label: Text('Tap to reveal', style: mono(color: Lx.teal)),
      ),
    );
  }
}

class _Busy extends StatelessWidget {
  const _Busy(this.label);
  final String label;
  @override
  Widget build(BuildContext context) => Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const CircularProgressIndicator(),
          const SizedBox(height: 18),
          Text(label, style: const TextStyle(color: Lx.muted)),
        ],
      );
}

class _ErrorBlock extends StatelessWidget {
  const _ErrorBlock(this.message);
  final String message;
  @override
  Widget build(BuildContext context) => Panel(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const SectionLabel('Something went wrong', color: Lx.danger),
            const SizedBox(height: 10),
            Text(message, style: mono(size: 12, color: Lx.text)),
          ],
        ),
      );
}
