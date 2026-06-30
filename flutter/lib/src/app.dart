import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'screens/dashboard_screen.dart';
import 'screens/onboarding.dart';
import 'state/app_controller.dart';
import 'theme.dart';
import 'widgets/ui.dart';

class LatticeApp extends StatelessWidget {
  const LatticeApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Lattice Node',
      debugShowCheckedModeBanner: false,
      theme: latticeTheme(),
      home: const BootstrapGate(),
    );
  }
}

/// Routes to the right screen based on the app lifecycle stage.
class BootstrapGate extends ConsumerWidget {
  const BootstrapGate({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final stage = ref.watch(appControllerProvider);
    final child = switch (stage) {
      StageLoading() => const _Splash(),
      StageOnboarding() => const OnboardingFlow(),
      StageLocked(:final biometric) => UnlockScreen(biometric: biometric),
      StageUnlocked(:final identity) => DashboardScreen(identity: identity),
      StageError(:final message) => _ErrorScreen(message: message),
    };
    return AnimatedSwitcher(duration: const Duration(milliseconds: 250), child: child);
  }
}

class _Splash extends StatelessWidget {
  const _Splash();
  @override
  Widget build(BuildContext context) => const Scaffold(
        body: Center(child: CircularProgressIndicator()),
      );
}

class _ErrorScreen extends ConsumerWidget {
  const _ErrorScreen({required this.message});
  final String message;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return Scaffold(
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 520),
          child: Padding(
            padding: const EdgeInsets.all(28),
            child: Panel(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const SectionLabel('Something went wrong', color: Lx.danger),
                  const SizedBox(height: 12),
                  Text(message, style: mono(size: 12, color: Lx.text)),
                  const SizedBox(height: 18),
                  Align(
                    alignment: Alignment.centerRight,
                    child: FilledButton(
                      onPressed: () => ref.read(appControllerProvider.notifier).retry(),
                      child: const Text('Retry'),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
