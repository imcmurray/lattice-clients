import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../rust/api/node.dart';
import '../services.dart';

/// The top-level lifecycle of the app.
sealed class AppStage {
  const AppStage();
}

class StageLoading extends AppStage {
  const StageLoading();
}

class StageOnboarding extends AppStage {
  const StageOnboarding();
}

class StageLocked extends AppStage {
  const StageLocked({required this.biometric});
  final bool biometric;
}

class StageUnlocked extends AppStage {
  const StageUnlocked(this.node, this.identity);
  final Node node;
  final IdentitySummary identity;
}

class StageError extends AppStage {
  const StageError(this.message);
  final String message;
}

final appControllerProvider =
    NotifierProvider<AppController, AppStage>(AppController.new);

class AppController extends Notifier<AppStage> {
  final SecureStore _store = SecureStore();
  final AuthService _auth = AuthService();
  String? _dir;

  @override
  AppStage build() {
    _bootstrap();
    return const StageLoading();
  }

  Future<String> _dirPath() async => _dir ??= await identityDir();

  /// Decide where to start: unlock an existing identity, or onboard a new one.
  Future<void> _bootstrap() async {
    try {
      final dir = await _dirPath();
      if (identityExists(dir: dir)) {
        state = StageLocked(biometric: await _auth.available());
      } else {
        state = const StageOnboarding();
      }
    } catch (e) {
      state = StageError('$e');
    }
  }

  /// Persist a confirmed-new (or recovered) mnemonic and bring the node up.
  Future<void> commitIdentity(String mnemonic) async {
    state = const StageLoading();
    try {
      final dir = await _dirPath();
      final pass = await _store.getOrCreatePassphrase();
      await storeIdentity(dir: dir, mnemonic: mnemonic, passphrase: pass);
      await _openInto(dir, pass);
    } catch (e) {
      state = StageError('$e');
    }
  }

  /// Validate a recovery phrase (throws on bad input) before committing it.
  Future<void> recover(String mnemonic) async {
    final phrase = mnemonic.trim().replaceAll(RegExp(r'\s+'), ' ');
    await summarizeMnemonic(mnemonic: phrase); // throws if invalid
    await commitIdentity(phrase);
  }

  /// Unlock the stored identity behind a biometric/device-credential gate.
  Future<void> unlock() async {
    try {
      if (!await _auth.authenticate('Unlock your Lattice identity')) return;
      state = const StageLoading();
      final dir = await _dirPath();
      final pass = await _store.getPassphrase();
      if (pass == null) {
        state = const StageError(
            'Stored identity found but its key is missing from the keystore. '
            'You may need to recover from your mnemonic.');
        return;
      }
      await _openInto(dir, pass);
    } catch (e) {
      state = StageError('$e');
    }
  }

  Future<void> _openInto(String dir, String pass) async {
    final node = await Node.open(dir: dir, passphrase: pass);
    state = StageUnlocked(
      node,
      IdentitySummary(peerIdHex: node.peerIdHex(), fingerprint: node.fingerprint()),
    );
  }

  void startOnboarding() => state = const StageOnboarding();

  Future<void> retry() async {
    state = const StageLoading();
    await _bootstrap();
  }
}
