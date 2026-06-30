import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';
import 'package:path_provider/path_provider.dart';

/// The app-private directory holding the encrypted identity file.
Future<String> identityDir() async {
  final base = await getApplicationSupportDirectory();
  final dir = Directory('${base.path}/lattice');
  await dir.create(recursive: true);
  return dir.path;
}

/// Wraps the platform keystore (Android Keystore / iOS Keychain / libsecret on
/// Linux / Credential Manager on Windows) to hold the high-entropy passphrase
/// that decrypts the age identity file. The passphrase never leaves the device
/// and is never shown to the user.
class SecureStore {
  SecureStore([FlutterSecureStorage? storage])
      : _storage = storage ?? const FlutterSecureStorage();

  final FlutterSecureStorage _storage;
  static const _key = 'lattice_identity_passphrase';

  Future<String?> getPassphrase() => _storage.read(key: _key);

  Future<String> getOrCreatePassphrase() async {
    final existing = await _storage.read(key: _key);
    if (existing != null && existing.isNotEmpty) return existing;
    final created = _randomPassphrase();
    await _storage.write(key: _key, value: created);
    return created;
  }

  Future<void> clear() => _storage.delete(key: _key);

  String _randomPassphrase() {
    final rng = Random.secure();
    final bytes = List<int>.generate(32, (_) => rng.nextInt(256));
    return base64Url.encode(bytes);
  }
}

/// Biometric / device-credential gate with graceful fallback: on platforms with
/// no biometric support (e.g. Linux desktop), [available] is false and
/// [authenticate] simply succeeds — the keystore itself is the protection there.
class AuthService {
  final LocalAuthentication _auth = LocalAuthentication();

  Future<bool> available() async {
    try {
      return await _auth.isDeviceSupported();
    } catch (_) {
      return false;
    }
  }

  Future<bool> authenticate(String reason) async {
    try {
      if (!await available()) return true;
      return await _auth.authenticate(
        localizedReason: reason,
        biometricOnly: false,
        persistAcrossBackgrounding: true,
      );
    } catch (_) {
      // No usable auth on this platform — fall through to the keystore layer.
      return true;
    }
  }
}
