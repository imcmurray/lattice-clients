import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter_foreground_task/flutter_foreground_task.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
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

/// System notifications for node activity (incoming messages, peer connections).
///
/// Local notifications only — Lattice is serverless, so events come from the
/// on-device node, not a push backend. We notify only while the app is *not*
/// foreground (no point popping a banner over the screen you're looking at).
/// True delivery while the app is killed needs a foreground service (future).
class NotificationService {
  NotificationService._();

  static final FlutterLocalNotificationsPlugin _plugin =
      FlutterLocalNotificationsPlugin();
  static bool _ready = false;
  static int _id = 0;
  static const String _channelId = 'lattice_events';
  static const String _channelName = 'Lattice activity';

  /// Updated by the app's lifecycle observer; we only notify when false.
  static bool appResumed = true;

  static Future<void> init() async {
    const android = AndroidInitializationSettings('@mipmap/ic_launcher');
    const linux = LinuxInitializationSettings(defaultActionName: 'Open');
    const settings = InitializationSettings(android: android, linux: linux);
    try {
      await _plugin.initialize(settings: settings);
      final androidImpl = _plugin.resolvePlatformSpecificImplementation<
          AndroidFlutterLocalNotificationsPlugin>();
      await androidImpl
          ?.createNotificationChannel(const AndroidNotificationChannel(
        _channelId,
        _channelName,
        description: 'Incoming messages and peer connections',
        importance: Importance.high,
      ));
      await androidImpl?.requestNotificationsPermission();
      _ready = true;
    } catch (_) {
      _ready = false; // unsupported platform — silently no-op
    }
  }

  /// Post a notification, but only when the app is backgrounded.
  static Future<void> notifyBackground(String title, String body) async {
    if (!_ready || appResumed) return;
    const details = NotificationDetails(
      android: AndroidNotificationDetails(
        _channelId,
        _channelName,
        importance: Importance.high,
        priority: Priority.high,
      ),
      linux: LinuxNotificationDetails(),
    );
    _id = (_id + 1) % 100000;
    try {
      await _plugin.show(
        id: _id,
        title: title,
        body: body,
        notificationDetails: details,
      );
    } catch (_) {}
  }
}

/// Foreground service that keeps the P2P node alive while the app is
/// backgrounded. Android freezes cached processes within seconds, which stops
/// the iroh node entirely — a typed foreground service (dataSync) exempts the
/// process from freezing so messages keep arriving and notifications fire.
///
/// Tied to the ONLINE toggle: started when the node goes online, stopped when
/// it goes offline. Swiping the app away stops the service (and the node) — a
/// node running in the UI isolate can't outlive the activity.
class ForegroundService {
  ForegroundService._();

  static bool get _supported => Platform.isAndroid || Platform.isIOS;

  static void init() {
    if (!_supported) return;
    FlutterForegroundTask.init(
      androidNotificationOptions: AndroidNotificationOptions(
        channelId: 'lattice_service',
        channelName: 'Lattice node',
        channelDescription: 'Keeps your node online in the background',
        channelImportance: NotificationChannelImportance.LOW,
        priority: NotificationPriority.LOW,
      ),
      iosNotificationOptions: const IOSNotificationOptions(),
      foregroundTaskOptions: ForegroundTaskOptions(
        eventAction: ForegroundTaskEventAction.nothing(),
        autoRunOnBoot: false,
        allowWakeLock: true,
        allowWifiLock: true,
        stopWithTask: true,
      ),
    );
  }

  static Future<void> start() async {
    if (!_supported || await FlutterForegroundTask.isRunningService) return;
    await FlutterForegroundTask.startService(
      serviceId: 4242,
      notificationTitle: 'Lattice Node — online',
      notificationText: 'Reachable for peer connections',
      callback: foregroundStartCallback,
    );
  }

  static Future<void> stop() async {
    if (!_supported || !await FlutterForegroundTask.isRunningService) return;
    await FlutterForegroundTask.stopService();
  }
}

/// Entry point for the foreground service's task isolate. The node itself runs
/// in the main isolate (kept alive by the service); this handler is a no-op
/// placeholder the plugin requires.
@pragma('vm:entry-point')
void foregroundStartCallback() {
  FlutterForegroundTask.setTaskHandler(_LatticeTaskHandler());
}

class _LatticeTaskHandler extends TaskHandler {
  @override
  Future<void> onStart(DateTime timestamp, TaskStarter starter) async {}

  @override
  void onRepeatEvent(DateTime timestamp) {}

  @override
  Future<void> onDestroy(DateTime timestamp, bool isTimeout) async {}
}
