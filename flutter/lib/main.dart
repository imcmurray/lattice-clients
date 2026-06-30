import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'src/app.dart';
import 'src/rust/frb_generated.dart';
import 'src/services.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  await NotificationService.init();
  ForegroundService.init();
  runApp(const ProviderScope(child: LatticeApp()));
}
