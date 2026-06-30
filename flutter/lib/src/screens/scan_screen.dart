import 'package:flutter/material.dart';
import 'package:qr_code_dart_scan/qr_code_dart_scan.dart';

import '../theme.dart';
import '../widgets/ui.dart';

/// Camera QR scanner (mobile only). Pops with the first decoded ticket string.
///
/// Built on Flutter's official `camera` plugin + a pure-Dart zxing decoder
/// (qr_code_dart_scan) — no ML Kit / CameraX, which is what made mobile_scanner
/// crash on this Flutter/engine version.
class ScanScreen extends StatefulWidget {
  const ScanScreen({super.key});
  @override
  State<ScanScreen> createState() => _ScanScreenState();
}

class _ScanScreenState extends State<ScanScreen> {
  bool _handled = false;

  void _onCapture(Result result) {
    if (_handled) return;
    final value = result.text;
    if (value.isEmpty) return;
    _handled = true;
    Navigator.of(context).pop(value);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Lx.surface,
        title: Text('Scan ticket', style: Theme.of(context).textTheme.titleMedium),
      ),
      body: Stack(
        fit: StackFit.expand,
        children: [
          QRCodeDartScanView(
            typeScan: TypeScan.live,
            formats: const [BarcodeFormat.qrCode],
            onCapture: _onCapture,
          ),
          Align(
            alignment: Alignment.bottomCenter,
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Panel(
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                child: Text(
                  'Point at the other device’s connect-ticket QR',
                  style: mono(size: 12, color: Lx.text),
                  textAlign: TextAlign.center,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
