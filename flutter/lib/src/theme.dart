import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

/// Lattice instrument-panel palette. Two semantic accents:
/// violet = identity / keys (static), teal = live network / signal.
class Lx {
  Lx._();
  static const surface = Color(0xFF0E0F1A);
  static const raised = Color(0xFF171A2B);
  static const raisedHi = Color(0xFF1F2338);
  static const line = Color(0xFF262B45);
  static const violet = Color(0xFF9D8BFF);
  static const teal = Color(0xFF35E0D0);
  static const text = Color(0xFFE6E8F2);
  static const muted = Color(0xFF8A90B0);
  static const danger = Color(0xFFFF6B7A);
  static const amber = Color(0xFFE8A33D);
}

ThemeData latticeTheme() {
  final base = ThemeData(brightness: Brightness.dark, useMaterial3: true);
  const scheme = ColorScheme.dark(
    surface: Lx.surface,
    primary: Lx.violet,
    onPrimary: Lx.surface,
    secondary: Lx.teal,
    onSecondary: Lx.surface,
    error: Lx.danger,
    onSurface: Lx.text,
  );
  final body = GoogleFonts.interTextTheme(base.textTheme)
      .apply(bodyColor: Lx.text, displayColor: Lx.text);
  TextStyle grotesk(TextStyle? s) =>
      GoogleFonts.spaceGrotesk(textStyle: s, fontWeight: FontWeight.w600, color: Lx.text);

  return base.copyWith(
    colorScheme: scheme,
    scaffoldBackgroundColor: Lx.surface,
    textTheme: body.copyWith(
      headlineMedium: grotesk(body.headlineMedium),
      headlineSmall: grotesk(body.headlineSmall),
      titleLarge: grotesk(body.titleLarge),
      titleMedium: grotesk(body.titleMedium),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        backgroundColor: Lx.violet,
        foregroundColor: Lx.surface,
        textStyle: GoogleFonts.spaceGrotesk(fontWeight: FontWeight.w600, fontSize: 15),
        padding: const EdgeInsets.symmetric(horizontal: 22, vertical: 16),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        foregroundColor: Lx.text,
        side: const BorderSide(color: Lx.line),
        padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      ),
    ),
    snackBarTheme: const SnackBarThemeData(
      backgroundColor: Lx.raisedHi,
      contentTextStyle: TextStyle(color: Lx.text),
      behavior: SnackBarBehavior.floating,
    ),
  );
}

/// Monospace style for all cryptographic data readouts.
TextStyle mono({
  double size = 13,
  Color color = Lx.text,
  FontWeight weight = FontWeight.w500,
  double spacing = 0.2,
}) =>
    GoogleFonts.jetBrainsMono(
      fontSize: size,
      color: color,
      fontWeight: weight,
      letterSpacing: spacing,
    );

/// Group a hex string into space-separated 4-char blocks for readability.
String groupHex(String hex, {int block = 4}) {
  final b = StringBuffer();
  for (var i = 0; i < hex.length; i += block) {
    if (i > 0) b.write(' ');
    b.write(hex.substring(i, (i + block).clamp(0, hex.length)));
  }
  return b.toString();
}
