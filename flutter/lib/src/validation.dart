import 'dart:convert';

/// Whether [p] is usable as an identity passphrase: non-null and not empty or
/// whitespace-only. Mirrors the core's `validate_passphrase`.
bool isUsablePassphrase(String? p) => p != null && p.trim().isNotEmpty;

/// Returns an error message if [body] exceeds [maxBytes] UTF-8 bytes, else null.
String? messageSizeError(String body, int maxBytes) {
  final n = utf8.encode(body).length;
  if (n <= maxBytes) return null;
  return 'Message too large: $n bytes (max $maxBytes bytes)';
}
