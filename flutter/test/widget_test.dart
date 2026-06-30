// Minimal placeholder test. Real widget/integration tests land with the M2 UI.
// The smoke screen drives native Rust (RustLib.init + Node.open), so it isn't
// exercised in a plain unit test here.
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('arithmetic sanity', () {
    expect(1 + 1, 2);
  });
}
