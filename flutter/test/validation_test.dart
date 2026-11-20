import 'package:flutter_test/flutter_test.dart';
import 'package:lattice_node/src/validation.dart';

void main() {
  test('isUsablePassphrase', () {
    expect(isUsablePassphrase(null), isFalse);
    expect(isUsablePassphrase(''), isFalse);
    expect(isUsablePassphrase('  \n'), isFalse);
    expect(isUsablePassphrase('abc'), isTrue);
  });

  test('messageSizeError counts UTF-8 bytes', () {
    expect(messageSizeError('abc', 3), isNull);
    expect(messageSizeError('abcd', 3), contains('too large'));
    expect(messageSizeError('é', 3), isNull);
    expect(messageSizeError('éé', 3), contains('too large'));
  });
}
