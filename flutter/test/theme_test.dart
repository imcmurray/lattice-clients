import 'package:flutter_test/flutter_test.dart';
import 'package:lattice_node/src/theme.dart';

void main() {
  group('groupHex', () {
    test('groups into 4-char blocks', () {
      expect(groupHex('deadbeef'), 'dead beef');
      expect(groupHex('abcd'), 'abcd');
      expect(groupHex(''), '');
    });

    test('handles lengths that are not a multiple of the block', () {
      expect(groupHex('deadbee'), 'dead bee');
      expect(groupHex('a'), 'a');
    });
  });
}
