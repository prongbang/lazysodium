import 'package:ffi/ffi.dart' as ffi;
import 'package:flutter_test/flutter_test.dart';
import 'package:lazysodium/lazysodium.dart';

void main() {
  late Lazysodium lazysodium;

  setUp(() {
    lazysodium = Lazysodium.instance();
  });

  test('Should return nonce size when get nonce size success', () async {
    // Given
    const secretBoxNonceBytes = 24;

    // When
    final size = lazysodium.crypto_secretbox_noncebytes();

    // Then
    expect(size, secretBoxNonceBytes);
  });
}
