import 'package:flutter_test/flutter_test.dart';
import 'package:lazysodium/lazysodium.dart';

void main() {
  late Lazysodium lazysodium;

  setUp(() {
    lazysodium = Lazysodium.instance();
  });

  test('Should return nonce size when get nonce size success', () async {
    // Given
    final nonceSize = lazysodium.crypto_secretbox_noncebytes();

    // When
    final nonceByte = lazysodium.randomBytesBuf(nonceSize);
    final nonceHex = lazysodium.bin2Hex(nonceByte);

    // Then
    expect(nonceHex.length, 48);
    expect(nonceSize, 24);
  });
}
