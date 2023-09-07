import 'package:flutter_test/flutter_test.dart';
import 'package:lazysodium/lazysodium.dart';

void main() {
  late Lazysodium lazysodium;

  setUp(() {
    lazysodium = Lazysodium();
  });

  test('Should return nonce size when get nonce size success', () {
    // Given
    final nonceSize = lazysodium.crypto_secretbox_noncebytes();

    // When
    final nonceByte = lazysodium.randomBytesBuf(nonceSize);
    final nonceHex1 = lazysodium.bin2Hex(nonceByte);
    final nonceBytes = lazysodium.hex2Bin(nonceHex1);
    final nonceHex2 = lazysodium.bin2Hex(nonceBytes);

    // Then
    expect(nonceHex1.length, 48);
    expect(nonceHex2.length, 48);
    expect(nonceHex1, nonceHex2);
    expect(nonceSize, 24);
  });
}
