import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:lazysodium/lazysodium.dart';

void main() {
  late Lazysodium lazysodium;

  setUp(() {
    lazysodium = Lazysodium();
  });

  test('Should return text when encrypt and decrypt success', () {
    // Given
    const expected = 'Lazysodium';
    final plaintext = Uint8List.fromList(expected.codeUnits);
    final nonceSize = lazysodium.crypto_box_noncebytes();
    final nonceByte = lazysodium.randomBytesBuf(nonceSize);
    final serverKeypair = lazysodium.cryptoKxKeyPair();
    final clientKeypair = lazysodium.cryptoKxKeyPair();

    // Key Exchange
    final kxServerKeyPair = KeyPair(
      pk: clientKeypair.pk,
      sk: serverKeypair.sk,
    );
    final kxClientKeyPair = KeyPair(
      pk: serverKeypair.pk,
      sk: clientKeypair.sk,
    );

    // When
    final actualCipherBytes =
        lazysodium.cryptoBoxEasy(plaintext, nonceByte, kxServerKeyPair);
    final actualPlainBytes = lazysodium.cryptoBoxOpenEasy(
        actualCipherBytes, nonceByte, kxClientKeyPair);

    // Then
    expect(String.fromCharCodes(actualPlainBytes), expected);
  });
}
