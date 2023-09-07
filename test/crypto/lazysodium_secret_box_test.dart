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
    final nonceSize = lazysodium.crypto_secretbox_noncebytes();
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
    final kxServerSharedKey = lazysodium.cryptoBoxBeforeNm(kxServerKeyPair);
    final kxClientSharedKey = lazysodium.cryptoBoxBeforeNm(kxClientKeyPair);

    // When
    final actualCipherBytes =
        lazysodium.cryptoSecretBoxEasy(plaintext, nonceByte, kxServerSharedKey);
    final actualPlainBytes = lazysodium.cryptoSecretBoxOpenEasy(
        actualCipherBytes, nonceByte, kxClientSharedKey);

    // Then
    expect(String.fromCharCodes(actualPlainBytes), expected);
  });
}
