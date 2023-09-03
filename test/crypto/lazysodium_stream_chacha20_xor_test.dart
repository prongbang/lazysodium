import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:lazysodium/lazysodium.dart';

void main() {
  late Lazysodium lazysodium;

  setUp(() {
    lazysodium = Lazysodium.instance();
  });

  test(
    'Should has result when encrypt/decrypt crypto_stream_chacha20_xor success',
    () {
      // Should
      final keypair = lazysodium.cryptoKxKeyPair();
      final nonce = lazysodium.randomBytesBuf(
        lazysodium.crypto_secretbox_noncebytes(),
      );
      final key = keypair.pk;
      const message = 'Lazysodium';
      final bytes = Uint8List.fromList(message.codeUnits);

      // When
      // encrypt
      final encrypted = lazysodium.cryptoStreamChaCha20Xor(bytes, nonce, key);

      // decrypt
      final decryptedBytes =
          lazysodium.cryptoStreamChaCha20Xor(encrypted, nonce, key);
      final decrypted = String.fromCharCodes(decryptedBytes);

      // Then
      expect(decrypted, message);
    },
  );
}
