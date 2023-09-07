import 'package:flutter_test/flutter_test.dart';
import 'package:lazysodium/lazysodium.dart';

void main() {
  late Lazysodium lazysodium;

  setUp(() {
    lazysodium = Lazysodium();
  });

  test(
    'Should has result when encrypt/decrypt crypto_stream_chacha20_xor success',
    () {
      // Given
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
      final clientSharedKey = lazysodium.cryptoBoxBeforeNm(kxClientKeyPair);
      final serverSharedKey = lazysodium.cryptoBoxBeforeNm(kxServerKeyPair);
      final clientSharedKeyHex = lazysodium.bin2Hex(clientSharedKey);
      final serverSharedKeyHex = lazysodium.bin2Hex(serverSharedKey);

      // Then
      expect(clientSharedKey, isNotEmpty);
      expect(serverSharedKey, isNotEmpty);
      expect(clientSharedKey, serverSharedKey);
      expect(clientSharedKeyHex, serverSharedKeyHex);
    },
  );
}
