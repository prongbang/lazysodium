import 'package:flutter_test/flutter_test.dart';
import 'package:lazysodium/lazysodium.dart';

void main() {
  late Lazysodium lazysodium;

  setUp(() {
    lazysodium = Lazysodium();
  });

  test('Should return keypair when create keypair success', () {
    // Given
    final pkSize = lazysodium.crypto_kx_publickeybytes();
    final skSize = lazysodium.crypto_kx_secretkeybytes();

    // When
    final actual = lazysodium.cryptoKxKeyPair();

    // Then
    expect(actual.pk.length, pkSize);
    expect(actual.sk.length, skSize);
  });
}
