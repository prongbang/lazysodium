import 'package:flutter_test/flutter_test.dart';
import 'package:lazysodium/lazysodium.dart';

void main() {
  late Lazysodium lazysodium;

  setUp(() {
    lazysodium = LazySodium.instance();
  });

  test('Should return nonce when random nonce success', () async {
    // Given
    final nonceHex = lazysodium.randomNonceHex();

    // When

    // Then
    print(nonceHex);
  });
}
