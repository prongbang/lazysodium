import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';
import 'dart:ffi' as ffi;
import 'package:lazysodium/lazysodium.dart';

class KeyPair {
  Uint8List pk;
  Uint8List sk;

  KeyPair({required this.pk, required this.sk});
}

extension LazysodiumKxExtension on LazysodiumBinding {
  KeyPair cryptoKxKeyPair() {
    final keyPair = KeyPair(pk: Uint8List(0), sk: Uint8List(0));

    // Allocate memory for the public key (pk) and secret key (sk)
    final publicKey = calloc<ffi.Uint8>(crypto_kx_PUBLICKEYBYTES);
    final secretKey = calloc<ffi.Uint8>(crypto_kx_SECRETKEYBYTES);

    // Call crypto_kx_keypair to generate the keypair
    final result = crypto_kx_keypair(
      publicKey.cast<ffi.UnsignedChar>(),
      secretKey.cast<ffi.UnsignedChar>(),
    );

    if (result == 0) {
      // You can access the keys like this:
      final pkList = publicKey.asTypedList(crypto_kx_PUBLICKEYBYTES);
      final skList = secretKey.asTypedList(crypto_kx_SECRETKEYBYTES);
      keyPair
        ..pk = Uint8List.fromList(List.from(pkList))
        ..sk = Uint8List.fromList(List.from(skList));
    } else {
      debugPrint('[Lazysodium] Keypair generation failed.');
    }

    // Free allocated memory
    calloc.free(publicKey);
    calloc.free(secretKey);

    return keyPair;
  }
}
