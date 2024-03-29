import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart' as f;
import 'dart:ffi' as ffi;

import 'package:lazysodium/lazysodium.binding.dart';

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

    try {
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
        f.debugPrint('[Lazysodium] Keypair generation failed.');
      }
      return keyPair;
    } finally {
      // Free allocated memory
      calloc.free(publicKey);
      calloc.free(secretKey);
    }
  }
}
