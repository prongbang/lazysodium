import 'dart:ffi' as ffi;
import 'dart:ffi';

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';
import 'package:lazysodium/lazysodium.dart';

extension LazysodiumBoxBeforeNmExtension on LazysodiumBinding {
  Uint8List cryptoBoxBeforeNm(KeyPair keyPair) {
    // Allocate memory for the shared secret key (k), public key (pk), and secret key (sk)
    final sharedSecretKey = calloc<ffi.Uint8>(crypto_box_BEFORENMBYTES);
    final publicKey = calloc<ffi.Uint8>(crypto_box_PUBLICKEYBYTES);
    final secretKey = calloc<ffi.Uint8>(crypto_box_SECRETKEYBYTES);

    // Fill publicKey and secretKey with your values
    for (var i = 0; i < crypto_box_PUBLICKEYBYTES; i++) {
      publicKey.elementAt(i).value = keyPair.pk[i];
    }
    for (var i = 0; i < crypto_box_SECRETKEYBYTES; i++) {
      secretKey.elementAt(i).value = keyPair.sk[i];
    }

    try {
      // Call crypto_box_beforenm to compute the shared secret key
      final result = crypto_box_beforenm(
        sharedSecretKey.cast<ffi.UnsignedChar>(),
        publicKey.cast<ffi.UnsignedChar>(),
        secretKey.cast<ffi.UnsignedChar>(),
      );

      if (result == 0) {
        // Print the computed shared secret key
        final sharedSecretKeyList =
            sharedSecretKey.asTypedList(crypto_box_BEFORENMBYTES);
        // Clone the original list
        return Uint8List.fromList(List.from(sharedSecretKeyList));
      } else {
        debugPrint('[Lazysodium] Crypto box before nm failed.');
        return Uint8List(0);
      }
    } finally {
      // Free allocated memory
      calloc.free(sharedSecretKey);
      calloc.free(publicKey);
      calloc.free(secretKey);
    }
  }
}
