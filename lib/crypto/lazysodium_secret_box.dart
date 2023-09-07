import 'dart:ffi' as ffi;

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';
import 'package:lazysodium/lazysodium.binding.dart';

extension LazysodiumSecretBoxExtension on LazysodiumBinding {
  Uint8List cryptoSecretBoxOpenEasy(
    Uint8List ciphertext,
    Uint8List nonce,
    Uint8List sharedKey,
  ) {
    final plaintextLength = ciphertext.length - crypto_secretbox_MACBYTES;
    final ciphertextPointer = calloc<ffi.Uint8>(ciphertext.length);
    final plaintextPointer = calloc<ffi.Uint8>(plaintextLength);
    final noncePointer = calloc<ffi.Uint8>(crypto_secretbox_NONCEBYTES);
    final sharedKeyPointer = calloc<ffi.Uint8>(crypto_secretbox_KEYBYTES);

    // Fill nonce, secretKey, and ciphertext with appropriate values
    for (var i = 0; i < ciphertext.length; i++) {
      ciphertextPointer.elementAt(i).value = ciphertext[i];
    }
    for (var i = 0; i < nonce.length; i++) {
      noncePointer.elementAt(i).value = nonce[i];
    }
    for (var i = 0; i < sharedKey.length; i++) {
      sharedKeyPointer.elementAt(i).value = sharedKey[i];
    }

    try {
      // Call crypto_secretbox_open_easy to decrypt the message
      final result = crypto_secretbox_open_easy(
        plaintextPointer.cast<ffi.UnsignedChar>(),
        ciphertextPointer.cast<ffi.UnsignedChar>(),
        ciphertext.length,
        noncePointer.cast<ffi.UnsignedChar>(),
        sharedKeyPointer.cast<ffi.UnsignedChar>(),
      );

      if (result == 0) {
        final plaintextList = plaintextPointer
            .asTypedList(ciphertext.length - crypto_secretbox_MACBYTES);
        // Clone the original list
        return Uint8List.fromList(List.from(plaintextList));
      } else {
        debugPrint('[Lazysodium] Crypto secret box open easy failed.');
        return Uint8List(0);
      }
    } finally {
      // Free allocated memory
      calloc.free(ciphertextPointer);
      calloc.free(plaintextPointer);
      calloc.free(noncePointer);
      calloc.free(sharedKeyPointer);
    }
  }

  Uint8List cryptoSecretBoxEasy(
    Uint8List plaintext,
    Uint8List nonce,
    Uint8List sharedKey,
  ) {
    final ciphertextLength = plaintext.length + crypto_secretbox_MACBYTES;
    final plaintextPointer = calloc<ffi.Uint8>(plaintext.length);
    final ciphertextPointer = calloc<ffi.Uint8>(ciphertextLength);
    final noncePointer = calloc<ffi.Uint8>(crypto_secretbox_NONCEBYTES);
    final sharedKeyPointer = calloc<ffi.Uint8>(crypto_secretbox_KEYBYTES);

    try {
      // Fill nonce and secretKey with appropriate values
      for (var i = 0; i < plaintext.length; i++) {
        plaintextPointer.elementAt(i).value = plaintext[i];
      }
      for (var i = 0; i < nonce.length; i++) {
        noncePointer.elementAt(i).value = nonce[i];
      }
      for (var i = 0; i < sharedKey.length; i++) {
        sharedKeyPointer.elementAt(i).value = sharedKey[i];
      }

      // Call crypto_secretbox_easy to encrypt the message
      final result = crypto_secretbox_easy(
        ciphertextPointer.cast<ffi.UnsignedChar>(),
        plaintextPointer.cast<ffi.UnsignedChar>(),
        plaintext.length,
        noncePointer.cast<ffi.UnsignedChar>(),
        sharedKeyPointer.cast<ffi.UnsignedChar>(),
      );

      if (result == 0) {
        final ciphertextList = ciphertextPointer.asTypedList(ciphertextLength);
        // Clone the original list
        return Uint8List.fromList(List.from(ciphertextList));
      } else {
        debugPrint('[Lazysodium] Crypto secret box easy failed.');
        return Uint8List(0);
      }
    } finally {
      // Free allocated memory
      calloc.free(plaintextPointer);
      calloc.free(ciphertextPointer);
      calloc.free(noncePointer);
      calloc.free(sharedKeyPointer);
    }
  }
}
