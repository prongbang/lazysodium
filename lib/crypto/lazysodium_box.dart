import 'dart:ffi' as ffi;

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';
import 'package:lazysodium/lazysodium.dart';

extension LazysodiumBoxExtension on LazysodiumBinding {
  Uint8List cryptoBoxEasy(
    Uint8List plaintext,
    Uint8List nonce,
    KeyPair keyPair,
  ) {
    final ciphertextLength = plaintext.length + crypto_box_MACBYTES;
    final ciphertextPointer = calloc<ffi.Uint8>(ciphertextLength);
    final plaintextPointer = calloc<ffi.Uint8>(plaintext.length);
    final noncePointer = calloc<ffi.Uint8>(crypto_secretbox_NONCEBYTES);
    final pkPointer = calloc<ffi.Uint8>(crypto_box_PUBLICKEYBYTES);
    final skPointer = calloc<ffi.Uint8>(crypto_box_SECRETKEYBYTES);

    // Fill nonce, publicKey, and secretKey with appropriate values
    for (var i = 0; i < plaintext.length; i++) {
      plaintextPointer.elementAt(i).value = plaintext[i];
    }
    for (var i = 0; i < nonce.length; i++) {
      noncePointer.elementAt(i).value = nonce[i];
    }
    for (var i = 0; i < keyPair.pk.length; i++) {
      pkPointer.elementAt(i).value = keyPair.pk[i];
    }
    for (var i = 0; i < keyPair.sk.length; i++) {
      skPointer.elementAt(i).value = keyPair.sk[i];
    }

    try {
      // Call crypto_box_easy to encrypt the message
      final result = crypto_box_easy(
        ciphertextPointer.cast<ffi.UnsignedChar>(),
        plaintextPointer.cast<ffi.UnsignedChar>(),
        plaintext.length,
        noncePointer.cast<ffi.UnsignedChar>(),
        pkPointer.cast<ffi.UnsignedChar>(),
        skPointer.cast<ffi.UnsignedChar>(),
      );

      if (result == 0) {
        final ciphertextList = ciphertextPointer.asTypedList(ciphertextLength);
        // Clone the original list
        return Uint8List.fromList(List.from(ciphertextList));
      } else {
        debugPrint('[Lazysodium] Crypto box easy failed.');
        return Uint8List(0);
      }
    } finally {
      // Free allocated memory
      calloc.free(plaintextPointer);
      calloc.free(ciphertextPointer);
      calloc.free(noncePointer);
      calloc.free(pkPointer);
      calloc.free(skPointer);
    }
  }

  Uint8List cryptoBoxOpenEasy(
    Uint8List ciphertext,
    Uint8List nonce,
    KeyPair keyPair,
  ) {
    final plaintextLength = ciphertext.length - crypto_box_MACBYTES;
    final plaintextPointer = calloc<ffi.Uint8>(plaintextLength);
    final ciphertextPointer = calloc<ffi.Uint8>(ciphertext.length);
    final noncePointer = calloc<ffi.Uint8>(crypto_box_NONCEBYTES);
    final pkPointer = calloc<ffi.Uint8>(crypto_box_PUBLICKEYBYTES);
    final skPointer = calloc<ffi.Uint8>(crypto_box_SECRETKEYBYTES);

    // Fill the nonce and key with your values
    for (var i = 0; i < ciphertext.length; i++) {
      ciphertextPointer.elementAt(i).value = ciphertext[i];
    }
    for (var i = 0; i < nonce.length; i++) {
      noncePointer.elementAt(i).value = nonce[i];
    }
    for (var i = 0; i < keyPair.pk.length; i++) {
      pkPointer.elementAt(i).value = keyPair.pk[i];
    }
    for (var i = 0; i < keyPair.sk.length; i++) {
      skPointer.elementAt(i).value = keyPair.sk[i];
    }

    try {
      // Call crypto_box_open_easy to decrypt the message
      final result = crypto_box_open_easy(
        plaintextPointer.cast<ffi.UnsignedChar>(),
        ciphertextPointer.cast<ffi.UnsignedChar>(),
        ciphertext.length,
        noncePointer.cast<ffi.UnsignedChar>(),
        pkPointer.cast<ffi.UnsignedChar>(),
        skPointer.cast<ffi.UnsignedChar>(),
      );

      if (result == 0) {
        final decryptedMessageList =
            plaintextPointer.asTypedList(plaintextLength);
        // Clone the original list
        return Uint8List.fromList(List.from(decryptedMessageList));
      } else {
        debugPrint('[Lazysodium] Crypto box open easy failed.');
        return Uint8List(0);
      }
    } finally {
      // Free allocated memory
      calloc.free(plaintextPointer);
      calloc.free(ciphertextPointer);
      calloc.free(noncePointer);
      calloc.free(pkPointer);
      calloc.free(skPointer);
    }
  }
}
