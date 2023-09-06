import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart';
import 'dart:ffi' as ffi;

import 'package:lazysodium/lazysodium.binding.dart';

extension LazysodiumStreamChaCha20XorExtension on LazysodiumBinding {
  Uint8List cryptoStreamChaCha20Xor(
    Uint8List message,
    Uint8List nonce,
    Uint8List key,
  ) {
    // Allocate memory for the output stream (ciphertext), nonce (n), and key (k)
    final ciphertextPointer = calloc<ffi.Uint8>(message.length);
    final plaintextPointer = calloc<ffi.Uint8>(message.length);
    final noncePointer = calloc<ffi.Uint8>(nonce.length);
    final keyPointer = calloc<ffi.Uint8>(crypto_stream_chacha20_KEYBYTES);

    // Fill the nonce and key with your values
    for (var i = 0; i < nonce.length; i++) {
      noncePointer.elementAt(i).value = nonce[i];
    }
    for (var i = 0; i < key.length; i++) {
      keyPointer.elementAt(i).value = key[i];
    }
    for (var i = 0; i < message.length; i++) {
      plaintextPointer.elementAt(i).value = message[i];
    }

    try {
      // Call crypto_stream_chacha20 to generate the stream
      final result = crypto_stream_chacha20_xor(
        ciphertextPointer.cast<ffi.UnsignedChar>(),
        plaintextPointer.cast<ffi.UnsignedChar>(),
        message.length,
        noncePointer.cast<ffi.UnsignedChar>(),
        keyPointer.cast<ffi.UnsignedChar>(),
      );

      if (result == 0) {
        final ciphertextList = ciphertextPointer.asTypedList(message.length);
        // Clone the original list
        return Uint8List.fromList(List.from(ciphertextList));
      } else {
        debugPrint('[Lazysodium] Crypto stream ChaCha20 failed.');
        return Uint8List(0);
      }
    } finally {
      // Free allocated memory
      calloc.free(ciphertextPointer);
      calloc.free(plaintextPointer);
      calloc.free(noncePointer);
      calloc.free(keyPointer);
    }
  }
}
