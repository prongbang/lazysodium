import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart' as f;
import 'package:lazysodium/lazysodium.binding.dart';

extension LazysodiumHelperExtension on LazysodiumBinding {
  Uint8List randomBytesBuf(int size) {
    // Allocate memory for the binary data
    final buffer = calloc<ffi.Uint8>();

    try {
      // Call sodium_hex2bin to perform the conversion
      randombytes_buf(buffer.cast<ffi.Void>(), size);
      final binData = buffer.asTypedList(size);

      // Clone the original list
      return Uint8List.fromList(List.from(binData));
    } finally {
      // Free allocated memory
      calloc.free(buffer);
    }
  }

  String bin2Hex(Uint8List bytes) {
    final hexMaxLen = bytes.length * 2 + 1;
    final hexPointer = calloc<ffi.Char>(hexMaxLen);
    final binPointer = calloc<ffi.Uint8>(bytes.length);

    try {
      // Copy the binary data into the allocated buffer
      for (var i = 0; i < bytes.length; i++) {
        binPointer.elementAt(i).value = bytes[i];
      }

      // Convert binary data to hexadecimal
      final result = sodium_bin2hex(
        hexPointer,
        hexMaxLen,
        binPointer.cast<ffi.UnsignedChar>(),
        bytes.length,
      );

      List<int> output = [];
      if (result != ffi.nullptr) {
        for (var i = 0; i < hexMaxLen - 1; i++) {
          output.add(result[i]);
        }
      } else {
        f.debugPrint('[Lazysodium] Conversion bin2Hex failed.');
      }
      return String.fromCharCodes(output.toList());
    } finally {
      // Free allocated memory for hexPointer
      calloc.free(binPointer);
      calloc.free(hexPointer);
    }
  }

  Uint8List hex2Bin(String hexString) {
    final hexPointer = hexString.toNativeUtf8().cast<ffi.Char>();

    // Allocate memory for the binary data
    final binMaxLen = hexString.length ~/ 2;
    final binPointer = calloc<ffi.Uint8>(binMaxLen);
    final binLen = calloc<ffi.Size>();

    try {
      // Call sodium_hex2bin to perform the conversion
      final result = sodium_hex2bin(
        binPointer.cast<ffi.UnsignedChar>(),
        binMaxLen,
        hexPointer,
        hexString.length,
        ffi.nullptr,
        binLen,
        ffi.nullptr,
      );

      if (result == 0) {
        final binData = binPointer.asTypedList(binLen.value);

        // Clone the original list
        return Uint8List.fromList(List.from(binData));
      } else {
        f.debugPrint('[Lazysodium] Conversion hex2Bin failed.');
      }
      return Uint8List(0);
    } finally {
      // Free allocated memory
      calloc.free(binPointer);
      calloc.free(binLen);
      calloc.free(hexPointer);
    }
  }
}
