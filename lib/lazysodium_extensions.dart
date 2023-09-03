import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:flutter/cupertino.dart';
import 'package:lazysodium/lazysodium.dart';

extension LazysodiumExtension on LazysodiumBinding {
  Uint8List randomBytesBuf(int size) {
    // Allocate a buffer to hold the random data (you can choose the size)
    return using<Uint8List>((Arena arena) {
      final buffer = arena<ffi.UnsignedChar>();

      // Use the memory allocated to `buffer`.
      randombytes_buf(buffer.cast(), size);

      List<int> out = [];
      for (var i = 0; i < size; i++) {
        out.add(buffer[i]);
      }

      return Uint8List.fromList(out);
    });
  }

  String bin2Hex(Uint8List bytes) {
    return using<String>((Arena arena) {
      final binSize = bytes.length;
      final binPointer = arena<ffi.UnsignedChar>();

      final buffer = arena<ffi.Uint8>();

      // Copy the binary data into the allocated buffer
      for (var i = 0; i < binSize; i++) {
        binPointer.elementAt(i).value = bytes[i];
      }

      // Ensure enough space for the hex representation
      final hexMaxLen = (binSize * 2) + 1;

      final result = sodium_bin2hex(
          buffer.cast<ffi.Char>(), hexMaxLen, binPointer, binSize);

      List<int> out = [];
      if (result != ffi.nullptr) {
        for (var i = 0; i < hexMaxLen - 1; i++) {
          out.add(result[i]);
        }
      } else {
        debugPrint('[Lazysodium] Conversion bin2Hex failed.');
      }

      return String.fromCharCodes(out.toList());
    });
  }

  Uint8List hex2Bin(String hexString) {
    // Convert the hex string to a Dart string
    final hexPointer = hexString.toNativeUtf8().cast<ffi.Char>();

    // Allocate memory for the binary data
    final binMaxLen = hexString.length ~/ 2;
    final binPointer = calloc<ffi.Uint8>(binMaxLen);
    final binLen = calloc<ffi.Size>();

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

    List<int> output = [];
    if (result == 0) {
      final binData = binPointer.asTypedList(binLen.value);

      // Clone the original list
      output = List.from(binData);
    } else {
      debugPrint('[Lazysodium] Conversion hex2Bin failed.');
    }

    // Free allocated memory
    calloc.free(binPointer);
    calloc.free(binLen);
    calloc.free(hexPointer);

    if (result == 0) {
      return Uint8List.fromList(output);
    }
    return Uint8List(0);
  }
}

extension StringExtension on String {
  Int8List toCharArray({int? memoryWidth, bool zeroTerminated = false}) {
    final List<int> chars;
    if (zeroTerminated) {
      chars = utf8.encode(this).takeWhile((value) => value != 0).toList();
    } else {
      chars = utf8.encode(this);
    }

    if (memoryWidth != null) {
      if (chars.length > memoryWidth) {
        throw ArgumentError.value(
          memoryWidth,
          'memoryWidth',
          'must be at least as long as the encoded string ${chars.length} bytes',
        );
      }

      return Int8List(memoryWidth)
        ..setRange(0, chars.length, chars)
        ..fillRange(chars.length, memoryWidth, 0);
    } else {
      return Int8List.fromList(chars);
    }
  }
}

extension Int8ListExtension on Int8List {
  String toDartString({bool zeroTerminated = false}) {
    if (zeroTerminated) {
      return utf8.decode(takeWhile((value) => value != 0).toList());
    } else {
      return utf8.decode(this);
    }
  }

  Uint8List unsignedView() => Uint8List.view(buffer);
}

extension Uint8ListExtension on Uint8List {
  Int8List signedView() => Int8List.view(buffer);
}
