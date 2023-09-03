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

      // Release the allocated buffer when done
      arena.releaseAll();

      return Uint8List.fromList(out);
    });
  }

  String bin2Hex(Uint8List bytes) {
    return using<String>((Arena arena) {
      final binSize = bytes.length;
      final binPointer = arena<ffi.UnsignedChar>();

      final buffer = arena<ffi.Char>();

      // Copy the binary data into the allocated buffer
      for (var i = 0; i < binSize; i++) {
        binPointer.elementAt(i).value = bytes[i];
      }

      // Ensure enough space for the hex representation
      final hexMaxLen = (binSize * 2) + 1;

      final result = sodium_bin2hex(buffer, hexMaxLen, binPointer, binSize);

      List<int> out = [];
      if (result != ffi.nullptr) {
        for (var i = 0; i < hexMaxLen - 1; i++) {
          out.add(result[i]);
        }
      } else {
        debugPrint('Conversion failed.');
      }

      // Release the allocated buffer when done
      arena.releaseAll();

      return String.fromCharCodes(out);
    });
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
