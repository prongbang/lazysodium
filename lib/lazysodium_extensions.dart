import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

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
}

extension Uint8ListExtension on Uint8List {
  Pointer<Uint8> toPointer({int? size}) {
    final p = calloc<Uint8>(size ?? length);
    p.asTypedList(size ?? length).setAll(0, this);
    return p;
  }
}

extension Uint8PointerExtension on Pointer<Uint8> {
  Uint8List toList(int length) {
    final builder = BytesBuilder();
    for (var i = 0; i < length; i++) {
      builder.addByte(this[i]);
    }
    return builder.takeBytes();
  }
}
