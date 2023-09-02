import 'dart:ffi';
import 'dart:io';

import 'package:lazysodium/lazysodium.d.dart';
import 'package:lazysodium/lazysodium.g.dart';

export 'lazysodium.d.dart';
export 'lazysodium.g.dart';

class LazySodium {
  Future<String?> getPlatformVersion() async {
    return "";
  }

  static Lazysodium instance() => LazysodiumImpl(_load());
}

final DynamicLibrary lazysodium = _load();

DynamicLibrary _load() {
  if (Platform.isAndroid) {
    return DynamicLibrary.open('libsodium.so');
  }
  if (Platform.isIOS) {
    return DynamicLibrary.process();
  }
  if (Platform.isMacOS) {
    // assuming user installed libsodium as per the installation instructions
    // see also https://libsodium.gitbook.io/doc/installation
    return DynamicLibrary.open('/usr/local/lib/libsodium.dylib');
  }
  if (Platform.isLinux) {
    // assuming user installed libsodium as per the installation instructions
    // see also https://libsodium.gitbook.io/doc/installation
    return DynamicLibrary.open('/usr/local/lib/libsodium.so');
  }
  if (Platform.isWindows) {
    // assuming user installed libsodium as per the installation instructions
    // see also https://py-ipv8.readthedocs.io/en/latest/preliminaries/install_libsodium/
    return DynamicLibrary.open('C:\\Windows\\System32\\libsodium.dll');
  }
  throw Exception('platform not supported');
}
