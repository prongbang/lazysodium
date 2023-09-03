import 'dart:ffi';
import 'dart:io';

import 'package:lazysodium/lazysodium.binding.dart';

export 'lazysodium.binding.dart';
export 'lazysodium_extensions.dart';

class Lazysodium extends LazysodiumBinding {
  Lazysodium(super.dynamicLibrary);

  Future<String?> getPlatformVersion() async {
    return "";
  }

  static Lazysodium instance() => Lazysodium(_load());
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
