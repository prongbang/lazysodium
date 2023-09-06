import 'package:lazysodium/lazysodium.binding.dart';
import 'package:lazysodium/lazysodium.loader.dart';

export 'lazysodium.binding.dart';
export 'lazysodium_extensions.dart';
export 'kx/lazysodium_kx.dart';
export 'crypto/lazysodium_box_beforenm.dart';
export 'crypto/lazysodium_box.dart';
export 'crypto/lazysodium_secret_box.dart';
export 'crypto/lazysodium_stream_chacha20_xor.dart';

class Lazysodium extends LazysodiumBinding {
  Lazysodium(super.dynamicLibrary);

  static void init() {
    final sodium = Lazysodium.instance();
    if (sodium.sodium_init() == -1) {
      throw Exception('Lazysodium initialization failed');
    }
  }

  factory Lazysodium.instance() => Lazysodium(lazysodium);
}
