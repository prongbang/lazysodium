
import 'lazysodium_platform_interface.dart';

class Lazysodium {
  Future<String?> getPlatformVersion() {
    return LazysodiumPlatform.instance.getPlatformVersion();
  }
}
