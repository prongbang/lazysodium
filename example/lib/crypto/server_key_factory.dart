import 'package:lazysodium_example/crypto/key_factory.dart';

class ServerKeyFactory implements KeyFactory {
  static String sharedKey = '';

  @override
  String key() => sharedKey;
}
