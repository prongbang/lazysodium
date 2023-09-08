import 'package:lazysodium/lazysodium.dart';

class KeyPairFactory {
  final Lazysodium lazysodium;

  KeyPairFactory(this.lazysodium);

  Future<KeyPair> create() async {
    return lazysodium.cryptoKxKeyPair();
  }
}
