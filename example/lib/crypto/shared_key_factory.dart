import 'package:lazysodium/lazysodium.dart';

class SharedKeyFactory {
  final Lazysodium lazysodium;

  SharedKeyFactory(this.lazysodium);

  Future<String> create(KeyPair keyPair) async {
    final sharedKeyBytes = lazysodium.cryptoBoxBeforeNm(keyPair);
    return String.fromCharCodes(sharedKeyBytes);
  }
}
