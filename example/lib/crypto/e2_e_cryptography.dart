import 'dart:typed_data';

import 'package:lazysodium/lazysodium.dart';
import 'package:lazysodium_example/crypto/client_key_factory.dart';
import 'package:lazysodium_example/crypto/key_factory.dart';
import 'package:lazysodium_example/crypto/server_key_factory.dart';

class E2ECryptography {
  final ServerKeyFactory serverKeyFactory;
  final ClientKeyFactory clientKeyFactory;
  final Lazysodium lazysodium;

  E2ECryptography(this.serverKeyFactory, this.clientKeyFactory, this.lazysodium);

  Future<String> encrypt(String plaintext) async {
    final sharedKey = serverKeyFactory.key();

    final nonceSize = lazysodium.crypto_secretbox_noncebytes();
    final nonceBytes = lazysodium.randomBytesBuf(nonceSize);
    final nonceHex = lazysodium.bin2Hex(nonceBytes);

    final cipherBytes = lazysodium.cryptoSecretBoxEasy(
      Uint8List.fromList(plaintext.codeUnits),
      nonceBytes,
      Uint8List.fromList(sharedKey.codeUnits),
    );
    final ciphertext = lazysodium.bin2Hex(cipherBytes);

    return '$nonceHex$ciphertext';
  }

  Future<String> decrypt(String ciphertext) async {
    final sharedKey = clientKeyFactory.key();

    final nonceSize = lazysodium.crypto_secretbox_noncebytes() * 2;
    final nonceHex = ciphertext.substring(0, nonceSize);
    final nonceBytes = lazysodium.hex2Bin(nonceHex);
    final cipherHex = ciphertext.substring(nonceSize);
    final cipherBytes = lazysodium.hex2Bin(cipherHex);

    final plainBytes = lazysodium.cryptoSecretBoxOpenEasy(
      cipherBytes,
      nonceBytes,
      Uint8List.fromList(sharedKey.codeUnits),
    );

    return String.fromCharCodes(plainBytes);
  }
}
