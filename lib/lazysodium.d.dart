// AUTO GENERATED FILE, DO NOT EDIT.
// Generated by `flutter_rust_bridge`@ 1.81.0.
// ignore_for_file: non_constant_identifier_names, unused_element, duplicate_ignore, directives_ordering, curly_braces_in_flow_control_structures, unnecessary_lambdas, slash_for_doc_comments, prefer_const_literals_to_create_immutables, implicit_dynamic_list_literal, duplicate_import, unused_import, unnecessary_import, prefer_single_quotes, prefer_const_constructors, use_super_parameters, always_use_package_imports, annotate_overrides, invalid_use_of_protected_member, constant_identifier_names, invalid_use_of_internal_member, prefer_is_empty, unnecessary_const

import 'dart:convert';
import 'dart:async';
import 'package:meta/meta.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge.dart';
import 'package:uuid/uuid.dart';

abstract class Lazysodium {
  Future<KeyPair> cryptoKxKeypair(
      {required int pkSize, required int skSize, dynamic hint});

  FlutterRustBridgeTaskConstMeta get kCryptoKxKeypairConstMeta;

  Future<Uint8List> cryptoBoxBeforenm({required KeyPair keypair, dynamic hint});

  FlutterRustBridgeTaskConstMeta get kCryptoBoxBeforenmConstMeta;

  Future<String> cryptoBoxBeforenmHex({required KeyPair keypair, dynamic hint});

  FlutterRustBridgeTaskConstMeta get kCryptoBoxBeforenmHexConstMeta;

  Future<SessionKey> cryptoKxClientSessionKeys(
      {required Uint8List clientPk,
      required Uint8List clientSk,
      required Uint8List serverPk,
      dynamic hint});

  FlutterRustBridgeTaskConstMeta get kCryptoKxClientSessionKeysConstMeta;

  Future<SessionKey> cryptoKxServerSessionKeys(
      {required Uint8List serverPk,
      required Uint8List serverSk,
      required Uint8List clientPk,
      dynamic hint});

  FlutterRustBridgeTaskConstMeta get kCryptoKxServerSessionKeysConstMeta;

  Future<Uint8List> cryptoStreamChacha20Xor(
      {required Uint8List message,
      required Uint8List nonce,
      required Uint8List key,
      dynamic hint});

  FlutterRustBridgeTaskConstMeta get kCryptoStreamChacha20XorConstMeta;

  Future<Uint8List> cryptoAeadChacha20Poly1305Encrypt(
      {required Uint8List message,
      required Uint8List additionalData,
      required Uint8List nonce,
      required Uint8List key,
      dynamic hint});

  FlutterRustBridgeTaskConstMeta
      get kCryptoAeadChacha20Poly1305EncryptConstMeta;

  Future<String> binToHex({required Uint8List data, dynamic hint});

  FlutterRustBridgeTaskConstMeta get kBinToHexConstMeta;

  Future<Uint8List> hexToBin({required String hex, dynamic hint});

  FlutterRustBridgeTaskConstMeta get kHexToBinConstMeta;

  Future<Uint8List> randomBytesBuf({required int size, dynamic hint});

  FlutterRustBridgeTaskConstMeta get kRandomBytesBufConstMeta;

  Future<Uint8List> randomNonceBytes({dynamic hint});

  FlutterRustBridgeTaskConstMeta get kRandomNonceBytesConstMeta;

  Future<String> randomNonceHex({dynamic hint});

  FlutterRustBridgeTaskConstMeta get kRandomNonceHexConstMeta;
}

class KeyPair {
  final Uint8List pk;
  final Uint8List sk;

  const KeyPair({
    required this.pk,
    required this.sk,
  });
}

class SessionKey {
  final Uint8List rx;
  final Uint8List tx;

  const SessionKey({
    required this.rx,
    required this.tx,
  });
}
