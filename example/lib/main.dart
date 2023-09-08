import 'dart:convert';

import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:get_it/get_it.dart';
import 'dart:async';

import 'package:lazysodium/lazysodium.dart';
import 'package:lazysodium_example/crypto/client_key_factory.dart';
import 'package:lazysodium_example/crypto/key_pair_factory.dart';
import 'package:lazysodium_example/crypto/server_key_factory.dart';
import 'package:lazysodium_example/crypto/shared_key_factory.dart';
import 'package:lazysodium_example/service_locator.dart';

void main() {
  Lazysodium.init();

  ServiceLocator.setup();

  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  final _responseList = [];

  @override
  void initState() {
    super.initState();
    _processKeyExchange();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Lazysodium'),
        ),
        body: Column(
          children: [
            Column(
              children: [
                const SizedBox(height: 16),
                ElevatedButton(
                  onPressed: () {
                    _processCallAPI();
                  },
                  child: const Text('CALL API'),
                ),
              ],
            ),
            Text('Response:'),
            Expanded(
              child: ListView.builder(
                itemCount: _responseList.length,
                itemBuilder: (context, index) {
                  final data = _responseList[index];
                  return Text(data);
                },
              ),
            ),
          ],
        ),
      ),
    );
  }

  void _processKeyExchange() async {
    final keyPairFactory = GetIt.I.get<KeyPairFactory>();
    final sharedKeyFactory = GetIt.I.get<SharedKeyFactory>();

    // Create Key Pair
    final clientKeyPair = await keyPairFactory.create();
    final serverKeyPair = await keyPairFactory.create();

    // Key Exchange
    final kxServerKeyPair = KeyPair(pk: clientKeyPair.pk, sk: serverKeyPair.sk);
    final kxClientKeyPair = KeyPair(pk: serverKeyPair.pk, sk: clientKeyPair.sk);
    ServerKeyFactory.sharedKey = await sharedKeyFactory.create(kxServerKeyPair);
    ClientKeyFactory.sharedKey = await sharedKeyFactory.create(kxClientKeyPair);
  }

  void _processCallAPI({int round = 10}) async {
    final dio = GetIt.I.get<Dio>();
    setState(() {
      _responseList.clear();
    });

    for (int i = 0; i < round; i++) {
      final response = await dio.post('/post', data: <String, dynamic>{
        'username': 'admin',
        'password': 'P@ssw0rd',
      });
      final data = response.data;
      print('data[$i]: $data');

      final resp = jsonEncode(data);
      _responseList.add(resp);
    }
    setState(() {});
  }
}
