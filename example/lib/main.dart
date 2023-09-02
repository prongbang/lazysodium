import 'package:flutter/material.dart';
import 'dart:async';

import 'package:lazysodium/lazysodium.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  int _secretBoxNonceBytes = -1;
  final _lazysodium = Lazysodium.instance();

  @override
  void initState() {
    super.initState();
    _processSecretBoxNonceBytesState();
  }

  Future<void> _processSecretBoxNonceBytesState() async {
    int nonceBytes;
    try {
      nonceBytes = _lazysodium.crypto_secretbox_noncebytes();
    } on Exception {
      nonceBytes = -1;
    }

    // If the widget was removed from the tree while the asynchronous platform
    // message was in flight, we want to discard the reply rather than calling
    // setState to update our non-existent appearance.
    if (!mounted) return;

    setState(() {
      _secretBoxNonceBytes = nonceBytes;
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Lazysodium'),
        ),
        body: Center(
          child: Text('Nonce Bytes: $_secretBoxNonceBytes\n'),
        ),
      ),
    );
  }
}
