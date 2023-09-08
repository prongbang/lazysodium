import 'dart:convert';

import 'package:dio/dio.dart';
import 'package:lazysodium_example/crypto/client_key_factory.dart';
import 'package:lazysodium_example/crypto/e2_e_cryptography.dart';
import 'package:lazysodium_example/crypto/server_key_factory.dart';

class CryptoInterceptor extends InterceptorsWrapper {
  final E2ECryptography e2eCryptography;
  final ServerKeyFactory serverKeyFactory;
  final ClientKeyFactory clientKeyFactory;

  CryptoInterceptor(
    this.e2eCryptography,
    this.serverKeyFactory,
    this.clientKeyFactory,
  );

  @override
  Future onRequest(
    RequestOptions options,
    RequestInterceptorHandler handler,
  ) async {
    print("REQUEST[${options.method}] => PATH: ${options.path}");

    final body = jsonEncode(options.data);

    final value = await e2eCryptography.encrypt(body);

    options.data = <String, String>{
      'value': value,
    };

    return super.onRequest(options, handler);
  }

  @override
  void onResponse(
    Response response,
    ResponseInterceptorHandler handler,
  ) async {
    print(
      "RESPONSE[${response.statusCode}] => PATH: ${response.requestOptions.path}",
    );

    // Get Payload
    final data = response.data;
    print('data: $data');

    Map<String, dynamic> json = data['json'];
    String ciphertext = json['value'];

    final value = await e2eCryptography.decrypt(ciphertext);

    print('value: $value');

    response.data = jsonDecode(value);

    return super.onResponse(response, handler);
  }

  @override
  void onError(
    DioException err,
    ErrorInterceptorHandler handler,
  ) async {
    print(
      "ERROR[${err.response?.statusCode}] => PATH: ${err.requestOptions.path}",
    );
    return super.onError(err, handler);
  }
}
