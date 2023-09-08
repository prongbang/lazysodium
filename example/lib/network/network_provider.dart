import 'package:dio/dio.dart';
import 'package:lazysodium_example/network/crypto_interceptor.dart';

class NetworkProvider {
  final CryptoInterceptor cryptoInterceptor;

  NetworkProvider(this.cryptoInterceptor);

  Dio create() {
    final options = BaseOptions(
      connectTimeout: const Duration(seconds: 30),
      sendTimeout: const Duration(seconds: 30),
      receiveTimeout: const Duration(seconds: 30),
      baseUrl: 'https://httpbin.org',
    );

    return Dio(options)
      ..interceptors.add(LogInterceptor())
      ..interceptors.add(cryptoInterceptor);
  }
}
