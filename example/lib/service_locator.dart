import 'package:dio/dio.dart';
import 'package:get_it/get_it.dart';
import 'package:lazysodium/lazysodium.dart';
import 'package:lazysodium_example/crypto/client_key_factory.dart';
import 'package:lazysodium_example/crypto/e2_e_cryptography.dart';
import 'package:lazysodium_example/crypto/key_pair_factory.dart';
import 'package:lazysodium_example/crypto/server_key_factory.dart';
import 'package:lazysodium_example/crypto/shared_key_factory.dart';
import 'package:lazysodium_example/network/crypto_interceptor.dart';
import 'package:lazysodium_example/network/network_provider.dart';

class ServiceLocator {
  static void setup() {
    GetIt.I.registerFactory(() => Lazysodium.instance());
    GetIt.I.registerFactory(
      () => CryptoInterceptor(
        GetIt.I.get(),
        GetIt.I.get(),
        GetIt.I.get(),
      ),
    );
    GetIt.I.registerFactory(
      () => E2ECryptography(
        GetIt.I.get(),
        GetIt.I.get(),
        GetIt.I.get(),
      ),
    );
    GetIt.I.registerFactory(() => NetworkProvider(GetIt.I.get()));
    GetIt.I.registerLazySingleton(() => SharedKeyFactory(GetIt.I.get()));
    GetIt.I.registerLazySingleton(() => ServerKeyFactory());
    GetIt.I.registerLazySingleton(() => ClientKeyFactory());
    GetIt.I.registerLazySingleton(() => KeyPairFactory(GetIt.I.get()));
    GetIt.I.registerFactory<Dio>(() => GetIt.I.get<NetworkProvider>().create());
  }
}
