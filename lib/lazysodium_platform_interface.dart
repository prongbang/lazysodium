import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'lazysodium_method_channel.dart';

abstract class LazysodiumPlatform extends PlatformInterface {
  /// Constructs a LazysodiumPlatform.
  LazysodiumPlatform() : super(token: _token);

  static final Object _token = Object();

  static LazysodiumPlatform _instance = MethodChannelLazysodium();

  /// The default instance of [LazysodiumPlatform] to use.
  ///
  /// Defaults to [MethodChannelLazysodium].
  static LazysodiumPlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [LazysodiumPlatform] when
  /// they register themselves.
  static set instance(LazysodiumPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> getPlatformVersion() {
    throw UnimplementedError('platformVersion() has not been implemented.');
  }
}
