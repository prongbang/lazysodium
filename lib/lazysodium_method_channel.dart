import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'lazysodium_platform_interface.dart';

/// An implementation of [LazysodiumPlatform] that uses method channels.
class MethodChannelLazysodium extends LazysodiumPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('lazysodium');

  @override
  Future<String?> getPlatformVersion() async {
    final version = await methodChannel.invokeMethod<String>('getPlatformVersion');
    return version;
  }
}
