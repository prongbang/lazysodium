import 'package:flutter_test/flutter_test.dart';
import 'package:lazysodium/lazysodium.dart';
import 'package:lazysodium/lazysodium_platform_interface.dart';
import 'package:lazysodium/lazysodium_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockLazysodiumPlatform
    with MockPlatformInterfaceMixin
    implements LazysodiumPlatform {

  @override
  Future<String?> getPlatformVersion() => Future.value('42');
}

void main() {
  final LazysodiumPlatform initialPlatform = LazysodiumPlatform.instance;

  test('$MethodChannelLazysodium is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelLazysodium>());
  });

  test('getPlatformVersion', () async {
    Lazysodium lazysodiumPlugin = Lazysodium();
    MockLazysodiumPlatform fakePlatform = MockLazysodiumPlatform();
    LazysodiumPlatform.instance = fakePlatform;

    expect(await lazysodiumPlugin.getPlatformVersion(), '42');
  });
}
