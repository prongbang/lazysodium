#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint lazysodium.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'lazysodium'
  s.version          = '1.0.0'
  s.summary          = 'Lazysodium is a comprehensive Flutter implementation of the Libsodium library.'
  s.description      = <<-DESC
Lazysodium is a comprehensive Flutter implementation of the Libsodium library.
                       DESC
  s.homepage         = 'https://github.com/prongbang/lazysodium'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'wachasit' => 'email@example.com' }
  s.source           = { :path => '.' }
  s.public_header_files = 'Classes**/*.h'
  s.source_files = 'Classes/**/*'
  s.vendored_libraries = "**/*.a"
  s.dependency 'Flutter'
  s.platform = :ios, '11.0'

  # Flutter.framework does not contain a i386 slice. Only x86_64 simulators are supported.
  # s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'VALID_ARCHS[sdk=iphonesimulator*]' => 'x86_64' }
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'

  # libsodium
  # s.xcconfig = { 'OTHER_LDFLAGS' => '-force_load "${PODS_ROOT}/../.symlinks/plugins/lazysodium/ios/libsodium.a"'}
  s.xcconfig = {
          'OTHER_LDFLAGS[sdk=iphoneos*]' => '$(inherited) -force_load "${PODS_ROOT}/../.symlinks/plugins/lazysodium/ios/libsodium.a"',
          'OTHER_LDFLAGS[sdk=iphonesimulator*]' => '$(inherited) -force_load "${PODS_ROOT}/../.symlinks/plugins/lazysodium/ios/libsodium.a"',
  }
end
