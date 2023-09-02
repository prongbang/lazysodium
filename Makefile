require:
	cargo install flutter_rust_bridge_codegen
	cargo install cargo-expand
	cargo install cargo-xcode
	cargo install cargo-ndk
	cargo install cbindgen
	cargo install cargo-lipo
	dart pub global activate ffigen
	arch -arm64 brew install llvm
	arch -arm64 brew install pkg-config
	arch -arm64 brew install cmake
	arch -arm64 brew install libsodium

new_project:
	dart run flutter_rust_bridge:serve --crate lazysodium

platform:
	flutter create --template=plugin --platforms=web,linux,windows,macos .

gen:
	flutter_rust_bridge_codegen \
		--skip-deps-check \
		--rust-input lazysodium/src/api.rs \
		--dart-output lib/lazysodium.g.dart \
		--dart-decl-output lib/lazysodium.d.dart \
		-c ios/Runner/lazysodium.h

gen_dart:
	dart run ffigen

publish:
	dart pub publish

nightly:
	rustup default nightly

stable:
	rustup default stable

before_build_android:
	rustup target add \
        aarch64-linux-android \
        armv7-linux-androideabi \
        x86_64-linux-android \
        i686-linux-android

build_android:
	export ANDROID_NDK_HOME=$HOME/Library/Android/sdk/ndk/25.2.9519653
	cargo ndk \
		-t armeabi-v7a \
		-t arm64-v8a \
		-t x86_64 \
		-t x86 \
		-o ../android/app/src/main/jniLibs build --release

before_build_ios:
	rustup update
	rustup target add aarch64-apple-ios x86_64-apple-ios

build_ios:
	export ANDROID_NDK_HOME=$HOME/Library/Android/sdk/ndk/25.2.9519653
	cargo lipo --release && cp target/universal/release/liblazysodium.a ../ios/Runner
