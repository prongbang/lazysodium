require:
	cargo install flutter_rust_bridge_codegen
	cargo install cargo-expand
	cargo install cargo-xcode
	cargo install cargo-ndk
	cargo install cbindgen
	dart pub global activate ffigen
	arch -arm64 brew install llvm

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

build_ios:
	cargo lipo && cp target/universal/debug/liblazysodium.a ../ios/Runner

build_android:
	cargo build --target aarch64-linux-android --release
	cargo build --target armv7-linux-androideabi --release
	cargo build --target i686-linux-android --release
	cargo build --target x86_64-linux-android --release
	cargo build --target arm-linux-androideabi --release