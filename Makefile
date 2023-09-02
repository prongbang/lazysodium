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
