require:
	cargo install flutter_rust_bridge_codegen
	cargo install cargo-expand

gen:
	flutter_rust_bridge_codegen \
		--skip-deps-check \
		--rust-input lazysodium/src/api.rs \
		--dart-output lib/lazysodium.g.dart \
		--dart-decl-output lib/lazysodium.d.dart \
		-c ios/Runner/lazysodium.h

build_android:
	cargo build --target aarch64-linux-android --release
	cargo build --target armv7-linux-androideabi --release
	cargo build --target i686-linux-android --release
	cargo build --target x86_64-linux-android --release
	cargo build --target arm-linux-androideabi --release