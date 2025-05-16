.PHONY: all build clean deploy test fmt

all: build

build:
	dfx canister create ic_sis_provider
	cargo build --target wasm32-unknown-unknown --release --package ic_sis_provider
	ic-wasm target/wasm32-unknown-unknown/release/ic_sis_provider.wasm -o target/wasm32-unknown-unknown/release/ic_sis_provider-opt.wasm shrink
	gzip -fk target/wasm32-unknown-unknown/release/ic_sis_provider-opt.wasm
	mv target/wasm32-unknown-unknown/release/ic_sis_provider-opt.wasm.gz ic_sis_provider.wasm.gz

deploy: build
	dfx canister install ic_sis_provider --wasm-module target/wasm32-unknown-unknown/release/ic_sis_provider-opt.wasm --argument '(record { domain = "example.com"; uri = "https://example.com"; salt = "test-salt"; network = opt "mainnet"; scheme = null; statement = null; sign_in_expires_in = null; session_expires_in = null; targets = null; runtime_features = null; })'

upgrade: build
	dfx canister install ic_sis_provider --wasm-module target/wasm32-unknown-unknown/release/ic_sis_provider-opt.wasm --argument '(record { domain = "example.com"; uri = "https://example.com"; salt = "test-salt"; network = opt "mainnet"; scheme = null; statement = null; sign_in_expires_in = null; session_expires_in = null; targets = null; runtime_features = null; })' --mode upgrade

test:
	cargo test

fmt:
	cargo fmt --all

clean:
	cargo clean
	rm -f ic_sis_provider.wasm.gz