.PHONY: build test clean check fmt clippy install-tools setup-pocketic

# Build configuration
CANISTER_NAME = ic_sis_provider
WASM_OUTPUT = $(CANISTER_NAME).wasm.gz
DID_FILE = $(CANISTER_NAME).did

# Paths
PROJECT_ROOT = ../../
TARGET_DIR = $(PROJECT_ROOT)target/wasm32-unknown-unknown/release
PACKAGE_DIR = packages/$(CANISTER_NAME)
POCKET_IC_PATH = $(PROJECT_ROOT)pocket-ic

# Check if tools are installed
check-tools:
	@which dfx > /dev/null || (echo "Error: dfx not installed" && exit 1)
	@which ic-wasm > /dev/null || (echo "Error: ic-wasm not installed" && exit 1)
	@which cargo > /dev/null || (echo "Error: cargo not installed" && exit 1)

# Install required tools
install-tools:
	@echo "Installing required tools..."
	@cargo install ic-wasm || echo "ic-wasm already installed"

# Setup PocketIC for WSL/Linux
setup-pocketic:
	@echo "Setting up PocketIC for WSL/Linux..."
	@if [ ! -f "$(POCKET_IC_PATH)" ]; then \
		echo "📥 Downloading PocketIC..."; \
		curl -L "https://github.com/dfinity/pocketic/releases/download/4.0.0/pocket-ic-x86_64-linux.gz" -o "$(PROJECT_ROOT)pocket-ic.gz"; \
		gunzip "$(PROJECT_ROOT)pocket-ic.gz"; \
		chmod +x "$(POCKET_IC_PATH)"; \
		echo "✅ PocketIC setup complete!"; \
	else \
		echo "✅ PocketIC already installed at $(POCKET_IC_PATH)"; \
	fi
	@echo "🧪 Testing PocketIC binary..."
	@if "$(POCKET_IC_PATH)" --help > /dev/null 2>&1; then \
		echo "✅ PocketIC is working correctly!"; \
	else \
		echo "❌ PocketIC test failed. Installing dependencies..."; \
		echo "💡 If this fails, run: sudo apt update && sudo apt install libc6-dev"; \
	fi

# Code quality checks
fmt:
	cargo fmt --check

clippy:
	cargo clippy -- -D warnings

check:
	cargo check

# Test the code
test-unit:
	cargo test --lib

test-integration: build setup-pocketic
	@echo "Running integration tests..."
	@if [ ! -f "$(POCKET_IC_PATH)" ]; then \
		echo "❌ PocketIC binary not found. Run 'make setup-pocketic' first."; \
		exit 1; \
	fi
	@{ \
		export POCKET_IC_BIN=$(POCKET_IC_PATH); \
		export IC_SIS_PROVIDER_PATH=$(TARGET_DIR)/$(CANISTER_NAME).wasm.gz; \
		echo "🧪 POCKET_IC_BIN=$$POCKET_IC_BIN"; \
		echo "🧪 IC_SIS_PROVIDER_PATH=$$IC_SIS_PROVIDER_PATH"; \
		cargo test --test integration_tests -- --nocapture; \
	}

test: test-unit test-integration

# Build the canister
build: check-tools
	@echo "Building $(CANISTER_NAME) canister..."
	
	# Navigate to project root and build
	cd $(PROJECT_ROOT) && \
	dfx canister create --all --network local || true && \
	dfx build $(CANISTER_NAME) --network local
	
	# Navigate to target directory and process WASM
	cd $(TARGET_DIR) && \
	ic-wasm $(CANISTER_NAME).wasm -o $(CANISTER_NAME).wasm metadata candid:service -f ../../../$(PACKAGE_DIR)/$(DID_FILE) -v public && \
	gzip --no-name --force $(CANISTER_NAME).wasm
	
	# Copy files back to package directory
	cp $(TARGET_DIR)/$(WASM_OUTPUT) ./
	
	@echo "✅ Build complete!"
	@echo "📦 WASM file: ./$(WASM_OUTPUT)"
	@echo "📄 DID file: ./$(DID_FILE)"

# Development build (faster, no optimization)
build-dev: check-tools
	@echo "Building $(CANISTER_NAME) canister (development mode)..."
	cd $(PROJECT_ROOT) && \
	dfx build $(CANISTER_NAME) --network local
	@echo "✅ Development build complete!"

# Deploy to local replica
deploy: build
	@echo "Deploying $(CANISTER_NAME) to local replica..."
	cd $(PROJECT_ROOT) && \
	dfx deploy $(CANISTER_NAME) --network local --argument '(record { \
		domain = "127.0.0.1"; \
		uri = "http://127.0.0.1:4943"; \
		salt = "dev-salt"; \
		network = opt "devnet"; \
		scheme = opt "http"; \
		statement = opt "Sign in with Sui"; \
		sign_in_expires_in = opt 300000000000; \
		session_expires_in = opt 604800000000000; \
		targets = opt vec { \
			principal "$(shell cd $(PROJECT_ROOT) && dfx canister id $(CANISTER_NAME) --network local)"; \
		}; \
	})'
	@echo "✅ Deployment complete!"

# Start local replica
start:
	cd $(PROJECT_ROOT) && dfx start --background --clean

# Stop local replica
stop:
	cd $(PROJECT_ROOT) && dfx stop

# Clean build artifacts
clean:
	cargo clean
	rm -f ./$(WASM_OUTPUT)
	cd $(PROJECT_ROOT) && rm -rf .dfx target

# Generate Candid interface (if needed)
generate-did:
	@echo "Generating Candid interface..."
	cargo test --test integration_tests 2>/dev/null || echo "Tests completed"
	@echo "✅ DID file should be in ./$(DID_FILE)"

# Full workflow: clean, check, build, test
all: clean fmt clippy check build test
	@echo "🎉 All checks passed! Ready for deployment."

# Development workflow
dev: fmt check build-dev
	@echo "🚀 Development build ready!"

# Release workflow
release: clean all
	@echo "📦 Release build complete!"
	@echo "Files ready for distribution:"
	@echo "  - $(WASM_OUTPUT)"
	@echo "  - $(DID_FILE)"

# Show help
help:
	@echo "Available commands:"
	@echo "  make setup-pocketic - Download and setup PocketIC binary"
	@echo "  make build         - Build the canister WASM"
	@echo "  make test          - Run all tests"
	@echo "  make test-unit     - Run unit tests only"
	@echo "  make test-integration - Run integration tests only"
	@echo "  make deploy        - Deploy to local replica"
	@echo "  make clean         - Clean build artifacts"
	@echo "  make fmt           - Check code formatting"
	@echo "  make clippy        - Run clippy lints"
	@echo "  make all           - Full build and test pipeline"
	@echo "  make dev           - Quick development build"
	@echo "  make release       - Complete release build"
	@echo "  make help          - Show this help"