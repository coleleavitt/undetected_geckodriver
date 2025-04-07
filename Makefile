# Makefile for Firefox WebDriver Detection Bypass Tool

.PHONY: all build test clean coverage check fmt

# Default target
all: build test

# Build the project
build:
	cargo build

# Run tests without coverage
test:
	cargo test

# Clean build artifacts and coverage data
clean:
	cargo clean
	rm -rf ./coverage/
	rm -f undetected_geckodriver-*.profraw

# Run clippy for linting
check:
	cargo clippy -- -D warnings

# Format code
fmt:
	cargo fmt

coverage:
	# Clean previous results
	$(MAKE) clean

	# First build the binary normally so it exists for the tests
	cargo build

	# Set up environment variables for coverage instrumentation
	CARGO_INCREMENTAL=0 \
	RUSTFLAGS="-Cinstrument-coverage -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off" \
	LLVM_PROFILE_FILE="undetected_geckodriver-%p-%m.profraw" \
	cargo test --verbose

	# Generate coverage report with grcov
	grcov . --binary-path ./target/debug/ \
		-s . \
		-t html \
		--branch \
		--ignore-not-existing \
		--ignore "/*" \
		--ignore "target/*" \
		-o ./coverage/

	# Print report location
	@echo "Coverage report generated at ./coverage/index.html"

	# Try to open the report (works on Linux and macOS)
	xdg-open ./coverage/index.html 2>/dev/null || open ./coverage/index.html 2>/dev/null || \
		echo "Please open ./coverage/index.html in your browser"

# Check if all prerequisites are installed
check-prereqs:
	@echo "Checking prerequisites..."
	@which cargo > /dev/null || (echo "cargo not found, please install Rust" && exit 1)
	@which grcov > /dev/null || (echo "grcov not found, please install: cargo install grcov" && exit 1)
	@rustup component list | grep "llvm-tools-preview" > /dev/null || \
		(echo "llvm-tools-preview not found, please install: rustup component add llvm-tools-preview" && exit 1)
	@echo "All prerequisites installed!"

# Help target
help:
	@echo "Available targets:"
	@echo "  all:          Build and test the project (default)"
	@echo "  build:        Build the project"
	@echo "  test:         Run tests"
	@echo "  clean:        Remove build artifacts and coverage data"
	@echo "  check:        Run clippy for linting"
	@echo "  fmt:          Format code with rustfmt"
	@echo "  coverage:     Generate code coverage report"
	@echo "  check-prereqs: Check if all prerequisites are installed"
	@echo "  help:         Show this help message"
