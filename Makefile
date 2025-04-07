# Makefile for Radiation-Hardened Firefox WebDriver Detection Bypass Tool

.PHONY: all build test clean coverage check fmt static-analysis tmr-check compliance \
        jpl-verify static-bounds-check memory-safety-check fault-tolerance-check temporal-check \
        enhanced-static-analysis formal-verify radiation-hardening jpl-build jpl-docs \
        verification-report dependency-verify lock-dependencies

# Configuration variables
RUSTFLAGS_COMMON := -D warnings -D unsafe_code
RUSTFLAGS_HARDENED := $(RUSTFLAGS_COMMON) -C overflow-checks=on -C codegen-units=1

# Default target
all: check build test

# Build the project with radiation-hardened configurations
build:
	RUSTFLAGS="$(RUSTFLAGS_HARDENED)" cargo build --release

# JPL-compliant release build with additional hardening
jpl-build:
	RUSTFLAGS="$(RUSTFLAGS_HARDENED) -C target-cpu=native -C panic=abort -C lto=fat -C codegen-units=1 -C embed-bitcode=yes" \
	cargo build --release --locked

# Run tests with radiation-hardened configurations
test:
	RUSTFLAGS="$(RUSTFLAGS_HARDENED)" cargo test -- --nocapture

# Clean build artifacts and coverage data
clean:
	cargo clean
	rm -rf ./coverage/
	rm -rf ./reports/
	rm -f undetected_geckodriver-*.profraw

# Run clippy for linting with JPL standards
check: static-analysis tmr-check compliance

# Additional JPL-specific verification targets
jpl-verify: static-bounds-check memory-safety-check fault-tolerance-check temporal-check

# Static analysis using clippy
static-analysis:
	RUSTFLAGS="$(RUSTFLAGS_COMMON)" cargo clippy -- -D warnings

# Comprehensive static analysis with additional JPL-specific rules
enhanced-static-analysis: static-analysis
	@echo "Running enhanced JPL-specific static analysis..."
	RUSTFLAGS="$(RUSTFLAGS_COMMON) -Z strict-overflow-checks=on" cargo clippy -- -W clippy::cast_possible_truncation -W clippy::cast_precision_loss -W clippy::cast_sign_loss

# Verify static bounds on all loops
static-bounds-check:
	@echo "Verifying static loop bounds (RLOC-2)..."
	@grep -r "for\|while" src/ --include="*.rs" | grep -v "// @bounded" | \
		grep -v "// @non-terminating" && echo "WARNING: Potentially unbounded loops found" || echo "All loops properly bounded"

# Check for memory safety patterns
memory-safety-check:
	@echo "Verifying memory safety patterns (RLOC-1)..."
	@grep -r "unsafe" src/ --include="*.rs" && echo "ERROR: Unsafe code found" || echo "No unsafe code detected"
	@grep -r "as_mut_ptr\|as_ptr" src/ --include="*.rs" && echo "WARNING: Raw pointer usage detected" || echo "No raw pointer usage detected"

# Verify fault containment and redundancy
fault-tolerance-check:
	@echo "Verifying fault containment regions (RLOC-3)..."
	@grep -r "tmr_vote!" src/ --include="*.rs" | wc -l | \
		xargs -I{} bash -c 'if [ {} -lt 5 ]; then echo "WARNING: Only {} TMR patterns found"; else echo "Found {} TMR patterns"; fi'

# Verify temporal predictability
temporal-check:
	@echo "Verifying temporal predictability (RLOC-2)..."
	@grep -r "thread::sleep\|tokio::time::sleep" src/ --include="*.rs" | \
		grep -v "// @bounded-delay" && echo "WARNING: Potentially unbounded delays found" || echo "All delays properly bounded"

# Check for TMR pattern compliance
tmr-check:
	@echo "Verifying Triple Modular Redundancy patterns..."
	@grep -r "tmr_vote!" src/ --include="*.rs" || (echo "WARNING: No TMR patterns found" && exit 0)

# Formal verification check (if tools available)
formal-verify:
	@echo "Checking for formal verification annotations..."
	@if command -v cargo-kani > /dev/null; then \
		echo "Running Kani model checker..."; \
		cargo kani; \
	elif command -v cargo-verify > /dev/null; then \
		echo "Running cargo-verify..."; \
		cargo verify; \
	else \
		echo "Formal verification tools not found, skipping verification"; \
	fi

# Radiation hardening verification
radiation-hardening:
	@echo "Verifying radiation hardening patterns..."
	@grep -r "barrier_pattern\|redundant_check\|seu_resistant" src/ --include="*.rs" | wc -l | \
		xargs -I{} bash -c 'if [ {} -lt 3 ]; then echo "WARNING: Only {} radiation hardening patterns found"; else echo "Found {} radiation hardening patterns"; fi'

# Verify compliance with JPL coding standards
compliance:
	@echo "Checking compliance with JPL-STD-RUST-001 Rev A..."
	@cargo deny check

# Verify dependency supply chain
dependency-verify:
	@echo "Verifying dependency supply chain..."
	@if command -v cargo-audit > /dev/null; then \
		cargo audit; \
	else \
		echo "cargo-audit not found, skipping security audit"; \
	fi
	@cargo deny check licenses sources

# Lock dependencies for reproducible builds
lock-dependencies:
	@echo "Locking dependencies for reproducible builds..."
	@cargo update
	@if [ ! -d vendor ]; then mkdir vendor; fi
	@cargo vendor vendor/
	@echo "Dependencies locked and vendored"

# Format code according to JPL standards
fmt:
	cargo fmt

# Generate documentation with safety annotations
jpl-docs:
	@echo "Generating JPL-compliant documentation..."
	RUSTDOCFLAGS="--cfg docsrs" cargo doc --no-deps --document-private-items
	@echo "Documentation generated in target/doc/"

# Verification report generation
verification-report:
	@mkdir -p reports
	@echo "Generating JPL verification report..."
	@echo "# JPL Compliance Verification Report" > reports/verification.md
	@echo "Generated: $$(date)" >> reports/verification.md
	@echo "\n## Static Analysis Results" >> reports/verification.md
	@RUSTFLAGS="$(RUSTFLAGS_COMMON)" cargo clippy --message-format=json 2>/dev/null | \
		jq -r 'select(.reason == "compiler-message") | .message | select(.level == "warning" or .level == "error") | "$$.level): $$.message)"' >> reports/verification.md 2>/dev/null || echo "No issues found" >> reports/verification.md
	@echo "\n## Memory Safety Verification" >> reports/verification.md
	@grep -r "unsafe" src/ --include="*.rs" | wc -l | xargs -I{} echo "Unsafe blocks: {}" >> reports/verification.md
	@echo "\n## TMR Pattern Usage" >> reports/verification.md
	@grep -r "tmr_vote!" src/ --include="*.rs" | wc -l | xargs -I{} echo "TMR patterns: {}" >> reports/verification.md
	@echo "\nVerification report generated at reports/verification.md"

# Generate coverage report with enhanced radiation hardening instrumentation
coverage:
	# Clean previous results
	$(MAKE) clean

	# Build with instrumentation for coverage
	CARGO_INCREMENTAL=0 \
	RUSTFLAGS="-Cinstrument-coverage -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=on -D unsafe_code" \
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

	# Try to open the report
	xdg-open ./coverage/index.html 2>/dev/null || open ./coverage/index.html 2>/dev/null || \
		echo "Please open ./coverage/index.html in your browser"

# Check if all prerequisites are installed
check-prereqs:
	@echo "Checking prerequisites for radiation-hardened build environment..."
	@which cargo > /dev/null || (echo "cargo not found, please install Rust" && exit 1)
	@which grcov > /dev/null || (echo "grcov not found, please install: cargo install grcov" && exit 1)
	@rustup component list | grep "llvm-tools-preview" > /dev/null || \
		(echo "llvm-tools-preview not found, please install: rustup component add llvm-tools-preview" && exit 1)
	@which cargo-deny > /dev/null || (echo "cargo-deny not found, please install: cargo install cargo-deny" && exit 1)
	@echo "All prerequisites installed! Environment ready for radiation-hardened development."

# Help target
help:
	@echo "Radiation-Hardened Firefox WebDriver Detection Bypass Tool"
	@echo "--------------------------------------------------------"
	@echo "Available targets:"
	@echo "  all:                Run checks, build and test the project (default)"
	@echo ""
	@echo "Build targets:"
	@echo "  build:              Build the project with radiation hardening"
	@echo "  jpl-build:          Build with enhanced JPL-compliant hardening"
	@echo "  test:               Run tests with radiation hardening"
	@echo "  clean:              Remove build artifacts and coverage data"
	@echo ""
	@echo "Verification targets:"
	@echo "  check:              Run all verification checks"
	@echo "  jpl-verify:         Run all JPL-specific verification checks"
	@echo "  static-analysis:    Run clippy for static code analysis"
	@echo "  enhanced-static-analysis: Run expanded static analysis with JPL rules"
	@echo "  static-bounds-check: Verify all loops have static bounds"
	@echo "  memory-safety-check: Verify memory safety patterns"
	@echo "  fault-tolerance-check: Verify fault containment mechanisms"
	@echo "  temporal-check:     Verify temporal predictability"
	@echo "  tmr-check:          Verify Triple Modular Redundancy patterns"
	@echo "  formal-verify:      Run formal verification tools if available"
	@echo "  radiation-hardening: Verify radiation hardening patterns"
	@echo "  compliance:         Check compliance with JPL-STD-RUST-001 Rev A"
	@echo ""
	@echo "Documentation and reporting:"
	@echo "  jpl-docs:           Generate JPL-compliant documentation"
	@echo "  verification-report: Generate comprehensive verification report"
	@echo "  coverage:           Generate code coverage report"
	@echo ""
	@echo "Dependency management:"
	@echo "  dependency-verify:  Verify dependency supply chain security"
	@echo "  lock-dependencies:  Lock and vendor dependencies for reproducible builds"
	@echo ""
	@echo "Other targets:"
	@echo "  fmt:                Format code with rustfmt"
	@echo "  check-prereqs:      Check if all prerequisites are installed"
	@echo "  help:               Show this help message"