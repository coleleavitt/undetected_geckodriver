# Undetected GeckoDriver

A radiation-hardened Firefox WebDriver bypass tool developed in accordance with JPL-STD-RUST-001 Rev A.

## Architecture Overview

![Architecture Diagram](resources/images/architecture_diagram.png)

*Figure 1: System architecture showing the binary patching workflow*

## Overview

This tool patches Firefox's `libxul.so` binary to bypass WebDriver detection mechanisms, allowing for automated browser testing without being detected as automation. It's implemented using memory-safe, radiation-hardened patterns suitable for mission-critical applications.

## Features

- **Zero Unsafe Code**: Full memory-safe implementation with no `unsafe` blocks
- **Radiation Hardening**: Triple Modular Redundancy (TMR) voting mechanisms to protect against Single Event Upsets (SEUs)
- **Bounded Operations**: All loops have statically verifiable upper bounds
- **Resource Constraints**: Fixed memory allocation with predetermined limits
- **Fault Containment**: Comprehensive error handling with recovery mechanisms
- **Temporal Predictability**: All operations have deterministic execution paths

## Proof of Effectiveness

The following screenshots demonstrate successful bypass of automation detection:

### SannySoft Detection Test
![SannySoft Detection Bypass](proof_20250407_131554/sannysoft_detection_131605.png)

### CreepJS Detection Test
![CreepJS Detection Bypass](proof_20250407_131554/creepjs_detection_131610.png)

*Figures 2-3: Automation detection bypass proof on common detection platforms*

## Installation

```
# Clone the repository
git clone https://github.com/coleleavitt/undetected_geckodriver.git
cd undetected_geckodriver

# Build the project with radiation-hardened configurations
make build
```

## Usage

```
# Patch Firefox's libxul.so to bypass WebDriver detection
undetected_geckodriver /opt/firefox/libxul.so

# Run automated tests with the patched Firefox
cargo test
```

### Recommended Firefox Preferences

For optimal undetectability, add these preferences to your Firefox profile:

```
user_pref("dom.webdriver.enabled", false);
user_pref("devtools.selfxss.count", 0);
user_pref("marionette.enabled", false);
user_pref("remote.enabled", false);
user_pref("remote.log.level", "Fatal");
user_pref("remote.force-local", true);
```

## Implementation Details

### Radiation Hardening Techniques

This implementation follows JPL-STD-RUST-001 Rev A guidelines for radiation-hardened software:

1. **Triple Modular Redundancy (TMR)**: Critical operations use the `tmr_vote!` macro for fault tolerance:
   ```rust
   // Majority voting mechanism for fault tolerance
   tmr_vote!(1, 1, 0)  // Returns 1 (majority vote)
   tmr_vote!(0, 0, 1)  // Returns 0 (majority vote)
   ```



2. **SEU (Single Event Upset) Resistance**: Pattern replacements use Hamming-encoded data to ensure data integrity

3. **Memory Protection**: Barrier patterns and safety margins detect memory corruption

4. **Pattern Validation**: All pattern replacements have size limits enforced by `MAX_PATTERN_LENGTH`

### System Architecture

The implementation follows a modular architecture with radiation-hardened traits:

- `BinaryLoader`: Manages ELF binary loading with memory safety checks
- `PatternDetector`: Identifies WebDriver-related string patterns
- `PatternReplacer`: Applies radiation-hardened replacements
- `FileOperations`: Handles file I/O with validation
- `SystemOperations`: Provides system-level functions for process management

## Testing

The test suite verifies:

1. TMR voting mechanisms
2. Pattern replacement constraints
3. Firefox binary patching
4. Automated WebDriver detection bypass on test sites

Run tests with:

```
cargo test
```

## JPL Compliance

This project adheres to all LOC-1 through LOC-4 compliance levels from the JPL Institutional Coding Standard:

- **LOC-1 Language Compliance**: No undefined or implementation-defined behavior
- **LOC-2 Predictable Execution**: Bounded loops, no recursion, static memory allocation
- **LOC-3 Defensive Coding**: Verification of inputs, defensive checks throughout
- **LOC-4 Code Clarity**: Limited preprocessor use, small functions with clear purpose

## Safety Considerations

This tool requires root/administrator privileges to modify Firefox system files. Always backup your Firefox installation before using. The tool automatically creates backups before modifying any files.

## License

MIT

## Acknowledgments

Developed in accordance with JPL Institutional Coding Standards for safety-critical systems.