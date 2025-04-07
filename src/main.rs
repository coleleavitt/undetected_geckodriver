#![feature(internal_output_capture)]
//! Firefox WebDriver Detection Bypass Tool
//!
//! This tool patches Firefox binaries to bypass WebDriver detection mechanisms
//! by replacing specific detection patterns with random bytes.
//!
//! # Overview
//! The tool works by:
//! 1. Locating specific WebDriver detection patterns in Firefox binaries
//! 2. Replacing these patterns with random byte sequences
//! 3. Preserving a backup of the original binary

mod tests;

use goblin::elf::Elf;
use rand::Rng;
use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

/// Comprehensive error type for all failure modes in the application
#[derive(Debug)]
pub enum PatcherError {
    /// File system related errors with a detailed message
    Io(String),

    /// ELF binary parsing errors with a detailed message
    ElfParsing(String),

    /// Input validation errors with a detailed message
    InvalidInput(String),
}

impl From<std::io::Error> for PatcherError {
    fn from(error: std::io::Error) -> Self {
        PatcherError::Io(error.to_string())
    }
}

/// Standard Result type used throughout the application
pub type Result<T> = std::result::Result<T, PatcherError>;

/// Provides functionality to load and parse binary files
pub trait BinaryLoader {
    /// Load a binary file into memory
    ///
    /// # Arguments
    /// * `path` - Path to the binary file
    ///
    /// # Returns
    /// * `Result<Vec<u8>>` - File content as bytes or an error
    fn load(&self, path: &str) -> Result<Vec<u8>>;

    /// Parse an ELF binary
    ///
    /// # Arguments
    /// * `data` - Binary data to parse
    ///
    /// # Returns
    /// * `Result<Elf>` - Parsed ELF structure or an error
    fn parse_elf<'a>(&self, data: &'a [u8]) -> Result<Elf<'a>>;
}

/// Detects patterns in binary data
pub trait PatternDetector {
    /// Returns a list of patterns to search for
    ///
    /// # Returns
    /// * `&[&[u8]]` - Slice of byte patterns to search for
    fn detection_patterns(&self) -> &[&[u8]];

    /// Finds all occurrences of a pattern in a binary section
    ///
    /// # Arguments
    /// * `section_data` - The data to search in
    /// * `section_start` - Starting offset of the section in the file
    /// * `pattern` - The pattern to search for
    ///
    /// # Returns
    /// * `Vec<(usize, &[u8])>` - Collection of (global_offset, matched_pattern) pairs
    fn find_patterns<'a>(
        &self,
        section_data: &'a [u8],
        section_start: usize,
        pattern: &[u8],
    ) -> Vec<(usize, &'a [u8])>;
}

/// Replaces detected patterns with alternative data
pub trait PatternReplacer {
    /// Replace a pattern at a specific offset in binary data
    ///
    /// # Arguments
    /// * `data` - The binary data to modify
    /// * `offset` - The offset where the pattern starts
    /// * `pattern` - The pattern to replace
    ///
    /// # Returns
    /// * `Vec<u8>` - The replacement bytes used
    fn replace_pattern(&self, data: &mut [u8], offset: usize, pattern: &[u8]) -> Vec<u8>;
}

/// Provides file operations functionality
pub trait FileOperations {
    /// Create a backup of a file
    ///
    /// # Arguments
    /// * `source` - Path to the source file
    /// * `destination` - Path where the backup should be created
    ///
    /// # Returns
    /// * `Result<()>` - Success or an error
    fn create_backup(&self, source: &str, destination: &str) -> Result<()>;

    /// Write modified data back to a binary file
    ///
    /// # Arguments
    /// * `path` - Path to the file to write
    /// * `data` - The data to write
    ///
    /// # Returns
    /// * `Result<()>` - Success or an error
    fn write_patched_binary(&self, path: &str, data: &[u8]) -> Result<()>;
}

/// Standard implementation of the BinaryLoader trait
pub struct DefaultBinaryLoader;

impl BinaryLoader for DefaultBinaryLoader {
    fn load(&self, path: &str) -> Result<Vec<u8>> {
        // Validate input
        if path.is_empty() {
            return Err(PatcherError::InvalidInput("Empty file path provided".to_string()));
        }

        let file_path = Path::new(path);
        if !file_path.exists() {
            return Err(PatcherError::InvalidInput(
                format!("File not found: '{}'", path)
            ));
        }

        let mut file_data = Vec::new();
        let mut file = File::open(path)
            .map_err(|e| PatcherError::Io(format!("Failed to open binary '{}': {}", path, e)))?;

        file.read_to_end(&mut file_data)
            .map_err(|e| PatcherError::Io(format!("Failed to read binary '{}': {}", path, e)))?;

        Ok(file_data)
    }

    fn parse_elf<'a>(&self, data: &'a [u8]) -> Result<Elf<'a>> {
        // Validate input
        if data.is_empty() {
            return Err(PatcherError::InvalidInput("Empty data provided for ELF parsing".to_string()));
        }

        Elf::parse(data)
            .map_err(|e| PatcherError::ElfParsing(format!("Error parsing ELF: {}", e)))
    }
}

/// Firefox WebDriver detection pattern detector implementation
pub struct WebdriverPatternDetector {
    /// Collection of byte patterns to detect
    patterns: Vec<&'static [u8]>,
}

impl WebdriverPatternDetector {
    /// Create a new instance with predefined WebDriver detection patterns
    ///
    /// # Returns
    /// * `Self` - A new WebdriverPatternDetector instance
    pub fn new() -> Self {
        Self {
            patterns: vec![
                // Explicit webdriver identifiers
                b"webdriver",
                b"navigator.webdriver",
                b"window.navigator.webdriver",
                b"dom.webdriver.enabled",
                // Process type identifiers
                b"_ZN7mozilla7startup17sChildProcessTypeE",
                b"_ZN7mozilla19SetGeckoProcessTypeEPKc",
                b"_ZN7mozilla15SetGeckoChildIDEPKc",
                // Remote control markers
                b"@mozilla.org/remote/agent;1",
                // Automation detection
                b"dom.automation",
                b"cookiebanners.service.detectOnly",
                b"dom.media.autoplay-policy-detection.enabled",
            ],
        }
    }
}

impl PatternDetector for WebdriverPatternDetector {
    fn detection_patterns(&self) -> &[&[u8]] {
        &self.patterns
    }

    fn find_patterns<'a>(
        &self,
        section_data: &'a [u8],
        section_start: usize,
        pattern: &[u8],
    ) -> Vec<(usize, &'a [u8])> {
        if section_data.is_empty() || pattern.is_empty() {
            return Vec::new();
        }

        let pattern_len = pattern.len();
        let section_len = section_data.len();

        if pattern_len > section_len {
            return Vec::new();
        }

        let mut results = Vec::new();
        let mut pos = 0;
        let max_pos = section_len.saturating_sub(pattern_len);

        while pos <= max_pos {
            if &section_data[pos..pos + pattern_len] == pattern {
                results.push((section_start + pos, &section_data[pos..pos + pattern_len]));
                pos += pattern_len;
            } else {
                pos += 1;
            }
        }

        results
    }

}

/// Random byte pattern replacer implementation
pub struct RandomReplacer;

impl RandomReplacer {
    /// Create a new random replacer
    ///
    /// # Returns
    /// * `Self` - A new RandomReplacer instance
    pub fn new() -> Self {
        Self {}
    }
}

impl PatternReplacer for RandomReplacer {
    fn replace_pattern(&self, data: &mut [u8], offset: usize, pattern: &[u8]) -> Vec<u8> {
        // Validate inputs
        if data.is_empty() || pattern.is_empty() || offset >= data.len() {
            return Vec::new();
        }

        let mut rng = rand::rng();
        let pattern_len = pattern.len();

        // Ensure we don't exceed buffer bounds
        let max_replace_len = std::cmp::min(pattern_len, data.len() - offset);

        // Generate random bytes (avoiding NULL bytes)
        let random_bytes: Vec<u8> = (0..max_replace_len)
            .map(|_| rng.random_range(1..=255))
            .collect();

        // Apply the random bytes at the specified offset
        for (i, &byte) in random_bytes.iter().enumerate() {
            data[offset + i] = byte;
        }

        random_bytes
    }
}

/// Default file operations implementation
pub struct DefaultFileOperations;

impl FileOperations for DefaultFileOperations {
    fn create_backup(&self, source: &str, destination: &str) -> Result<()> {
        // Validate inputs
        if source.is_empty() || destination.is_empty() {
            return Err(PatcherError::InvalidInput("Empty file path provided".to_string()));
        }

        if !Path::new(source).exists() {
            return Err(PatcherError::InvalidInput(format!("Source file not found: '{}'", source)));
        }

        if !Path::new(destination).exists() {
            println!("Creating backup at {}", destination);
            fs::copy(source, destination)?;
        } else {
            println!("Backup already exists at {}", destination);
        }

        Ok(())
    }

    fn write_patched_binary(&self, path: &str, data: &[u8]) -> Result<()> {
        // Validate inputs
        if path.is_empty() {
            return Err(PatcherError::InvalidInput("Empty file path provided".to_string()));
        }

        if data.is_empty() {
            return Err(PatcherError::InvalidInput("Empty data provided for writing".to_string()));
        }

        let mut output_file = File::create(path)?;
        output_file.write_all(data)?;

        Ok(())
    }
}

/// Core component that orchestrates the patching process
pub struct FirefoxPatcher<L, D, R, F>
where
    L: BinaryLoader,
    D: PatternDetector,
    R: PatternReplacer,
    F: FileOperations,
{
    loader: L,
    detector: D,
    replacer: R,
    file_ops: F,
}

impl<L, D, R, F> FirefoxPatcher<L, D, R, F>
where
    L: BinaryLoader,
    D: PatternDetector,
    R: PatternReplacer,
    F: FileOperations,
{
    /// Create a new patcher with the specified components
    ///
    /// # Arguments
    /// * `loader` - Binary loader implementation
    /// * `detector` - Pattern detector implementation
    /// * `replacer` - Pattern replacer implementation
    /// * `file_ops` - File operations implementation
    ///
    /// # Returns
    /// * `Self` - A new FirefoxPatcher instance
    pub fn new(loader: L, detector: D, replacer: R, file_ops: F) -> Self {
        Self {
            loader,
            detector,
            replacer,
            file_ops,
        }
    }

    /// Process a single ELF section to find and replace patterns
    ///
    /// # Arguments
    /// * `section_name` - Name of the section being processed
    /// * `shdr` - Section header
    /// * `file_data` - Original binary data
    /// * `patched_data` - Data buffer to apply changes to
    /// * `elf` - ELF file structure
    ///
    /// # Returns
    /// * `Result<usize>` - Number of patterns replaced
    fn process_section(
        &self,
        section_name: &str,
        shdr: &goblin::elf::section_header::SectionHeader,
        file_data: &[u8],
        patched_data: &mut [u8],
    ) -> Result<usize> {
        let mut section_patches = 0;
        let section_start = shdr.sh_offset as usize;
        let section_end = (shdr.sh_offset + shdr.sh_size) as usize;

        println!(
            "Searching section {} at offset 0x{:x}",
            section_name, shdr.sh_offset
        );

        if section_end > file_data.len() {
            println!(
                "Warning: Section {} extends beyond file size, skipping",
                section_name
            );
            return Ok(0);
        }

        let section_data = &file_data[section_start..section_end];

        // Search for each pattern in the current section
        for pattern in self.detector.detection_patterns() {
            let matches = self.detector.find_patterns(section_data, section_start, pattern);

            for (global_offset, matched_pattern) in matches {
                // Replace pattern with random bytes
                let replacement = self.replacer.replace_pattern(
                    patched_data,
                    global_offset,
                    matched_pattern
                );

                if !replacement.is_empty() {
                    // Format replacement bytes for display
                    let replacement_display = replacement
                        .iter()
                        .take(4)
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");

                    println!(
                        "Patched '{}' at offset 0x{:x} in {} with '{}'",
                        String::from_utf8_lossy(matched_pattern),
                        global_offset,
                        section_name,
                        replacement_display
                    );

                    section_patches += 1;
                }
            }
        }

        Ok(section_patches)
    }

    /// Run the patching process on the specified Firefox binary
    ///
    /// # Arguments
    /// * `firefox_path` - Path to the Firefox binary to patch
    ///
    /// # Returns
    /// * `Result<usize>` - Number of patterns replaced or an error
    pub fn run(&self, firefox_path: &str) -> Result<usize> {
        // Validate path
        if firefox_path.is_empty() {
            return Err(PatcherError::InvalidInput("Empty Firefox path provided".to_string()));
        }

        let firefox_file_path = Path::new(firefox_path);
        if !firefox_file_path.exists() {
            return Err(PatcherError::InvalidInput(format!(
                "Firefox binary not found at '{}'",
                firefox_path
            )));
        }

        // Create backup path
        let backup_path = format!("{}.bak", firefox_path);

        // Create backup
        self.file_ops.create_backup(firefox_path, &backup_path)?;

        // Load the binary
        let file_data = self.loader.load(firefox_path)?;

        // Parse ELF
        println!("Analyzing ELF structure...");
        let elf = self.loader.parse_elf(&file_data)?;

        let mut total_patches = 0;
        let mut patched_data = file_data.clone();

        // Process relevant sections
        for section_name in &[".rodata", ".data"] {
            // Find section
            let section_opt = elf.section_headers.iter().find(|&s| {
                elf.shdr_strtab
                    .get_at(s.sh_name)
                    .map(|name| name == *section_name)
                    .unwrap_or(false)
            });

            if let Some(shdr) = section_opt {
                let section_patches = self.process_section(
                    section_name,
                    shdr,
                    &file_data,
                    &mut patched_data)?;

                total_patches += section_patches;
            } else {
                println!("Section {} not found, skipping", section_name);
            }
        }

        // Write patched binary if changes were made
        if total_patches > 0 {
            println!("Writing patched binary with {} modifications...", total_patches);
            self.file_ops.write_patched_binary(firefox_path, &patched_data)?;
            println!("Successfully applied {} patches", total_patches);
        } else {
            println!("No detection patterns found to patch.");
        }

        Ok(total_patches)
    }
}

/// Prints recommended Firefox preferences to disable WebDriver detection
fn print_firefox_preferences() {
    println!("\nEssential Firefox preferences (add to user.js):");
    println!("user_pref(\"dom.webdriver.enabled\", false);");
    println!("user_pref(\"dom.automation\", false);");
    println!("user_pref(\"marionette.enabled\", false);");
    println!("user_pref(\"network.http.spdy.enabled\", false);");
    println!(
        "user_pref(\"browser.tabs.remote.separatePrivilegedMozillaWebContentProcess\", false);"
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let exit_code = process_args(&args);
    std::process::exit(exit_code);
}

// Testable function that handles the application logic
pub fn process_args(args: &[String]) -> i32 {
    if args.len() < 2 {
        println!("Usage: {} <path_to_firefox_binary>", args[0]);
        return 1;
    }

    let firefox_path = &args[1];

    // Create the patcher with all components
    let patcher = FirefoxPatcher::new(
        DefaultBinaryLoader,
        WebdriverPatternDetector::new(),
        RandomReplacer::new(),
        DefaultFileOperations,
    );

    // Run the patcher
    match patcher.run(firefox_path) {
        Ok(patches) => {
            println!(
                "Patcher completed successfully with {} total modifications",
                patches
            );

            // Print additional instructions
            print_firefox_preferences();
            0 // Success exit code
        }
        Err(e) => {
            eprintln!("Error: {:?}", e);
            1 // Error exit code
        }
    }
}
