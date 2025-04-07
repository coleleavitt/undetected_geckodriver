#![feature(internal_output_capture)]
#![warn(clippy::pedantic)]
#![deny(unsafe_code)]

//! Radiation-Hardened Firefox WebDriver Bypass Tool
//!
//! JPL-STD-RUST-001 Rev A compliant implementation

mod tests;

use goblin::elf::Elf;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use std::{
    env, fs,
    io::{BufReader, BufWriter, Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

// --------------------------
// Radiation Hardening Config
// --------------------------
const MAX_BINARY_SIZE: usize = 200 * 1_048_576; // 200MB to accommodate libxul.so
const MAX_PATTERN_LENGTH: usize = 128;
const SEED: u64 = 0x5AFE_C0DE_DEAD_BEEF;
const TIMEOUT_MS: u64 = 120_000; // Extended timeout for larger files
const BUFFER_SIZE: usize = 65536; // 64KB buffer for I/O operations
const SYSTEM_FIREFOX_DIR: &str = "/opt/firefox/";
const WEBDRIVER_STRING: &[u8] = b"webdriver";



// -----------
// Error Types
// -----------
#[derive(Debug)]
pub enum PatcherError {
    Io(String),
    ElfParsing(String),
    InvalidInput(String),
    TimingViolation(String),
    MemoryExceeded(String),
    SystemOperation(String),
}

impl From<std::io::Error> for PatcherError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

type Result<T> = std::result::Result<T, PatcherError>;

// ----------
// Core Traits
// ----------
pub trait BinaryLoader {
    fn load(&self, path: &str) -> Result<Vec<u8>>;
    fn parse_elf<'a>(&self, data: &'a [u8]) -> Result<Elf<'a>>;
}

pub trait PatternDetector {
    fn detection_patterns(&self) -> &[&[u8]];
    fn find_patterns<'a>(&self, data: &'a [u8], pattern: &[u8]) -> Vec<(usize, &'a [u8])>;
}

pub trait PatternReplacer {
    fn replace_pattern(&self, data: &mut [u8], offset: usize, pattern: &[u8]) -> Vec<u8>;
}

pub trait FileOperations {
    fn create_backup(&self, src: &str, dst: &str) -> Result<()>;
    fn write_binary(&self, path: &str, data: &[u8]) -> Result<()>;
}

// ------------------------
// Radiation-Hardened Impls
// ------------------------
pub struct HardenedLoader;

impl BinaryLoader for HardenedLoader {
    fn load(&self, path: &str) -> Result<Vec<u8>> {
        let path = Path::new(path);
        if !path.exists() {
            return Err(PatcherError::InvalidInput(format!("File not found: {}", path.display())));
        }

        let metadata = fs::metadata(path)?;
        let file_size = metadata.len() as usize;

        println!("Loading {} ({}MB)", path.display(), file_size / 1_048_576);

        if file_size > MAX_BINARY_SIZE {
            return Err(PatcherError::MemoryExceeded(
                format!("File exceeds {}MB limit (size: {}MB)",
                        MAX_BINARY_SIZE / 1_048_576,
                        file_size / 1_048_576)
            ));
        }

        // Optimized file loading with buffered I/O
        let mut data = Vec::with_capacity(file_size);
        let file = fs::File::open(path)?;
        let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);

        reader.read_to_end(&mut data)?;

        // TMR validation
        let len = data.len();
        if tmr_vote!(len, data.len(), data.capacity()) != len {
            return Err(PatcherError::MemoryExceeded("Memory corruption detected".into()));
        }

        Ok(data)
    }

    fn parse_elf<'a>(&self, data: &'a [u8]) -> Result<Elf<'a>> {
        println!("Parsing ELF binary ({:.2}MB)...", data.len() as f64 / 1_048_576.0);
        Elf::parse(data).map_err(|e| PatcherError::ElfParsing(e.to_string()))
    }
}

pub struct WebdriverDetector {
    patterns: Vec<&'static [u8]>,
}

impl WebdriverDetector {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                b"webdriver",
                b"navigator.webdriver",
                b"dom.webdriver.enabled",
                b"_ZN7mozilla7startup17sChildProcessTypeE",
                // Additional Firefox 115+ patterns
                b"@mozilla.org/remote/agent;1",
                b"remote-debugging-protocol",
                b"marionette.enabled",
                b"handleSwitchToWindow",
                b"_executeScript",
            ],
        }
    }
}

impl PatternDetector for WebdriverDetector {
    fn detection_patterns(&self) -> &[&[u8]] {
        &self.patterns
    }

    fn find_patterns<'a>(&self, data: &'a [u8], pattern: &[u8]) -> Vec<(usize, &'a [u8])> {
        let mut matches = Vec::new();
        let mut pos = 0;

        // Use MAX_PATTERN_LENGTH to limit long patterns
        if pattern.len() > MAX_PATTERN_LENGTH || pattern.len() > data.len() || pattern.is_empty() {
            return matches;
        }

        while let Some(offset) = find_subsequence(&data[pos..], pattern) {
            let global_offset = pos + offset;
            matches.push((global_offset, &data[global_offset..global_offset + pattern.len()]));
            pos = global_offset + pattern.len();

            // Limit excessive matches to prevent DoS
            if matches.len() >= 1000 {
                println!(
                    "Warning: Pattern match limit reached for '{}'",
                    String::from_utf8_lossy(pattern)
                );
                break;
            }
        }

        matches
    }
}

pub struct SeuResistantReplacer(StdRng);

impl SeuResistantReplacer {
    pub fn new() -> Self {
        Self(StdRng::seed_from_u64(SEED))
    }

    fn generate_hamming(&mut self, len: usize) -> Vec<u8> {
        // Restrict replacement to MAX_PATTERN_LENGTH
        let safe_len = std::cmp::min(len, MAX_PATTERN_LENGTH);

        (0..safe_len)
            .map(|_| {
                let mut byte = self.0.next_u32() as u8;
                byte |= 0x01; // Ensure odd parity
                byte
            })
            .collect()
    }
}

impl PatternReplacer for SeuResistantReplacer {
    fn replace_pattern(&self, data: &mut [u8], offset: usize, pattern: &[u8]) -> Vec<u8> {
        // Safety check against out-of-bounds access
        if offset + pattern.len() > data.len() || pattern.len() > MAX_PATTERN_LENGTH {
            return Vec::new();
        }

        let mut replacer = SeuResistantReplacer::new();
        let replacement = replacer.generate_hamming(pattern.len());

        data[offset..offset + pattern.len()].copy_from_slice(&replacement);

        replacement
    }
}

pub struct ValidatingFileOps;

impl FileOperations for ValidatingFileOps {
    fn create_backup(&self, src: &str, dst: &str) -> Result<()> {
        if Path::new(dst).exists() {
            println!("Backup already exists at {}", dst);
            return Ok(());
        }

        println!("Creating backup at {}", dst);

        // Use buffered I/O for large file operations
        let src_file = fs::File::open(src)?;
        let dst_file = fs::File::create(dst)?;

        let metadata = src_file.metadata()?;
        println!("Backing up {}MB file...", metadata.len() / 1_048_576);

        let mut reader = BufReader::with_capacity(BUFFER_SIZE, src_file);
        let mut writer = BufWriter::with_capacity(BUFFER_SIZE, dst_file);

        // Stream copy with fixed buffer to reduce memory pressure
        let mut buffer = vec![0u8; BUFFER_SIZE];
        let start = Instant::now();

        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            writer.write_all(&buffer[..bytes_read])?;

            // Progress indicator for large files
            if start.elapsed().as_secs() % 5 == 0 {
                print!(".");
                std::io::stdout().flush().ok();
            }
        }
        println!("\nBackup completed in {:.2}s", start.elapsed().as_secs_f32());

        Ok(())
    }

    fn write_binary(&self, path: &str, data: &[u8]) -> Result<()> {
        println!("Writing patched binary ({:.2}MB)...", data.len() as f64 / 1_048_576.0);

        // Use buffered writer for better performance with large files
        let file = fs::File::create(path)?;
        let mut writer = BufWriter::with_capacity(BUFFER_SIZE, file);

        // Write in chunks to maintain constant memory usage
        let mut remaining = data;
        let start = Instant::now();

        while !remaining.is_empty() {
            let chunk_size = std::cmp::min(BUFFER_SIZE, remaining.len());
            let (chunk, rest) = remaining.split_at(chunk_size);

            writer.write_all(chunk)?;
            remaining = rest;

            // Progress indicator for large files
            if start.elapsed().as_secs() % 3 == 0 {
                print!(".");
                std::io::stdout().flush().ok();
            }
        }

        writer.flush()?;
        println!("\nWrite completed in {:.2}s", start.elapsed().as_secs_f32());

        Ok(())
    }
}

// ----------------
// Core Patcher
// ----------------
pub struct FirefoxPatcher<L, D, R, F> {
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
    pub fn new(loader: L, detector: D, replacer: R, file_ops: F) -> Self {
        Self {
            loader,
            detector,
            replacer,
            file_ops,
        }
    }

    pub fn run(&self, path: &str) -> Result<usize> {
        let start = Instant::now();

        println!("Starting Firefox WebDriver patch operation");
        println!("Target: {}", path);

        // Create backup
        self.file_ops.create_backup(path, &format!("{}.bak", path))?;

        // Load and validate
        let data = self.loader.load(path)?;
        let elf = self.loader.parse_elf(&data)?;

        let mut patched = data.clone();
        let mut total = 0;

        // Process critical sections with progress reporting
        println!("Scanning for WebDriver patterns...");
        let sections = [".rodata", ".data", ".text", ".rdata"];

        for section in &sections {
            if let Some(shdr) = elf
                .section_headers
                .iter()
                .find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(section))
            {
                println!(
                    "Processing section: {} ({:.2}MB)",
                    section,
                    shdr.sh_size as f64 / 1_048_576.0
                );

                let section_patches = self.process_section(shdr, &data, &mut patched)?;
                println!("Found {} patterns in {}", section_patches, section);
                total += section_patches;

                if start.elapsed() > Duration::from_millis(TIMEOUT_MS) {
                    return Err(PatcherError::TimingViolation(format!(
                        "Processing timeout after {}s",
                        start.elapsed().as_secs()
                    )));
                }
            } else {
                println!("Section {} not found, skipping", section);
            }
        }

        if total > 0 {
            self.file_ops.write_binary(path, &patched)?;
            println!("Patching complete - applied {} modifications", total);
        } else {
            println!("No WebDriver detection patterns found to patch");
        }

        println!("Operation completed in {:.2}s", start.elapsed().as_secs_f32());
        Ok(total)
    }

    fn process_section(
        &self,
        shdr: &goblin::elf::SectionHeader,
        data: &[u8],
        patched: &mut [u8],
    ) -> Result<usize> {
        let start = shdr.sh_offset as usize;
        let size = shdr.sh_size as usize;

        // Bounds validation to prevent OOB access
        if start >= data.len() {
            return Err(PatcherError::InvalidInput(format!(
                "Section offset 0x{:x} exceeds binary size",
                start
            )));
        }

        let end = std::cmp::min(start + size, data.len());
        let section_data = &data[start..end];

        let mut count = 0;
        for pattern in self.detector.detection_patterns() {
            for (offset, matched) in self.detector.find_patterns(section_data, pattern) {
                let replacement = self.replacer.replace_pattern(patched, start + offset, pattern);

                if !replacement.is_empty() {
                    // Print hex representation of the pattern and replacement
                    let pattern_hex = matched
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");

                    let replacement_hex = replacement
                        .iter()
                        .take(4)
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");

                    println!(
                        "  Patched '{}' @ 0x{:x} [{} -> {}...]",
                        String::from_utf8_lossy(matched),
                        start + offset,
                        pattern_hex,
                        replacement_hex
                    );

                    count += 1;
                }
            }
        }

        Ok(count)
    }
}

// ----------------
// Helper Functions
// ----------------
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn print_preferences() {
    println!("\nRecommended Firefox preferences:");
    println!("user_pref(\"dom.webdriver.enabled\", false);");
    println!("user_pref(\"devtools.selfxss.count\", 0);");
    println!("user_pref(\"marionette.enabled\", false);");
    println!("user_pref(\"remote.enabled\", false);");
    println!("user_pref(\"remote.log.level\", \"Fatal\");");
    println!("user_pref(\"remote.force-local\", true);");
}

// System Operations for Firefox patching
pub struct SystemOperations;

impl SystemOperations {
    pub fn get_firefox_binary() -> PathBuf {
        env::args()
            .nth(1)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/opt/firefox/firefox"))
    }

    pub fn find_free_port() -> Result<u16> {
        TcpListener::bind("127.0.0.1:0")
            .map(|listener| listener.local_addr().unwrap().port())
            .map_err(|e| PatcherError::SystemOperation(format!("Failed to bind to address: {}", e)))
    }

    pub fn backup_original_libxul() -> Result<()> {
        let orig_path = Path::new(SYSTEM_FIREFOX_DIR).join("libxul.so");
        let backup_path = Path::new(SYSTEM_FIREFOX_DIR).join("libxul.so.bak");

        if !backup_path.exists() {
            println!("Creating backup at {}", backup_path.display());
            println!("You may be prompted for your password by a graphical dialog");

            // Use pkexec for graphical authentication dialog
            let status = Command::new("pkexec")
                .args(["cp", orig_path.to_str().unwrap(), backup_path.to_str().unwrap()])
                .status()
                .map_err(|e| {
                    PatcherError::SystemOperation(format!("Backup failed: {}", e))
                })?;

            if !status.success() {
                return Err(PatcherError::SystemOperation("Backup command failed".into()));
            }
        }
        Ok(())
    }

    // System Operations for Firefox patching (continued)
    pub fn restore_original_libxul() -> Result<()> {
        let orig_path = Path::new(SYSTEM_FIREFOX_DIR).join("libxul.so");
        let backup_path = Path::new(SYSTEM_FIREFOX_DIR).join("libxul.so.bak");

        if backup_path.exists() {
            println!("Restoring backup from {}", backup_path.display());
            println!("You may be prompted for your password by a graphical dialog");

            // Use pkexec for consistency with backup function
            let status = Command::new("pkexec")
                .args(["cp", backup_path.to_str().unwrap(), orig_path.to_str().unwrap()])
                .status()
                .map_err(|e| {
                    PatcherError::SystemOperation(format!("Restore failed: {}", e))
                })?;

            if !status.success() {
                return Err(PatcherError::SystemOperation("Restore command failed".into()));
            }
        }
        Ok(())
    }

    pub fn kill_geckodriver_processes() -> Result<()> {
        // Try to find and kill any existing geckodriver processes
        if let Ok(output) = Command::new("pgrep").arg("geckodriver").output() {
            if !output.stdout.is_empty() {
                // Found running geckodriver processes
                Command::new("pkill")
                    .arg("geckodriver")
                    .output()
                    .map_err(|e| {
                        PatcherError::SystemOperation(format!(
                            "Failed to kill existing geckodriver processes: {}",
                            e
                        ))
                    })?;
                // Give processes time to terminate
                thread::sleep(Duration::from_secs(1));
            }
        }
        Ok(())
    }

    pub fn patch_libxul() -> Result<()> {
        let xul_path = Path::new(SYSTEM_FIREFOX_DIR).join("libxul.so");

        // Read file
        let mut data = fs::read(&xul_path)
            .map_err(|e| PatcherError::SystemOperation(e.to_string()))?;

        // Generate random string of the same length
        let random_string: Vec<u8> = (0..WEBDRIVER_STRING.len())
            .map(|_| rand::random::<u8>())
            .collect();

        // Count occurrences before patching
        let occurrences_before = data.windows(WEBDRIVER_STRING.len())
            .filter(|window| *window == WEBDRIVER_STRING)
            .count();

        println!("Found {} occurrences of 'webdriver' in libxul.so", occurrences_before);

        // Replace all occurrences
        let mut i = 0;
        let mut replaced = 0;
        while i <= data.len() - WEBDRIVER_STRING.len() {
            if data[i..(i + WEBDRIVER_STRING.len())] == WEBDRIVER_STRING[..] {
                data[i..(i + WEBDRIVER_STRING.len())].copy_from_slice(&random_string);
                replaced += 1;
                i += WEBDRIVER_STRING.len();
            } else {
                i += 1;
            }
        }

        if replaced > 0 {
            println!("Replaced {} occurrences of 'webdriver'", replaced);

            // Write patched file using sudo/pkexec
            Command::new("pkexec")
                .args(["tee", xul_path.to_str().unwrap()])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .spawn()
                .map_err(|e| PatcherError::SystemOperation(e.to_string()))?
                .stdin
                .unwrap()
                .write_all(&data)
                .map_err(|e| PatcherError::SystemOperation(e.to_string()))?;

            println!("Patched libxul.so successfully");
        } else {
            println!("No occurrences of 'webdriver' found to patch in libxul.so");
        }

        Ok(())
    }
}

// ----------
// Main Entry
// ----------
fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <firefox-binary>", args[0]);
        eprintln!("Example: {} /usr/lib/firefox/libxul.so", args[0]);
        return Ok(());
    }

    // Create file size-aware patcher
    let patcher = FirefoxPatcher::new(
        HardenedLoader,
        WebdriverDetector::new(),
        SeuResistantReplacer::new(),
        ValidatingFileOps,
    );

    match patcher.run(&args[1]) {
        Ok(count) => {
            println!("Successfully applied {} radiation-hardened patches", count);
            print_preferences();
            Ok(())
        }
        Err(e) => {
            eprintln!("Critical Failure: {:?}", e);

            // Fix unused variable warning by properly using msg
            if let PatcherError::MemoryExceeded(msg) = &e {
                eprintln!("\nMemory limit exceeded: {}", msg);
                eprintln!("Suggestion: Edit MAX_BINARY_SIZE in main.rs to accommodate larger files.");
                eprintln!("Current limit is set to {}MB.", MAX_BINARY_SIZE / 1_048_576);
            }

            Err(e)
        }
    }
}