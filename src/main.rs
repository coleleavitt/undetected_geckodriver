use goblin::elf::Elf;
use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use rand::Rng;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <path_to_firefox_binary>", args[0]);
        return;
    }

    let firefox_path = &args[1];
    let backup_path = format!("{}.bak", firefox_path);

    // Create backup if it doesn't exist
    if !Path::new(&backup_path).exists() {
        println!("Creating backup at {}", backup_path);
        fs::copy(firefox_path, &backup_path).expect("Failed to create backup");
    }

    // Read the binary
    let mut file_data = Vec::new();
    File::open(firefox_path)
        .expect("Failed to open Firefox binary")
        .read_to_end(&mut file_data)
        .expect("Failed to read Firefox binary");

    // Parse the ELF file
    println!("Analyzing ELF structure...");
    let elf = match Elf::parse(&file_data) {
        Ok(elf) => elf,
        Err(e) => {
            println!("Error parsing ELF: {}", e);
            return;
        }
    };

    // Define detection strings as byte slices with consistent types
    let webdriver_patterns = [
        &b"webdriver"[..],
        &b"navigator.webdriver"[..],
        &b"window.navigator.webdriver"[..],
        &b"dom.webdriver.enabled"[..]
    ];

    let mut total_patches = 0;
    let mut patched_data = file_data.clone();
    let mut rng = rand::thread_rng();

    // Search and patch in relevant sections
    for section in &[".rodata", ".data"] {
        if let Some(shdr) = elf.section_headers.iter().find(|&s| {
            elf.shdr_strtab.get_at(s.sh_name).map(|name| name == *section).unwrap_or(false)
        }) {
            println!("Searching section {} at offset 0x{:x}", section, shdr.sh_offset);

            let section_start = shdr.sh_offset as usize;
            let section_end = (shdr.sh_offset + shdr.sh_size) as usize;

            if section_end > file_data.len() {
                println!("Warning: Section {} extends beyond file size, skipping", section);
                continue;
            }

            let section_data = &file_data[section_start..section_end];

            for pattern in &webdriver_patterns {
                let pattern_bytes = *pattern;
                let mut pos = 0;

                while pos < section_data.len().saturating_sub(pattern_bytes.len()) {
                    if &section_data[pos..pos + pattern_bytes.len()] == pattern_bytes {
                        let global_offset = section_start + pos;

                        // Generate random bytes of the same length (avoiding null bytes)
                        let random_bytes: Vec<u8> = (0..pattern_bytes.len())
                            .map(|_| rng.gen_range(1..=255)) // Use exclusive range syntax
                            .collect();

                        // Apply patch to the patched_data copy
                        for (i, &byte) in random_bytes.iter().enumerate() {
                            patched_data[global_offset + i] = byte;
                        }

                        println!("Patched '{}' at offset 0x{:x} in {}",
                                 String::from_utf8_lossy(pattern_bytes),
                                 global_offset,
                                 section);
                        total_patches += 1;

                        pos += pattern_bytes.len();
                    } else {
                        pos += 1;
                    }
                }
            }
        }
    }

    // Write the patched binary
    if total_patches > 0 {
        println!("Writing patched binary with {} modifications...", total_patches);
        let mut output_file = File::create(firefox_path).expect("Failed to open output file");
        output_file.write_all(&patched_data).expect("Failed to write patched data");
        println!("Successfully applied {} patches", total_patches);
    } else {
        println!("No webdriver detection strings found to patch.");
    }

    // Print additional instructions
    println!("\nTo complete the setup, add these lines to your Firefox preferences (user.js):");
    println!("user_pref(\"dom.webdriver.enabled\", false);");
    println!("user_pref(\"network.http.spdy.enabled\", false);");
    println!("user_pref(\"network.http.spdy.enabled.deps\", false);");
    println!("user_pref(\"network.http.spdy.enabled.http2\", false);");
    println!("user_pref(\"network.http.spdy.websockets\", false);");
    println!("user_pref(\"dom.automation\", false);");
    println!("user_pref(\"general.useragent.override\", \"Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0\");");
}



mod tests {
    use serde_json::{json, Value};
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    use std::thread;
    use thirtyfour::common::capabilities::firefox::FirefoxPreferences;
    use thirtyfour::error::WebDriverResult;
    use thirtyfour::{DesiredCapabilities, WebDriver};

    #[tokio::test(flavor = "multi_thread")]
    async fn test_patched_firefox() -> WebDriverResult<()> {
        // Kill any existing geckodriver processes first
        if cfg!(target_os = "windows") {
            let _ = Command::new("taskkill")
                .args(["/F", "/IM", "geckodriver.exe"])
                .output();
        } else {
            let _ = Command::new("pkill")
                .arg("geckodriver")
                .output();
        }

        // Start geckodriver with verbose logging and pipe stdout/stderr
        let mut geckodriver = Command::new("geckodriver")
            .args([
                "--port", "4444",
                "--log", "trace",  // Maximum verbosity
                "--marionette-port", "2828",  // Explicit marionette port
                "--allow-hosts", "localhost"  // Restrict to localhost
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start geckodriver");

        println!("Started geckodriver with PID: {}", geckodriver.id());

        // Create threads to read and print stdout/stderr in real-time
        let stdout = geckodriver.stdout.take().expect("Failed to capture stdout");
        let stderr = geckodriver.stderr.take().expect("Failed to capture stderr");

        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            reader.lines().for_each(|line| {
                if let Ok(line) = line {
                    println!("GECKODRIVER OUT: {}", line);
                }
            });
        });

        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            reader.lines().for_each(|line| {
                if let Ok(line) = line {
                    println!("GECKODRIVER ERR: {}", line);
                }
            });
        });

        // Wait for geckodriver to initialize
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        // Set up Firefox capabilities with additional debugging
        let mut caps = DesiredCapabilities::firefox();

        // Create Firefox preferences
        let mut prefs = FirefoxPreferences::new();
        prefs.set("devtools.console.stdout.content", true)?;
        prefs.set("browser.dom.window.dump.enabled", true)?;
        prefs.set("webdriver.log.level", "trace")?;

        // TODO: Add more preferences to help with webdriver detection, not disabling the actual logic
        // // Disable various features that might interfere with webdriver detection testing
        // prefs.set("network.http.spdy.enabled", false)?;
        // prefs.set("network.http.spdy.enabled.deps", false)?;
        // prefs.set("network.http.spdy.enabled.http2", false)?;
        // prefs.set("dom.webdriver.enabled", false)?;

        // Additional preferences to help with debugging
        prefs.set("devtools.console.stdout.chrome", true)?;
        prefs.set("devtools.debugger.remote-enabled", true)?;
        prefs.set("devtools.chrome.enabled", true)?;
        prefs.set("marionette.log.level", "Trace")?;

        // Apply preferences to capabilities
        caps.set_preferences(prefs)?;

        // Set log level for geckodriver
        caps.set_log_level(thirtyfour::common::capabilities::firefox::LogLevel::Trace)?;

        println!("Connecting to WebDriver...");

        // Connect to the running geckodriver instance
        let driver = WebDriver::new("http://localhost:4444", caps).await?;
        println!("WebDriver connected successfully!");

        // Execute JavaScript to log webdriver detection results
        driver.execute(
            r#"
            console.log("=== WEBDRIVER DETECTION TEST ===");
            console.log("navigator.webdriver:", navigator.webdriver);
            console.log("window.navigator.webdriver:", window.navigator.webdriver);
            "#,
            Vec::<Value>::new()
        ).await?;

        // Navigate to a site that might have webdriver detection
        println!("Navigating to test site...");
        driver.goto("https://bot.sannysoft.com").await?;

        // Wait to allow the page to fully load and run detection scripts
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        // Take a screenshot for visual verification
        let screenshot = driver.screenshot_as_png().await?;
        std::fs::write("webdriver_test_result.png", screenshot).expect("Failed to save screenshot");

        // Print the page title
        println!("Page title: {}", driver.title().await?);

        // Get the page source for further analysis
        let page_source = driver.source().await?;
        std::fs::write("page_source.html", page_source).expect("Failed to save page source");

        // Execute JavaScript to extract and log detection results
        driver.execute(
            r#"
            console.log("=== DETECTION TEST RESULTS ===");
            document.querySelectorAll('.test-result').forEach(el => {
                console.log(el.parentElement.querySelector('.test-name').textContent + ': ' +
                           el.textContent);
            });
            "#,
            Vec::<Value>::new()
        ).await?;

        // Clean up
        println!("Shutting down WebDriver...");
        driver.quit().await?;

        // Stop geckodriver
        println!("Terminating geckodriver...");
        let _ = geckodriver.kill();

        println!("Test completed.");
        Ok(())
    }
}
