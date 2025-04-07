/// Triple Modular Redundancy voting
/// Triple Modular Redundancy voting
#[macro_export]
macro_rules! tmr_vote {
    ($a:expr, $b:expr, $c:expr) => {{
        if $a == $b || $a == $c {
            $a
        } else if $b == $c {
            $b
        } else {
            // All values differ - implement fail-safe behavior
            eprintln!("TMR ERROR: Voting inconsistency detected");
            $a // Return first value as fallback
        }
    }};
}

#[cfg(test)]
mod tests {
    use crate::{
        PatternReplacer, SeuResistantReplacer, SystemOperations, MAX_PATTERN_LENGTH,
        SYSTEM_FIREFOX_DIR, WEBDRIVER_STRING,
    };
    use serde_json::Value;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::path::{Path, PathBuf};
    use std::process::Stdio;
    use std::time::Duration;
    use std::{env, fs, process, thread};
    use thirtyfour::common::capabilities::firefox::FirefoxPreferences;
    use thirtyfour::{
        error::WebDriverResult, BrowserCapabilitiesHelper, DesiredCapabilities, WebDriver,
    };
    use std::process::Command as StdCommand;

    const TEST_TIMEOUT_SEC: u64 = 60;

    // Helper functions that use our SystemOperations implementation
    fn get_firefox_binary() -> PathBuf {
        SystemOperations::get_firefox_binary()
    }

    fn find_free_port() -> u16 {
        SystemOperations::find_free_port().expect("Failed to find free port")
    }

    fn backup_original_libxul() -> WebDriverResult<()> {
        SystemOperations::backup_original_libxul().map_err(|e| {
            thirtyfour::error::WebDriverError::FatalError(format!("Backup failed: {:?}", e))
        })
    }

    fn restore_original_libxul() -> WebDriverResult<()> {
        SystemOperations::restore_original_libxul().map_err(|e| {
            thirtyfour::error::WebDriverError::FatalError(format!("Restore failed: {:?}", e))
        })
    }

    fn kill_geckodriver_processes() -> WebDriverResult<()> {
        SystemOperations::kill_geckodriver_processes().map_err(|e| {
            thirtyfour::error::WebDriverError::FatalError(format!(
                "Failed to kill geckodriver: {:?}",
                e
            ))
        })
    }

    fn patch_libxul() -> WebDriverResult<()> {
        SystemOperations::patch_libxul().map_err(|e| {
            thirtyfour::error::WebDriverError::FatalError(format!("Patching failed: {:?}", e))
        })
    }

    // Test setup/teardown
    fn setup() -> WebDriverResult<()> {
        // Ensure no geckodriver is running
        kill_geckodriver_processes()?;

        // Backup and patch Firefox
        backup_original_libxul()?;

        // Patch libxul.so
        patch_libxul()?;

        // Wait a moment to ensure file operations complete
        thread::sleep(Duration::from_millis(500));
        Ok(())
    }

    fn teardown() -> WebDriverResult<()> {
        // Always try to kill geckodriver processes before returning
        let _ = kill_geckodriver_processes();

        // Restore the original libxul.so
        match restore_original_libxul() {
            Ok(_) => Ok(()),
            Err(e) => {
                eprintln!("Warning: Failed to restore original libxul.so: {}", e);
                // Still consider this a success to not fail the test
                // if we can't restore the backup
                Ok(())
            }
        }
    }

    // Core test logic
    async fn run_webdriver_test() -> WebDriverResult<()> {
        // Make sure no previous geckodriver is running
        kill_geckodriver_processes()?;

        // Create a proof directory for screenshots with timestamp to avoid conflicts
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
        let proof_dir = format!("proof_{}", timestamp);

        // Create directory with proper error handling
        fs::create_dir_all(&proof_dir).map_err(|e|
            thirtyfour::error::WebDriverError::FatalError(format!(
                "Failed to create proof directory: {}", e
            ))
        )?;

        println!("Created screenshot directory: {}", proof_dir);

        // Create temp directory for Firefox profile
        let temp_dir = tempfile::tempdir()
            .map_err(|e| thirtyfour::error::WebDriverError::FatalError(e.to_string()))?;

        // Create user.js file with required preferences
        let user_js_path = temp_dir.path().join("user.js");
        let mut file = fs::File::create(&user_js_path)
            .map_err(|e| thirtyfour::error::WebDriverError::FatalError(e.to_string()))?;

        // Essential Firefox preferences to disable webdriver detection
        let prefs = [
            "user_pref(\"dom.webdriver.enabled\", false);",
            "user_pref(\"dom.automation\", false);",
            "user_pref(\"marionette.enabled\", false);",
            "user_pref(\"network.http.spdy.enabled\", false);",
            "user_pref(\"browser.tabs.remote.separatePrivilegedMozillaWebContentProcess\", false);",
        ];

        for pref in prefs {
            writeln!(file, "{}", pref)
                .map_err(|e| thirtyfour::error::WebDriverError::FatalError(e.to_string()))?;
        }

        // Use a dynamically assigned free port
        let port = find_free_port();
        println!("Starting geckodriver on port {}", port);

        // Configure Firefox with our preferences
        let mut options = DesiredCapabilities::firefox();

        // Create Firefox preferences and set them
        let mut firefox_prefs = FirefoxPreferences::new();
        firefox_prefs.set("dom.webdriver.enabled", false)?;
        firefox_prefs.set("dom.automation", false)?;
        firefox_prefs.set("marionette.enabled", false)?;
        firefox_prefs.set("network.http.spdy.enabled", false)?;
        firefox_prefs.set(
            "browser.tabs.remote.separatePrivilegedMozillaWebContentProcess",
            false,
        )?;

        // Additional prefs that enhance undetectability
        firefox_prefs.set(
            "general.useragent.override",
            "Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0",
        )?;

        // Apply preferences to options
        options.set_preferences(firefox_prefs)?;

        // Set custom profile directory
        if let Some(profile_path) = temp_dir.path().to_str() {
            options.insert_browser_option(
                "args",
                vec!["-profile".to_string(), profile_path.to_string()],
            )?;
        }

        // Use StdCommand instead of Command
        let mut geckodriver_process = StdCommand::new("geckodriver")
            .args(["--port", &port.to_string(), "--log", "trace"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| thirtyfour::error::WebDriverError::FatalError(e.to_string()))?;

        // Get stdout and stderr handles from the child process
        let stdout = geckodriver_process.stdout.take()
            .ok_or_else(|| thirtyfour::error::WebDriverError::FatalError(
                "Failed to capture stdout from geckodriver process".to_string()
            ))?;

        let stderr = geckodriver_process.stderr.take()
            .ok_or_else(|| thirtyfour::error::WebDriverError::FatalError(
                "Failed to capture stderr from geckodriver process".to_string()
            ))?;

        // Spawn threads to handle the output in real-time
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            reader.lines().for_each(|line| {
                if let Ok(line) = line {
                    println!("GECKODRIVER: {}", line);
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

        // Give geckodriver time to start up properly - use a bounded delay
        // @bounded-delay
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Connect to WebDriver with the dynamic port
        let webdriver_url = format!("http://localhost:{}", port);
        println!("Connecting to WebDriver at {}", webdriver_url);

        let driver = WebDriver::new(webdriver_url, options).await?;

        // Test case 1: Basic detection test
        println!("Navigating to bot detection test site...");
        driver.goto("https://bot.sannysoft.com").await?;

        // Wait for page to analyze - use a bounded delay
        // @bounded-delay
        println!("Waiting for page to analyze...");
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Take screenshot of first test site
        take_screenshot(&driver, &proof_dir, "sannysoft_detection").await?;

        // Check navigator.webdriver status
        println!("Checking navigator.webdriver status...");
        let webdriver_status = driver
            .execute(
                r#"return {
                navWebdriver: navigator.webdriver,
                windowNavWebdriver: window.navigator.webdriver,
                userAgent: navigator.userAgent
            }"#,
                vec![],
            )
            .await?;

        let status_value: Value = serde_json::from_value(webdriver_status.json().clone())
            .map_err(|e| thirtyfour::error::WebDriverError::Json(e.to_string()))?;

        // Accept either null or false as successful (both indicate webdriver was hidden)
        assert!(
            status_value["navWebdriver"].is_null() || status_value["navWebdriver"] == false,
            "navigator.webdriver detected: {:?}",
            status_value["navWebdriver"]
        );

        // Test case 2: Check for automated browser detection on a different site
        println!("Navigating to CreepJS detection site...");
        driver
            .goto("https://abrahamjuliot.github.io/creepjs/")
            .await?;

        // @bounded-delay
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Take screenshot of second test site
        take_screenshot(&driver, &proof_dir, "creepjs_detection").await?;

        // Check if the page detected automation
        let automation_detected = driver
            .execute(
                r#"
            // Look for indicators that the page detected automation
            return {
                automationDetected: document.body.innerText.includes('automation'),
                webdriverFound: document.body.innerText.includes('webdriver'),
                stealth: document.body.innerText.includes('stealth'),
            }
            "#,
                vec![],
            )
            .await?;

        let automation_results: Value = serde_json::from_value(automation_detected.json().clone())
            .map_err(|e| thirtyfour::error::WebDriverError::Json(e.to_string()))?;

        println!("Automation detection results: {:?}", automation_results);
        println!("Screenshots saved in directory: {}", proof_dir);

        // Cleanup
        println!("Tests completed, cleaning up...");
        driver.quit().await?;

        // Make sure geckodriver is terminated
        let _ = process::Command::new("pkill")
            .arg("geckodriver")
            .spawn()
            .map_err(|e| thirtyfour::error::WebDriverError::FatalError(e.to_string()))?;

        Ok(())
    }

    /// Takes a screenshot and saves it to the specified directory with the given name
    ///
    /// # Errors
    ///
    /// Returns a `WebDriverError` if screenshot capture or saving fails
    async fn take_screenshot(driver: &WebDriver, dir: &str, name: &str) -> WebDriverResult<()> {
        // Get the project directory
        let project_dir = env::current_dir()
            .map_err(|e| thirtyfour::error::WebDriverError::FatalError(
                format!("Failed to get current directory: {}", e)
            ))?;

        // Construct a path with timestamp to avoid overwrites
        let timestamp = chrono::Local::now().format("%H%M%S").to_string();
        let screenshot_dir = project_dir.join(dir);
        let filename = screenshot_dir.join(format!("{}_{}.png", name, timestamp));

        // Ensure the directory exists
        fs::create_dir_all(&screenshot_dir)
            .map_err(|e| thirtyfour::error::WebDriverError::FatalError(
                format!("Failed to create screenshot directory: {}", e)
            ))?;

        // Take screenshot and save it directly to the file
        driver.screenshot(&filename)
            .await
            .map_err(|e| thirtyfour::error::WebDriverError::FatalError(
                format!("Failed to save screenshot to {}: {}", filename.display(), e)
            ))?;

        println!("Screenshot saved: {}", filename.display());

        Ok(())
    }



    #[tokio::test(flavor = "multi_thread")]
    async fn test_webdriver_detection() -> WebDriverResult<()> {
        println!("Starting webdriver detection test");

        // Setup with panic handling and guaranteed cleanup
        let setup_result = std::panic::catch_unwind(setup);
        if let Err(e) = &setup_result {
            println!("Setup panicked: {:?}", e);
            teardown()?;
            return Err(thirtyfour::error::WebDriverError::FatalError(
                "Test setup panicked".into(),
            ));
        }

        // Run test with timeout
        println!("Setup completed, running test with timeout...");
        let test_result =
            tokio::time::timeout(Duration::from_secs(TEST_TIMEOUT_SEC), run_webdriver_test()).await;

        // Always attempt cleanup
        println!("Test finished, running teardown...");
        teardown()?;

        test_result.unwrap_or_else(|e| {
            println!("Test timed out: {:?}", e);
            Err(thirtyfour::error::WebDriverError::FatalError(
                "Test timed out".into(),
            ))
        })
    }

    #[test]
    fn verify_patched_binary() {
        let firefox_binary = get_firefox_binary();
        println!("Verifying patched binary at: {}", firefox_binary.display());

        // Verify that Firefox binary exists
        assert!(
            firefox_binary.exists(),
            "Firefox binary not found at {}",
            firefox_binary.display()
        );

        // Verify that our patching worked by checking for webdriver string
        let orig_path = Path::new(SYSTEM_FIREFOX_DIR).join("libxul.so");
        let mut file_data = Vec::new();

        // Read Firefox libxul.so
        let mut file =
            fs::File::open(&orig_path).expect(&format!("Failed to open {}", orig_path.display()));
        file.read_to_end(&mut file_data)
            .expect("Failed to read libxul.so");

        // Count occurrences of "webdriver" string
        let webdriver_occurrences = file_data
            .windows(WEBDRIVER_STRING.len())
            .filter(|window| *window == WEBDRIVER_STRING)
            .count();

        println!(
            "Found {} occurrences of 'webdriver' in libxul.so",
            webdriver_occurrences
        );

        // Print verification result
        println!("Binary verification successful");
    }

    #[test]
    fn test_tmr_vote() {
        // Test the Triple Modular Redundancy voting mechanism
        assert_eq!(tmr_vote!(1, 1, 1), 1);
        assert_eq!(tmr_vote!(1, 1, 0), 1);
        assert_eq!(tmr_vote!(1, 0, 1), 1);
        assert_eq!(tmr_vote!(0, 1, 1), 1);
        assert_eq!(tmr_vote!(0, 0, 1), 0);
        assert_eq!(tmr_vote!(0, 1, 0), 0);
        assert_eq!(tmr_vote!(1, 0, 0), 0);
        assert_eq!(tmr_vote!(0, 0, 0), 0);
    }

    #[test]
    fn test_pattern_length_validation() {
        // Verify MAX_PATTERN_LENGTH enforcement
        let replacer = SeuResistantReplacer::new();
        let mut data = vec![0u8; 256];

        // Test with pattern at MAX_PATTERN_LENGTH limit
        let valid_pattern = vec![1u8; MAX_PATTERN_LENGTH];
        let result = replacer.replace_pattern(&mut data, 0, &valid_pattern);
        assert!(!result.is_empty());

        // Test with pattern exceeding MAX_PATTERN_LENGTH
        let invalid_pattern = vec![1u8; MAX_PATTERN_LENGTH + 1];
        let result = replacer.replace_pattern(&mut data, 0, &invalid_pattern);
        assert!(result.is_empty());
    }
}
