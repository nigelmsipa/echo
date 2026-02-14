use evdev::{Device, InputEventKind, Key};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const TEMP_FILE: &str = "/tmp/echo.wav";
const DATA_DIR: &str = ".local/share/echo";
const TRANSCRIPT_LOG: &str = "transcripts.log";


fn data_dir() -> PathBuf {
    let home = env::var("HOME").expect("HOME not set");
    PathBuf::from(home).join(DATA_DIR)
}

fn main() {
    println!("Echo - Speech-to-Text Daemon");
    println!("----------------------------------------");

    let log_path = data_dir().join(TRANSCRIPT_LOG);
    println!("Collecting transcripts to {}", log_path.display());

    setup_session_env();
    let api_key = load_api_key();
    check_dependencies();
    let keyboards = find_keyboards();

    if keyboards.is_empty() {
        eprintln!("ERROR: No keyboard devices found!");
        std::process::exit(1);
    }

    println!("----------------------------------------");
    println!("Ready! Hold RIGHT CTRL to record, release to transcribe");
    println!("Press Ctrl+C to stop");
    println!("----------------------------------------");

    // Signal handling
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc_handler(r);

    run_event_loop(&keyboards, &api_key, &running);
}

/// Install signal handler for clean shutdown
fn ctrlc_handler(running: Arc<AtomicBool>) {
    // SIGINT / SIGTERM
    unsafe {
        libc::signal(libc::SIGINT, signal_noop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, signal_noop as *const () as libc::sighandler_t);
    }
    // We'll just check `running` in the loop — the signal breaks epoll_wait
    std::thread::spawn(move || {
        // Actually, let's use a simpler approach: just set running=false
        // when the epoll breaks with EINTR
        let _ = running;
    });
}

extern "C" fn signal_noop(_: libc::c_int) {}

/// Read mako's environ for DBUS_SESSION_BUS_ADDRESS; set Wayland defaults
fn setup_session_env() {
    if env::var("DBUS_SESSION_BUS_ADDRESS").is_err() {
        if let Ok(output) = Command::new("pgrep").args(["-x", "mako"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(pid) = stdout.lines().next().filter(|s| !s.is_empty()) {
                let env_path = format!("/proc/{}/environ", pid);
                if let Ok(data) = fs::read(&env_path) {
                    let text = String::from_utf8_lossy(&data);
                    for var in text.split('\0') {
                        if let Some(val) = var.strip_prefix("DBUS_SESSION_BUS_ADDRESS=") {
                            env::set_var("DBUS_SESSION_BUS_ADDRESS", val);
                            println!("D-Bus session found from mako");
                            break;
                        }
                    }
                }
            }
        }
    }

    if env::var("XDG_RUNTIME_DIR").is_err() {
        let uid = unsafe { libc::getuid() };
        env::set_var("XDG_RUNTIME_DIR", format!("/run/user/{}", uid));
    }

    if env::var("WAYLAND_DISPLAY").is_err() {
        env::set_var("WAYLAND_DISPLAY", "wayland-1");
    }
}

/// Load API key from ~/nvoice or OPENAI_API_KEY
fn load_api_key() -> String {
    let home = env::var("HOME").expect("HOME not set");
    let nvoice = PathBuf::from(&home).join("nvoice");

    if let Ok(key) = fs::read_to_string(&nvoice) {
        let key = key.trim().to_string();
        if !key.is_empty() {
            println!("API key loaded");
            return key;
        }
    }

    if let Ok(key) = env::var("OPENAI_API_KEY") {
        if !key.is_empty() {
            println!("API key loaded from env");
            return key;
        }
    }

    eprintln!("ERROR: No API key found!");
    eprintln!("Add your OpenAI API key to ~/nvoice");
    std::process::exit(1);
}

/// Check that required system tools exist in PATH
fn check_dependencies() {
    let tools = ["pw-record", "wtype", "wl-copy", "notify-send"];
    let mut missing = Vec::new();

    for tool in &tools {
        let ok = Command::new("which")
            .arg(tool)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            missing.push(*tool);
        }
    }

    if !missing.is_empty() {
        eprintln!("ERROR: Missing tools: {}", missing.join(", "));
        eprintln!("Install: sudo xbps-install -S pipewire wtype wl-clipboard libnotify");
        std::process::exit(1);
    }
}

/// Scan /dev/input/event* for real keyboards with RIGHT CTRL
fn find_keyboards() -> Vec<String> {
    let mut keyboards = Vec::new();

    // Collect and sort event device paths
    let mut paths: Vec<PathBuf> = fs::read_dir("/dev/input")
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("event"))
                .unwrap_or(false)
        })
        .collect();
    paths.sort();

    for path in paths {
        let path_str = match path.to_str() {
            Some(s) => s.to_string(),
            None => continue,
        };

        let dev = match Device::open(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        // Must support key events
        let supported = match dev.supported_keys() {
            Some(keys) => keys,
            None => continue,
        };

        // Must have RIGHT CTRL
        if !supported.contains(Key::KEY_RIGHTCTRL) {
            continue;
        }

        // Skip virtual keyboards
        let name = dev.name().unwrap_or("").to_lowercase();
        if ["virtual", "keyd", "ydotool", "uinput"]
            .iter()
            .any(|v| name.contains(v))
        {
            continue;
        }

        println!("Found keyboard: {}", dev.name().unwrap_or("unknown"));
        keyboards.push(path_str);
    }

    keyboards
}

/// Desktop notification (fire-and-forget)
fn notify(title: &str, message: &str, icon: &str) {
    let _ = Command::new("notify-send")
        .args([
            "--app-name=Echo",
            "--urgency=normal",
            &format!("--icon={}", icon),
            "--hint=string:x-dunst-stack-tag:echo",
            "--hint=string:x-canonical-private-synchronous:echo",
            title,
            message,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Start pw-record, return child handle
fn start_recording() -> Option<Child> {
    println!("Recording...");
    notify("Echo Recording", "Speak now...", "media-record");

    // Remove old temp file
    let _ = fs::remove_file(TEMP_FILE);

    match Command::new("pw-record")
        .args(["--format=s16", "--channels=1", "--rate=16000", TEMP_FILE])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => Some(child),
        Err(e) => {
            eprintln!("Failed to start pw-record: {}", e);
            notify("Echo Error", "Failed to start recording", "dialog-error");
            None
        }
    }
}

/// Stop recording, transcribe, type text
fn stop_recording(child: &mut Child, api_key: &str) {
    println!("Processing...");

    // Kill pw-record
    let _ = child.kill();
    let _ = child.wait();

    std::thread::sleep(std::time::Duration::from_millis(100));

    // Check file
    let meta = match fs::metadata(TEMP_FILE) {
        Ok(m) => m,
        Err(_) => {
            println!("No audio detected");
            notify("Echo", "No audio detected", "dialog-warning");
            cleanup();
            return;
        }
    };

    if meta.len() < 1024 {
        println!("No audio detected");
        notify("Echo", "No audio detected", "dialog-warning");
        cleanup();
        return;
    }

    // Transcribe
    match transcribe(api_key) {
        Ok(text) if !text.is_empty() => {
            println!("Transcribed: {}", text);
            log_transcript(&text);
            type_text(&text);
            let preview = if text.len() > 50 {
                format!("{}...", &text[..50])
            } else {
                text
            };
            notify("Echo Done", &preview, "dialog-ok");
        }
        Ok(_) => {
            println!("No speech detected");
            notify("Echo", "No speech detected", "dialog-warning");
        }
        Err(e) => {
            eprintln!("API error: {}", e);
            notify("Echo Error", &e, "dialog-error");
        }
    }

    cleanup();
}

/// Build multipart body and POST to Whisper API
fn transcribe(api_key: &str) -> Result<String, String> {
    let boundary = "----EchoBoundary9876543210";

    // Read audio file
    let mut file_data = Vec::new();
    fs::File::open(TEMP_FILE)
        .and_then(|mut f| f.read_to_end(&mut file_data))
        .map_err(|e| format!("Failed to read audio: {}", e))?;

    // Build multipart body
    let mut body = Vec::new();

    // model field
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"model\"\r\n\r\n");
    body.extend_from_slice(b"whisper-1\r\n");

    // file field
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"file\"; filename=\"echo.wav\"\r\n",
    );
    body.extend_from_slice(b"Content-Type: audio/wav\r\n\r\n");
    body.extend_from_slice(&file_data);
    body.extend_from_slice(b"\r\n");

    // closing boundary
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

    let content_type = format!("multipart/form-data; boundary={}", boundary);

    let resp = ureq::post("https://api.openai.com/v1/audio/transcriptions")
        .set("Authorization", &format!("Bearer {}", api_key))
        .set("Content-Type", &content_type)
        .send_bytes(&body)
        .map_err(|e| format!("{}", e))?;

    let json_str = resp.into_string().map_err(|e| format!("{}", e))?;
    let json: serde_json::Value =
        serde_json::from_str(&json_str).map_err(|e| format!("{}", e))?;

    Ok(json["text"].as_str().unwrap_or("").trim().to_string())
}

/// Type text at cursor using dotool with boosted speed
fn type_text(text: &str) {
    use std::io::Write;

    let child = Command::new("dotool")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    match child {
        Ok(mut c) => {
            if let Some(mut stdin) = c.stdin.take() {
                let _ = writeln!(stdin, "typedelay 3");
                let _ = writeln!(stdin, "typehold 1");
                let _ = writeln!(stdin, "type {}", text);
            }
            let _ = c.wait();
            println!("Text typed");
        }
        Err(e) => {
            eprintln!("dotool failed: {}", e);
            notify("Echo Error", "dotool failed to type text", "dialog-error");
        }
    }
}

/// Append a timestamped transcript to the collection log
fn log_transcript(text: &str) {
    use std::io::Write;
    use std::time::SystemTime;

    let dir = data_dir();
    let _ = fs::create_dir_all(&dir);
    let path = dir.join(TRANSCRIPT_LOG);

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{}\t{}", timestamp, text);
        println!("Logged transcript ({} entries)", count_lines(&path));
    }
}

fn count_lines(path: &PathBuf) -> usize {
    fs::read_to_string(path)
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

/// Remove temp audio file
fn cleanup() {
    let _ = fs::remove_file(TEMP_FILE);
}

/// Main event loop using epoll on keyboard devices
fn run_event_loop(keyboard_paths: &[String], api_key: &str, running: &Arc<AtomicBool>) {
    // Open devices
    let mut devices: Vec<Device> = Vec::new();
    for path in keyboard_paths {
        match Device::open(path) {
            Ok(d) => devices.push(d),
            Err(e) => eprintln!("Warning: Could not open {}: {}", path, e),
        }
    }

    if devices.is_empty() {
        eprintln!("ERROR: Could not open any keyboard devices");
        std::process::exit(1);
    }

    // Build fd -> index map and set up epoll
    let epoll_fd = unsafe { libc::epoll_create1(0) };
    if epoll_fd < 0 {
        eprintln!("ERROR: epoll_create1 failed");
        std::process::exit(1);
    }

    let mut fd_to_idx: HashMap<i32, usize> = HashMap::new();

    for (i, dev) in devices.iter().enumerate() {
        let fd = dev.as_raw_fd();
        fd_to_idx.insert(fd, i);

        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: fd as u64,
        };
        unsafe {
            libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, fd, &mut ev);
        }
    }

    let mut record_child: Option<Child> = None;
    let mut events = vec![
        libc::epoll_event {
            events: 0,
            u64: 0
        };
        devices.len()
    ];

    while running.load(Ordering::Relaxed) {
        let n = unsafe {
            libc::epoll_wait(epoll_fd, events.as_mut_ptr(), events.len() as i32, 1000)
        };

        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                // Signal received
                running.store(false, Ordering::Relaxed);
                break;
            }
            continue;
        }

        for i in 0..n as usize {
            let fd = events[i].u64 as i32;
            let idx = match fd_to_idx.get(&fd) {
                Some(&i) => i,
                None => continue,
            };

            if let Ok(evs) = devices[idx].fetch_events() {
                for ev in evs {
                    if ev.kind() == InputEventKind::Key(Key::KEY_RIGHTCTRL) {
                        match ev.value() {
                            1 => {
                                // Key pressed — start recording
                                if record_child.is_none() {
                                    record_child = start_recording();
                                }
                            }
                            0 => {
                                // Key released — stop recording & transcribe
                                if let Some(ref mut child) = record_child {
                                    stop_recording(child, api_key);
                                }
                                record_child = None;
                            }
                            _ => {} // repeat events, ignore
                        }
                    }
                }
            }
        }
    }

    // Cleanup on exit
    println!("\nStopped");
    if let Some(ref mut child) = record_child {
        let _ = child.kill();
        let _ = child.wait();
    }
    cleanup();
    unsafe {
        libc::close(epoll_fd);
    }
}
