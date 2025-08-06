#!/usr/bin/env python3
"""
Echo Speech-to-Text Daemon v1.0
Proper daemon implementation with systemd integration
"""

import os
import sys
import time
import signal
import logging
import threading
import subprocess
import tempfile
import json
import atexit
from pathlib import Path
from datetime import datetime

# Try multiple keyboard libraries
KEYBOARD_LIB = None
try:
    from pynput import keyboard
    from pynput.keyboard import Key, Listener
    KEYBOARD_LIB = "pynput"
except ImportError:
    try:
        import keyboard as kb
        KEYBOARD_LIB = "keyboard"
    except ImportError:
        KEYBOARD_LIB = None

class EchoDaemon:
    def __init__(self, config_file=None, log_level=logging.INFO):
        self.config_file = config_file or Path.home() / ".config/echo/daemon.json"
        self.pid_file = Path("/tmp/echo_daemon.pid")
        self.log_file = Path.home() / ".local/share/echo/daemon.log"
        self.recording = False
        self.running = True
        
        # Setup logging
        self.setup_logging(log_level)
        
        # Load configuration
        self.config = self.load_config()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGHUP, self.reload_config)
        
        # Register cleanup on exit
        atexit.register(self.cleanup)
        
        self.logger.info("Echo daemon initialized")
        self.logger.info(f"Keyboard library: {KEYBOARD_LIB}")
        self.logger.info(f"Whisper binary: {self.config['whisper_bin']}")
        self.logger.info(f"Model: {self.config['model']}")

    def setup_logging(self, log_level):
        """Setup proper logging with rotation"""
        # Ensure log directory exists
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Setup logger
        self.logger = logging.getLogger('echo_daemon')
        self.logger.setLevel(log_level)
        
        # File handler with rotation
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            self.log_file, 
            maxBytes=1024*1024,  # 1MB
            backupCount=5
        )
        file_handler.setLevel(log_level)
        
        # Console handler for non-daemon mode
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        if not self.is_daemon_mode():
            self.logger.addHandler(console_handler)

    def is_daemon_mode(self):
        """Check if running as daemon (no controlling terminal)"""
        try:
            os.tcgetpgrp(sys.stdin.fileno())
            return False
        except:
            return True

    def load_config(self):
        """Load configuration from file with defaults"""
        default_config = {
            "whisper_bin": str(Path.home() / "apps/speech-to-text/whisper.cpp/build/bin/whisper-cli"),
            "model": str(Path.home() / "apps/speech-to-text/whisper.cpp/models/ggml-base.en.bin"),
            "record_duration": 5,
            "record_format": "s16le",
            "record_rate": 16000,
            "record_channels": 1,
            "transcription_timeout": 30,
            "hotkeys": {
                "ctrl": True
            },
            "notifications": True,
            "clipboard": True,
            "trigger_file": "/tmp/echo_trigger"
        }
        
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
                    self.logger.info(f"Loaded config from {self.config_file}")
            else:
                # Create default config file
                self.config_file.parent.mkdir(parents=True, exist_ok=True)
                with open(self.config_file, 'w') as f:
                    json.dump(default_config, f, indent=2)
                self.logger.info(f"Created default config at {self.config_file}")
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            
        return default_config

    def reload_config(self, signum=None, frame=None):
        """Reload configuration (SIGHUP handler)"""
        self.logger.info("Reloading configuration...")
        self.config = self.load_config()

    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
        self.cleanup()
        sys.exit(0)

    def cleanup(self):
        """Cleanup resources and remove PID file"""
        try:
            if self.pid_file.exists():
                self.pid_file.unlink()
                self.logger.info("Removed PID file")
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

    def daemonize(self):
        """Daemonize the process"""
        try:
            # First fork
            pid = os.fork()
            if pid > 0:
                sys.exit(0)  # Exit parent
        except OSError as e:
            self.logger.error(f"Fork #1 failed: {e}")
            sys.exit(1)

        # Decouple from parent environment
        os.chdir('/')
        os.setsid()
        os.umask(0)

        try:
            # Second fork
            pid = os.fork()
            if pid > 0:
                sys.exit(0)  # Exit second parent
        except OSError as e:
            self.logger.error(f"Fork #2 failed: {e}")
            sys.exit(1)

        # Redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        
        with open('/dev/null', 'r') as si:
            os.dup2(si.fileno(), sys.stdin.fileno())
        with open('/dev/null', 'w') as so:
            os.dup2(so.fileno(), sys.stdout.fileno())
        with open('/dev/null', 'w') as se:
            os.dup2(se.fileno(), sys.stderr.fileno())

        # Write PID file
        with open(self.pid_file, 'w') as f:
            f.write(str(os.getpid()))
        
        self.logger.info(f"Daemon started with PID {os.getpid()}")

    def is_running(self):
        """Check if daemon is already running"""
        if not self.pid_file.exists():
            return False
            
        try:
            with open(self.pid_file, 'r') as f:
                pid = int(f.read().strip())
            
            # Check if process exists
            os.kill(pid, 0)
            return True
        except (OSError, ValueError):
            # Process doesn't exist, remove stale PID file
            try:
                self.pid_file.unlink()
            except:
                pass
            return False

    def record_and_transcribe(self):
        """Enhanced recording with better error handling"""
        if self.recording:
            self.logger.warning("Already recording, ignoring request")
            return
            
        self.recording = True
        temp_audio = f"/tmp/echo_recording_{os.getpid()}.wav"
        
        try:
            self.logger.info("Starting recording session")
            
            # Notification
            if self.config['notifications']:
                subprocess.run([
                    "notify-send", 
                    "🎤 Echo Recording", 
                    f"Speak now for {self.config['record_duration']} seconds!", 
                    "-t", "4000",
                    "-u", "normal"
                ], capture_output=True)
            
            # Record audio
            self.logger.info(f"Recording {self.config['record_duration']} seconds of audio...")
            
            record_cmd = [
                "timeout", f"{self.config['record_duration']}s",
                "parecord", 
                f"--format={self.config['record_format']}", 
                f"--rate={self.config['record_rate']}", 
                f"--channels={self.config['record_channels']}", 
                temp_audio
            ]
            
            result = subprocess.run(record_cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                self.logger.warning(f"parecord failed: {result.stderr}")
                # Try arecord fallback
                record_cmd = [
                    "arecord",
                    "-f", "S16_LE",
                    f"-r", str(self.config['record_rate']), 
                    "-c", str(self.config['record_channels']),
                    "-d", str(self.config['record_duration']),
                    temp_audio
                ]
                result = subprocess.run(record_cmd, capture_output=True)
            
            # Validate recording
            if not os.path.exists(temp_audio):
                raise Exception("No audio file created")
                
            file_size = os.path.getsize(temp_audio)
            self.logger.info(f"Recorded {file_size} bytes")
            
            if file_size < 1000:
                raise Exception(f"Audio file too small ({file_size} bytes)")
            
            # Transcription notification
            if self.config['notifications']:
                subprocess.run([
                    "notify-send", 
                    "🧠 Echo Processing", 
                    "Transcribing speech...", 
                    "-t", "3000"
                ], capture_output=True)
            
            self.logger.info("Starting transcription...")
            
            # Build transcription command
            if "whisper-cli" in str(self.config['whisper_bin']):
                cmd = [
                    str(self.config['whisper_bin']),
                    "-m", str(self.config['model']),
                    "-f", temp_audio,
                    "-t", "8",
                    "--no-timestamps",
                    "--language", "en"
                ]
            else:
                cmd = [
                    str(self.config['whisper_bin']),
                    "--model", str(self.config['model']),
                    "--file", temp_audio,
                    "--threads", "8",
                    "--no-timestamps",
                    "--language", "en"
                ]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=self.config['transcription_timeout']
            )
            
            # Extract transcription
            transcription = self.extract_transcription(result.stdout)
            
            # Cleanup temp file
            try:
                os.unlink(temp_audio)
            except:
                pass
                
            if transcription and len(transcription.strip()) > 2:
                self.logger.info(f"Transcription successful: '{transcription}'")
                
                # Copy to clipboard
                if self.config['clipboard']:
                    self.copy_to_clipboard(transcription)
                
                # Success notification
                if self.config['notifications']:
                    subprocess.run([
                        "notify-send", 
                        "✅ Echo Success", 
                        f"📋 Transcribed: {transcription}", 
                        "-t", "8000"
                    ])
                
            else:
                self.logger.warning("No speech detected or transcription failed")
                if self.config['notifications']:
                    subprocess.run([
                        "notify-send", 
                        "❌ Echo Failed", 
                        "No speech detected\nTry speaking louder", 
                        "-t", "5000"
                    ])
            
        except Exception as e:
            self.logger.error(f"Recording/transcription error: {e}")
            if self.config['notifications']:
                subprocess.run([
                    "notify-send", 
                    "❌ Echo Error", 
                    f"Error: {str(e)[:50]}...", 
                    "-t", "5000"
                ])
        finally:
            self.logger.info("Recording session complete")
            self.recording = False

    def extract_transcription(self, output):
        """Extract clean transcription from whisper output"""
        lines = output.strip().split('\n')
        
        for line in reversed(lines):
            line = line.strip()
            if line and not any(skip in line.lower() for skip in [
                'warning', 'deprecated', 'github.com', 'whisper-cli', 
                'loading', 'whisper_', 'processing', 'model'
            ]):
                return line
        return ""

    def copy_to_clipboard(self, text):
        """Copy text to clipboard with fallback methods"""
        try:
            subprocess.run(["wl-copy"], input=text, text=True, check=True)
            self.logger.info("Copied to clipboard (Wayland)")
        except:
            try:
                subprocess.run(["xclip", "-selection", "clipboard"], 
                             input=text, text=True, check=True)
                self.logger.info("Copied to clipboard (X11)")
            except:
                self.logger.warning("Clipboard copy failed")

    def start_keyboard_listener(self):
        """Start keyboard listener based on available library"""
        if KEYBOARD_LIB == "pynput":
            return self.start_pynput_listener()
        elif KEYBOARD_LIB == "keyboard":
            return self.start_keyboard_library_listener()
        else:
            self.logger.warning("No keyboard library available")
            return False

    def start_pynput_listener(self):
        """Start pynput-based listener"""
        def on_press(key):
            try:
                if key == Key.f12 and self.config['hotkeys']['f12']:
                    self.logger.info("F12 hotkey activated")
                    threading.Thread(target=self.record_and_transcribe, daemon=True).start()
            except AttributeError:
                pass
        
        def on_release(key):
            if key == Key.esc:
                self.logger.info("ESC pressed - stopping daemon")
                self.running = False
                return False
        
        self.logger.info("Starting pynput keyboard listener...")
        try:
            with Listener(on_press=on_press, on_release=on_release) as listener:
                listener.join()
        except Exception as e:
            self.logger.error(f"pynput listener failed: {e}")
            return False
        return True

    def start_keyboard_library_listener(self):
        """Start keyboard library listener"""
        import keyboard as kb
        
        self.logger.info("Starting keyboard library listener...")
        try:
            # Register hotkeys based on configuration
            for hotkey_name, enabled in self.config['hotkeys'].items():
                if enabled:
                    if hotkey_name == 'ctrl':
                        # Map 'ctrl' to 'ctrl+space' for better usability
                        kb.add_hotkey('ctrl+space', lambda: threading.Thread(target=self.record_and_transcribe, daemon=True).start())
                        self.logger.info(f"Registered hotkey: ctrl+space")
                    else:
                        kb.add_hotkey(hotkey_name, lambda: threading.Thread(target=self.record_and_transcribe, daemon=True).start())
                        self.logger.info(f"Registered hotkey: {hotkey_name}")
            
            self.logger.info("Hotkeys registered successfully")
            kb.wait('esc')
            return True
            
        except Exception as e:
            self.logger.error(f"keyboard library failed: {e}")
            return False

    def start_polling_mode(self):
        """Fallback: Check for trigger file"""
        trigger_file = self.config['trigger_file']
        self.logger.info(f"Starting polling mode: watching {trigger_file}")
        
        while self.running:
            if os.path.exists(trigger_file):
                self.logger.info("Trigger file detected")
                try:
                    os.unlink(trigger_file)
                except:
                    pass
                threading.Thread(target=self.record_and_transcribe, daemon=True).start()
            time.sleep(0.5)

    def start(self, daemon_mode=False):
        """Start the daemon"""
        if self.is_running():
            self.logger.error("Daemon is already running")
            return False
        
        if daemon_mode:
            self.daemonize()
        
        self.logger.info("Starting Echo daemon...")
        
        # Try keyboard listeners first
        if self.start_keyboard_listener():
            return True
        
        # Fallback to polling mode
        self.logger.warning("Keyboard listeners failed, using polling mode")
        self.start_polling_mode()
        return True

    def stop(self):
        """Stop the daemon"""
        if not self.is_running():
            self.logger.info("Daemon is not running")
            return True
        
        try:
            with open(self.pid_file, 'r') as f:
                pid = int(f.read().strip())
            
            os.kill(pid, signal.SIGTERM)
            self.logger.info(f"Sent SIGTERM to daemon (PID {pid})")
            
            # Wait for process to terminate
            for _ in range(10):
                try:
                    os.kill(pid, 0)
                    time.sleep(0.5)
                except OSError:
                    break
            else:
                # Force kill if still running
                os.kill(pid, signal.SIGKILL)
                self.logger.warning(f"Force killed daemon (PID {pid})")
            
            return True
        except Exception as e:
            self.logger.error(f"Error stopping daemon: {e}")
            return False

    def status(self):
        """Get daemon status"""
        if self.is_running():
            with open(self.pid_file, 'r') as f:
                pid = int(f.read().strip())
            return f"Echo daemon is running (PID {pid})"
        else:
            return "Echo daemon is not running"


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Echo Speech-to-Text Daemon')
    parser.add_argument('command', choices=['start', 'stop', 'restart', 'status', 'foreground'],
                       help='Daemon command')
    parser.add_argument('--config', '-c', help='Configuration file path')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    log_level = logging.DEBUG if args.verbose else logging.INFO
    daemon = EchoDaemon(config_file=args.config, log_level=log_level)
    
    if args.command == 'start':
        if daemon.start(daemon_mode=True):
            print("Echo daemon started")
        else:
            print("Failed to start daemon")
            sys.exit(1)
    
    elif args.command == 'stop':
        if daemon.stop():
            print("Echo daemon stopped")
        else:
            print("Failed to stop daemon")
            sys.exit(1)
    
    elif args.command == 'restart':
        daemon.stop()
        time.sleep(1)
        if daemon.start(daemon_mode=True):
            print("Echo daemon restarted")
        else:
            print("Failed to restart daemon")
            sys.exit(1)
    
    elif args.command == 'status':
        print(daemon.status())
    
    elif args.command == 'foreground':
        try:
            daemon.start(daemon_mode=False)
        except KeyboardInterrupt:
            print("\nShutting down...")
            daemon.cleanup()


if __name__ == "__main__":
    main()
