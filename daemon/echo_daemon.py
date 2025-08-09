#!/usr/bin/env python3
"""
Echo Speech-to-Text Daemon v2.0
Press-and-hold walkie-talkie style with Super+E and Waybar feedback
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
        
        # Press-and-hold state
        self.recording = False
        self.super_pressed = False
        self.e_pressed = False
        self.recording_start_time = None
        self.recording_process = None
        self.audio_file = None
        
        # Daemon state
        self.running = True
        self.current_state = "idle"  # idle, recording, processing, success, error
        
        # Threading
        self.waybar_thread = None
        self.silence_monitor_thread = None
        self.typing_monitor_thread = None
        
        # Setup logging
        self.setup_logging(log_level)
        
        # Load configuration
        self.config = self.load_config()
        
        # Initialize Waybar status
        self.waybar_status_file = Path(self.config.get('waybar', {}).get('status_file', '/tmp/echo_waybar_status.json'))
        self.update_waybar_status("idle", "🎤 Ready")
        
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
    
    def update_waybar_status(self, state, text, elapsed_time=None):
        """Update Waybar status with current daemon state"""
        try:
            status = {
                "text": text,
                "tooltip": f"Echo Daemon - {state.title()}",
                "class": f"echo-{state}",
                "state": state
            }
            
            if elapsed_time is not None:
                status["elapsed"] = elapsed_time
                
            with open(self.waybar_status_file, 'w') as f:
                json.dump(status, f)
                
            self.current_state = state
        except Exception as e:
            self.logger.warning(f"Failed to update Waybar status: {e}")
    
    def start_recording(self):
        """Start press-and-hold recording"""
        if self.recording:
            self.logger.warning("Already recording, ignoring start request")
            return
            
        # Reset state before starting new recording
        self.reset_recording_state()
        
        self.recording = True
        self.recording_start_time = time.time()
        
        # Create temporary audio file
        self.audio_file = tempfile.NamedTemporaryFile(suffix='.wav', delete=False)
        self.audio_file.close()
        
        # Start recording process
        cmd = [
            "parecord",
            "--format", self.config['record_format'],
            "--rate", str(self.config['record_rate']),
            "--channels", str(self.config['record_channels']),
            self.audio_file.name
        ]
        
        try:
            self.recording_process = subprocess.Popen(cmd, 
                                                    stdout=subprocess.PIPE, 
                                                    stderr=subprocess.PIPE)
            self.logger.info("Started press-and-hold recording")
            self.update_waybar_status("recording", "🔴 0s")
            
            # Start monitoring threads
            self.start_monitoring_threads()
            
        except Exception as e:
            self.logger.error(f"Failed to start recording: {e}")
            self.recording = False
            self.update_waybar_status("error", "❌ Error")
            self.reset_recording_state()

    def stop_recording(self):
        """Stop press-and-hold recording and process"""
        if not self.recording:
            self.logger.warning("Not recording, ignoring stop request")
            return
            
        # Check minimum hold duration
        if self.recording_start_time:
            hold_duration = time.time() - self.recording_start_time
            min_duration = self.config.get('press_and_hold', {}).get('min_hold_duration', 0.3)
            
            if hold_duration < min_duration:
                self.logger.info(f"Recording too short ({hold_duration:.2f}s), ignoring")
                self.cancel_recording()
                return
        
        self.recording = False
        
        # Stop recording process
        if self.recording_process:
            try:
                self.recording_process.terminate()
                self.recording_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.recording_process.kill()
            except Exception as e:
                self.logger.warning(f"Error stopping recording: {e}")
        
        # Stop monitoring threads
        self.stop_monitoring_threads()
        
        # Process the recording in a separate thread to keep keyboard listener responsive
        self.update_waybar_status("processing", "🧠 Processing")
        threading.Thread(target=self.process_recording, daemon=True).start()
    
    def cancel_recording(self):
        """Cancel recording without processing"""
        if not self.recording:
            return
            
        self.recording = False
        
        # Stop recording process
        if self.recording_process:
            try:
                self.recording_process.terminate()
                self.recording_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.recording_process.kill()
            except Exception as e:
                self.logger.warning(f"Error canceling recording: {e}")
        
        # Stop monitoring threads
        self.stop_monitoring_threads()
        
        # Clean up audio file
        if self.audio_file and os.path.exists(self.audio_file.name):
            os.unlink(self.audio_file.name)
            
        self.logger.info("Recording canceled")
        self.update_waybar_status("idle", "🎤 Ready")
    
    def start_monitoring_threads(self):
        """Start monitoring threads for recording"""
        # Elapsed time updater thread
        self.waybar_thread = threading.Thread(target=self.update_elapsed_time, daemon=True)
        self.waybar_thread.start()
        
        # Silence monitor thread (if enabled)
        if self.config.get('press_and_hold', {}).get('silence_auto_stop', 0) > 0:
            self.silence_monitor_thread = threading.Thread(target=self.monitor_silence, daemon=True)
            self.silence_monitor_thread.start()
        
        # Typing monitor thread (if enabled)
        if self.config.get('press_and_hold', {}).get('cancel_on_typing', False):
            self.typing_monitor_thread = threading.Thread(target=self.monitor_typing, daemon=True)
            self.typing_monitor_thread.start()
    
    def stop_monitoring_threads(self):
        """Stop all monitoring threads"""
        # Threads will stop when self.recording becomes False
        pass
    
    def update_elapsed_time(self):
        """Update Waybar with elapsed recording time"""
        while self.recording and self.recording_start_time:
            elapsed = time.time() - self.recording_start_time
            
            # Check max duration
            max_duration = self.config.get('press_and_hold', {}).get('max_hold_duration', 60)
            if elapsed >= max_duration:
                self.logger.info(f"Max recording duration ({max_duration}s) reached")
                self.stop_recording()
                break
            
            # Update Waybar with elapsed time
            self.update_waybar_status("recording", f"🔴 {int(elapsed)}s")
            
            # Update interval
            update_interval = self.config.get('waybar', {}).get('update_interval', 0.1)
            time.sleep(update_interval)
    
    def monitor_silence(self):
        """Monitor for silence and auto-stop recording"""
        # This is a simplified implementation
        # In a full implementation, you'd analyze the audio stream for silence
        silence_duration = self.config.get('press_and_hold', {}).get('silence_auto_stop', 3.0)
        
        # For now, just a placeholder - would need audio level monitoring
        while self.recording:
            time.sleep(0.5)
            # TODO: Implement actual silence detection
    
    def monitor_typing(self):
        """Monitor for typing and cancel recording if detected"""
        # This would monitor for other key presses during recording
        # For now, just a placeholder
        while self.recording:
            time.sleep(0.1)
            # TODO: Implement typing detection

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

    def process_recording(self):
        """Process the completed press-and-hold recording"""
        if not self.audio_file or not os.path.exists(self.audio_file.name):
            self.logger.error("No audio file to process")
            self.update_waybar_status("error", "❌ No Audio")
            self.reset_recording_state()  # Reset state on error
            return
            
        temp_audio = self.audio_file.name
        
        try:
            self.logger.info("Processing press-and-hold recording")
            
            # Validate recording file
            if not os.path.exists(temp_audio):
                raise Exception("No audio file created")
                
            file_size = os.path.getsize(temp_audio)
            self.logger.info(f"Processing {file_size} bytes of audio")
            
            if file_size < 1000:
                raise Exception(f"Audio file too small ({file_size} bytes)")
            
            # Processing notification
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
            
            # Cleanup temp file immediately
            try:
                os.unlink(temp_audio)
            except:
                pass
                
            if transcription and len(transcription.strip()) > 2:
                self.logger.info(f"Transcription successful: '{transcription}'")
                
                # Update Waybar with success
                self.update_waybar_status("success", "✅ Success")
                
                # Copy to clipboard and auto-paste
                if self.config.get('clipboard', True):
                    self.copy_to_clipboard(transcription)
                
                # Success notification
                if self.config['notifications']:
                    subprocess.run([
                        "notify-send", 
                        "✅ Echo Success", 
                        f"📋 Transcribed: {transcription}", 
                        "-t", "8000"
                    ])
                
                # Return to idle after brief success display
                threading.Timer(2.0, lambda: self.update_waybar_status("idle", "🎤 Ready")).start()
                
            else:
                self.logger.warning("No speech detected or transcription failed")
                self.update_waybar_status("error", "❌ No Speech")
                
                if self.config['notifications']:
                    subprocess.run([
                        "notify-send", 
                        "❌ Echo Failed", 
                        "No speech detected\nTry speaking louder", 
                        "-t", "5000"
                    ])
                
                # Return to idle after brief error display
                threading.Timer(3.0, lambda: self.update_waybar_status("idle", "🎤 Ready")).start()
            
        except Exception as e:
            self.logger.error(f"Recording/transcription error: {e}")
            self.update_waybar_status("error", "❌ Error")
            
            if self.config['notifications']:
                subprocess.run([
                    "notify-send", 
                    "❌ Echo Error", 
                    f"Error: {str(e)[:50]}...", 
                    "-t", "5000"
                ])
            
            # Return to idle after brief error display
            threading.Timer(3.0, lambda: self.update_waybar_status("idle", "🎤 Ready")).start()
            
        finally:
            self.logger.info("Recording session complete")
            # Reset all recording state
            self.reset_recording_state()

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
        """Copy text to clipboard and auto-paste"""
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
                return
        
        # Auto-paste after a longer delay to ensure clipboard is ready
        try:
            import time
            time.sleep(0.5)  # Increased delay to ensure clipboard is ready
            
            # Use wtype for Wayland or xdotool for X11 to simulate Ctrl+V
            try:
                subprocess.run(["wtype", "-M", "ctrl", "v"], check=True)
                self.logger.info("Auto-pasted text (Wayland)")
            except:
                try:
                    subprocess.run(["xdotool", "key", "ctrl+v"], check=True)
                    self.logger.info("Auto-pasted text (X11)")
                except:
                    self.logger.warning("Auto-paste failed - text is in clipboard for manual paste")
        except Exception as e:
            self.logger.warning(f"Auto-paste error: {e}")

    def reset_recording_state(self):
        """Reset all recording state variables to prepare for next recording"""
        try:
            # Clean up audio file
            if self.audio_file and os.path.exists(self.audio_file.name):
                try:
                    os.unlink(self.audio_file.name)
                except Exception as e:
                    self.logger.warning(f"Failed to clean up audio file: {e}")
            
            # Reset state variables
            self.audio_file = None
            self.recording_process = None
            self.recording_start_time = None
            
            # Ensure recording flag is false
            self.recording = False
            
            self.logger.debug("Recording state reset successfully")
            
        except Exception as e:
            self.logger.warning(f"Error resetting recording state: {e}")

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
        """Start press-and-hold pynput listener for Right Ctrl"""
        def on_press(key):
            try:
                # Check for Right Ctrl key press
                if key == Key.ctrl_r:
                    if not self.right_ctrl_pressed and self.config['hotkeys'].get('right_ctrl', False):
                        self.right_ctrl_pressed = True
                        self.logger.info("Right Ctrl pressed - starting recording")
                        self.start_recording()
                # ESC to stop daemon
                elif key == Key.esc:
                    self.logger.info("ESC pressed - stopping daemon")
                    self.running = False
                    return False
            except AttributeError:
                pass
        
        def on_release(key):
            try:
                # Check for Right Ctrl key release
                if key == Key.ctrl_r:
                    if self.right_ctrl_pressed:
                        self.right_ctrl_pressed = False
                        self.logger.info("Right Ctrl released - stopping recording")
                        self.stop_recording()
            except AttributeError:
                pass
        
        # Initialize state
        self.right_ctrl_pressed = False
        
        self.logger.info("Starting press-and-hold pynput listener for Right Ctrl...")
        try:
            # Start listener in a separate thread so it doesn't block
            def run_listener():
                with Listener(on_press=on_press, on_release=on_release) as listener:
                    while self.running:
                        time.sleep(0.1)
                    listener.stop()
            
            listener_thread = threading.Thread(target=run_listener, daemon=True)
            listener_thread.start()
            return True
            
        except Exception as e:
            self.logger.error(f"pynput listener failed: {e}")
            return False

    def start(self, daemon_mode=False):
        """Start the daemon with press-and-hold Super+E"""
        if self.is_running():
            self.logger.error("Daemon is already running")
            return False
        
        if daemon_mode:
            self.daemonize()
        
        self.logger.info("Starting Echo daemon with press-and-hold Super+E...")
        
        # Initialize Waybar status to idle
        self.update_waybar_status("idle", "🎤 Ready")
        
        # Start press-and-hold Super+E listener
        if self.start_pynput_listener():
            self.logger.info("Press-and-hold Super+E listener started successfully")
            # Keep daemon running
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.logger.info("Daemon interrupted by user")
            return True
        else:
            self.logger.error("Failed to start press-and-hold listener")
            return False

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
