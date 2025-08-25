#!/usr/bin/env python3
"""
Simple working Echo daemon - uses basic whisper command
Focuses on reliability over complexity
"""

import sys
import time
import subprocess
import tempfile
import threading
from pathlib import Path
from evdev import InputDevice, categorize, ecodes

class SimpleWorkingDaemon:
    def __init__(self):
        self.device_path = "/dev/input/event2"  # MX Keys Mini
        self.recording = False
        self.temp_file = None
        self.record_process = None
        self.session_count = 0
        
    def log(self, message, icon="🔵"):
        """Simple logging with timestamp"""
        timestamp = time.strftime("%H:%M:%S")
        print(f"{icon} [{timestamp}] {message}")
        
    def start_recording(self):
        """Start audio recording"""
        if self.recording:
            return
            
        self.session_count += 1
        self.log(f"Recording session #{self.session_count}...", "🎤")
        self.recording = True
        
        # Create temp file
        self.temp_file = tempfile.NamedTemporaryFile(suffix='.wav', delete=False)
        self.temp_file.close()
        
        # Start recording
        try:
            self.record_process = subprocess.Popen([
                'parecord', 
                '--format', 's16le',
                '--rate', '16000', 
                '--channels', '1',
                self.temp_file.name
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
        except Exception as e:
            self.log(f"Recording failed: {e}", "❌")
            self.recording = False
        
    def stop_recording(self):
        """Stop recording and transcribe"""
        if not self.recording:
            return
            
        self.log("Processing...", "🛑")
        self.recording = False
        
        # Stop recording
        if self.record_process:
            self.record_process.terminate()
            self.record_process.wait()
            
        # Check audio file
        audio_file = Path(self.temp_file.name)
        if not audio_file.exists() or audio_file.stat().st_size < 1000:
            self.log("Recording too short, skipping", "⚠️")
            audio_file.unlink(missing_ok=True)
            return
            
        # Transcribe in background
        threading.Thread(target=self._transcribe, args=(audio_file,), daemon=True).start()
        
    def _transcribe(self, audio_file):
        """Simple transcription using basic whisper"""
        try:
            self.log("Transcribing...", "🧠")
            
            # Use the basic whisper command with simple output
            result = subprocess.run([
                'whisper', 
                str(audio_file),
                '--model', 'base',
                '--output_format', 'txt',
                '--output_dir', '/tmp'
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Look for the text file
                txt_file = audio_file.with_suffix('.txt')
                if txt_file.exists():
                    with open(txt_file, 'r') as f:
                        text = f.read().strip()
                    
                    if text:
                        self.log(f"SUCCESS: '{text}'", "✅")
                        self._copy_to_clipboard(text)
                    else:
                        self.log("No speech detected", "⚠️")
                    
                    txt_file.unlink(missing_ok=True)
                else:
                    self.log("Whisper output not found", "❌")
            else:
                # Show the actual error from whisper
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                self.log(f"Whisper failed: {error_msg}", "❌")
                
        except subprocess.TimeoutExpired:
            self.log("Transcription timeout", "❌")
        except Exception as e:
            self.log(f"Error: {e}", "❌")
        finally:
            audio_file.unlink(missing_ok=True)
            
    def _copy_to_clipboard(self, text):
        """Copy to clipboard"""
        try:
            subprocess.run(['wl-copy'], input=text, text=True, check=True)
            self.log("Copied to clipboard", "📋")
        except:
            try:
                subprocess.run(['xclip', '-selection', 'clipboard'], 
                             input=text, text=True, check=True)
                self.log("Copied to clipboard", "📋")
            except:
                self.log("Clipboard copy failed", "⚠️")
                
    def listen_for_hotkey(self):
        """Listen for RIGHT CTRL"""
        try:
            device = InputDevice(self.device_path)
            self.log(f"Listening on {device.name}", "👂")
            
            for event in device.read_loop():
                if event.type == ecodes.EV_KEY:
                    key_event = categorize(event)
                    
                    if key_event.keycode == 'KEY_RIGHTCTRL':
                        if key_event.keystate == 1:  # Pressed
                            self.start_recording()
                        elif key_event.keystate == 0:  # Released
                            self.stop_recording()
                            
        except Exception as e:
            self.log(f"Hotkey error: {e}", "❌")
            
    def run(self):
        """Main loop"""
        print("=" * 50)
        self.log("Echo Daemon Starting", "🚀")
        self.log("Press and hold RIGHT CTRL to record", "ℹ️")
        print("=" * 50)
        
        try:
            self.listen_for_hotkey()
        except KeyboardInterrupt:
            self.log("Daemon stopped", "👋")

if __name__ == "__main__":
    daemon = SimpleWorkingDaemon()
    daemon.run()
