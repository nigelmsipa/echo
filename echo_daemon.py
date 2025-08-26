#!/usr/bin/env python3
"""
Echo - Simple hotkey-to-speech daemon for nigel OS ecosystem
"""
import subprocess
import tempfile
import os
import time
from faster_whisper import WhisperModel
from evdev import InputDevice, categorize, ecodes

class EchoDaemon:
    def __init__(self, hotkey_device="/dev/input/event0", model_size="base"):
        self.hotkey_device = hotkey_device
        self.model_size = model_size
        
        # State
        self.recording = False
        self.record_process = None
        self.temp_path = None
        
        # Initialize Whisper model with optimized CPU settings
        print("Loading Whisper model...")
        os.environ["OMP_NUM_THREADS"] = "4"  # Optimal thread count for performance
        self.model = WhisperModel(model_size, device="cpu", compute_type="int8", cpu_threads=4)
        
        print(f"Echo daemon initialized with {model_size} model")
    
    def start_recording(self):
        """Start audio recording using arecord (same as GUI)"""
        if self.recording:
            return
            
        self.recording = True
        print("🎤 Recording...")
        
        # Create temp file
        temp_file = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
        self.temp_path = temp_file.name
        temp_file.close()
        
        # Start recording with arecord (same as working GUI)
        try:
            self.record_process = subprocess.Popen([
                'arecord',
                '-f', 'S16_LE',
                '-c', '1',
                '-r', '16000',
                self.temp_path
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            print("❌ arecord not found. Install with: sudo pacman -S alsa-utils")
            self.recording = False
            return
    
    def stop_recording(self):
        """Stop recording and transcribe (same as GUI)"""
        if not self.recording:
            return
            
        self.recording = False
        
        # Stop arecord process
        if self.record_process:
            self.record_process.terminate()
            self.record_process.wait()
        
        print("🔄 Transcribing...")
        
        # Transcribe using faster_whisper (same as GUI)
        try:
            time.sleep(0.1)  # Brief pause
            
            if os.path.exists(self.temp_path) and os.path.getsize(self.temp_path) > 1024:
                segments, info = self.model.transcribe(self.temp_path, beam_size=5)
                text = ""
                for segment in segments:
                    text += segment.text
                text = text.strip()
            else:
                text = ""
                
        except Exception as e:
            print(f"❌ Transcription error: {e}")
            text = ""
        
        # Clean up audio file
        if self.temp_path and os.path.exists(self.temp_path):
            os.unlink(self.temp_path)
        
        if text.strip():
            print(f"📝 Text: {text.strip()}")
            self.insert_text(text.strip())
        else:
            print("❌ No speech detected")
    
    def insert_text(self, text):
        """Insert text at cursor position using xdotool"""
        try:
            subprocess.run(['xdotool', 'type', text], check=True)
        except subprocess.CalledProcessError:
            print("⚠️  Failed to insert text - is xdotool installed?")
        except FileNotFoundError:
            print("⚠️  xdotool not found - installing with: sudo pacman -S xdotool")
    
    def listen_hotkey(self):
        """Listen for hotkey presses"""
        try:
            device = InputDevice(self.hotkey_device)
            print(f"👂 Listening for hotkey on {device.name}")
            print("Hold key to record, release to transcribe and insert text")
            
            for event in device.read_loop():
                if event.type == ecodes.EV_KEY:
                    key_event = categorize(event)
                    
                    # Using right control key
                    if key_event.keycode == 'KEY_RIGHTCTRL':
                        if key_event.keystate == 1:  # Key pressed
                            self.start_recording()
                        elif key_event.keystate == 0:  # Key released
                            self.stop_recording()
                            
        except PermissionError:
            print(f"❌ Permission denied accessing {self.hotkey_device}")
            print("Run with sudo or add user to input group")
        except FileNotFoundError:
            print(f"❌ Device {self.hotkey_device} not found")
            print("List available devices with: ls /dev/input/event*")
    
    def run(self):
        """Main daemon loop"""
        try:
            self.listen_hotkey()
        except KeyboardInterrupt:
            print("\n👋 Echo daemon stopped")

if __name__ == "__main__":
    # Using your MX Keys Mini Keyboard
    daemon = EchoDaemon(hotkey_device="/dev/input/event2")
    daemon.run()