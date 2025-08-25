#!/usr/bin/env python3
"""
Echo - Simple hotkey-to-speech daemon using system audio recording
"""
import subprocess
import threading
import tempfile
import os
import time
from faster_whisper import WhisperModel
from evdev import InputDevice, categorize, ecodes

class SimpleEcho:
    def __init__(self, hotkey_device="/dev/input/event2", model_size="base"):
        self.hotkey_device = hotkey_device
        self.model_size = model_size
        
        # State
        self.recording = False
        self.record_process = None
        
        # Initialize Whisper model
        print("Loading Whisper model...")
        import sys
        sys.stdout.flush()
        self.model = WhisperModel(model_size, device="cpu", compute_type="int8")
        print(f"✅ Echo initialized with {model_size} model")
        sys.stdout.flush()
    
    def start_recording(self):
        """Start audio recording using arecord"""
        if self.recording:
            return
            
        self.recording = True
        
        # Create temp file for recording
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
        self.temp_path = self.temp_file.name
        self.temp_file.close()
        
        print("🎤 Recording... (speak now)")
        import sys
        sys.stdout.flush()
        
        # Use arecord to record audio
        self.record_process = subprocess.Popen([
            'arecord',
            '-f', 'S16_LE',    # 16-bit little-endian
            '-c', '1',         # mono
            '-r', '16000',     # 16kHz sample rate
            self.temp_path
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    def stop_recording(self):
        """Stop recording and transcribe"""
        if not self.recording:
            return
            
        self.recording = False
        
        if self.record_process:
            self.record_process.terminate()
            self.record_process.wait()
        
        print("🔄 Transcribing...")
        import sys
        sys.stdout.flush()
        
        # Check if file exists and has content
        if os.path.exists(self.temp_path) and os.path.getsize(self.temp_path) > 1024:
            # Transcribe
            segments, info = self.model.transcribe(self.temp_path, beam_size=5)
            text = ""
            for segment in segments:
                text += segment.text
            
            if text.strip():
                print(f"📝 Text: {text.strip()}")
                self.insert_text(text.strip())
            else:
                print("❌ No speech detected")
        else:
            print("❌ No audio recorded")
        
        # Clean up
        if os.path.exists(self.temp_path):
            os.unlink(self.temp_path)
    
    def insert_text(self, text):
        """Insert text at cursor position using Wayland-compatible methods"""
        # Try wtype (Wayland equivalent of xdotool type)
        try:
            subprocess.run(['wtype', text], check=True)
            return
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        # Try ydotool (works on both X11 and Wayland)
        try:
            subprocess.run(['ydotool', 'type', text], check=True)
            return
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        # Fallback to clipboard
        try:
            subprocess.run(['wl-copy'], input=text.encode(), check=True)
            print(f"📋 Text copied to clipboard: {text}")
            return
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        
        print("⚠️  No text insertion method available")
        print("Install: sudo pacman -S wtype ydotool wl-clipboard")
    
    def find_keyboard_device(self):
        """Find the keyboard device automatically"""
        for i in range(32):  # Check first 32 event devices
            try:
                device_path = f"/dev/input/event{i}"
                device = InputDevice(device_path)
                
                # Check if device has keyboard capabilities
                if ecodes.EV_KEY in device.capabilities():
                    # Check if it has common keys
                    keys = device.capabilities()[ecodes.EV_KEY]
                    if ecodes.KEY_SPACE in keys:
                        print(f"🎹 Found keyboard: {device.name} at {device_path}")
                        return device_path
                        
            except (FileNotFoundError, PermissionError):
                continue
        
        print("❌ No keyboard device found")
        return None
    
    def listen_hotkey(self):
        """Listen for hotkey presses"""
        # Try to find keyboard automatically if default doesn't work
        device_path = self.hotkey_device
        
        try:
            device = InputDevice(device_path)
        except (FileNotFoundError, PermissionError):
            print(f"❌ Cannot access {device_path}")
            device_path = self.find_keyboard_device()
            if not device_path:
                return
            device = InputDevice(device_path)
        
        print(f"👂 Listening for hotkey on {device.name}")
        print("Press and hold RIGHT ALT to record, release to transcribe and insert text")
        print("Press Ctrl+C to exit")
        
        try:
            for event in device.read_loop():
                if event.type == ecodes.EV_KEY:
                    key_event = categorize(event)
                    
                    # Using RIGHT ALT key (RIGHTALT) as trigger
                    if key_event.keycode == 'KEY_RIGHTALT':
                        if key_event.keystate == 1:  # Key pressed
                            self.start_recording()
                        elif key_event.keystate == 0:  # Key released
                            self.stop_recording()
                            
        except PermissionError:
            print(f"❌ Permission denied accessing {device_path}")
            print("Run with sudo or add user to input group:")
            print("sudo usermod -a -G input $USER")
            print("Then log out and back in")
    
    def run(self):
        """Main daemon loop"""
        # Check dependencies
        try:
            subprocess.run(['arecord', '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            print("❌ arecord not found - install with: sudo pacman -S alsa-utils")
            return
        
        # Check for text insertion tools (Wayland compatible)
        has_text_tool = False
        for tool in ['wtype', 'ydotool', 'wl-copy']:
            try:
                subprocess.run([tool, '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                has_text_tool = True
                break
            except (FileNotFoundError, subprocess.CalledProcessError):
                continue
        
        if not has_text_tool:
            print("❌ No text insertion tool found")
            print("Install with: sudo pacman -S wtype ydotool wl-clipboard")
            return
        
        try:
            self.listen_hotkey()
        except KeyboardInterrupt:
            print("\n👋 Echo daemon stopped")

if __name__ == "__main__":
    echo = SimpleEcho()
    echo.run()