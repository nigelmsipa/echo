#!/usr/bin/env python3
"""
Simple Echo daemon using RIGHT CTRL hotkey
Works around keyd interference by using RIGHT CTRL instead of ALT
"""

import sys
import time
import subprocess
import tempfile
from pathlib import Path
from evdev import InputDevice, categorize, ecodes

class SimpleEchoDaemon:
    def __init__(self):
        self.device_path = "/dev/input/event2"  # MX Keys Mini
        self.recording = False
        self.temp_file = None
        
    def start_recording(self):
        """Start audio recording"""
        if self.recording:
            return
            
        print("🎤 Recording...")
        self.recording = True
        
        # Create temp file for recording
        self.temp_file = tempfile.NamedTemporaryFile(suffix='.wav', delete=False)
        self.temp_file.close()
        
        # Start parecord
        self.record_process = subprocess.Popen([
            'parecord', 
            '--format', 's16le',
            '--rate', '16000', 
            '--channels', '1',
            self.temp_file.name
        ])
        
    def stop_recording(self):
        """Stop recording and transcribe"""
        if not self.recording:
            return
            
        print("🛑 Stopping...")
        self.recording = False
        
        # Stop recording
        if hasattr(self, 'record_process'):
            self.record_process.terminate()
            self.record_process.wait()
            
        # Transcribe (placeholder - add your whisper call here)
        print(f"📝 Transcribing {self.temp_file.name}...")
        # TODO: Add whisper transcription here
        
        # Cleanup
        Path(self.temp_file.name).unlink(missing_ok=True)
        
    def listen_for_hotkey(self):
        """Listen for RIGHT CTRL press/release"""
        try:
            device = InputDevice(self.device_path)
            print(f"👂 Listening for RIGHT CTRL on {device.name}")
            
            for event in device.read_loop():
                if event.type == ecodes.EV_KEY:
                    key_event = categorize(event)
                    
                    if key_event.keycode == 'KEY_RIGHTCTRL':
                        if key_event.keystate == 1:  # Pressed
                            self.start_recording()
                        elif key_event.keystate == 0:  # Released
                            self.stop_recording()
                            
        except Exception as e:
            print(f"❌ Error: {e}")
            
    def run(self):
        """Main daemon loop"""
        print("🚀 Simple Echo Daemon Starting")
        print("Press and hold RIGHT CTRL to record")
        print("Press Ctrl+C to exit")
        
        try:
            self.listen_for_hotkey()
        except KeyboardInterrupt:
            print("\n👋 Daemon stopped")
            if self.recording:
                self.stop_recording()

if __name__ == "__main__":
    daemon = SimpleEchoDaemon()
    daemon.run()
