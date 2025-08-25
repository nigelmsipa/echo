#!/usr/bin/env python3
"""
Echo daemon using pynput for Wayland/Hyprland compatibility
Uses RIGHT ALT as hotkey, works around keyd interference
"""

import sys
import time
import subprocess
import tempfile
import threading
from pathlib import Path
from pynput import keyboard

class PynputEchoDaemon:
    def __init__(self):
        self.recording = False
        self.temp_file = None
        self.record_process = None
        
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
        if self.record_process:
            self.record_process.terminate()
            self.record_process.wait()
            
        # Transcribe (placeholder - add your whisper call here)
        print(f"📝 Transcribing {self.temp_file.name}...")
        # TODO: Add whisper transcription here
        
        # Cleanup
        Path(self.temp_file.name).unlink(missing_ok=True)
        
    def on_press(self, key):
        """Handle key press events"""
        try:
            if key == keyboard.Key.alt_r:  # RIGHT ALT
                self.start_recording()
        except AttributeError:
            pass  # Special keys
            
    def on_release(self, key):
        """Handle key release events"""
        try:
            if key == keyboard.Key.alt_r:  # RIGHT ALT
                self.stop_recording()
            elif key == keyboard.Key.esc:
                print("\n👋 Daemon stopped")
                return False  # Stop listener
        except AttributeError:
            pass  # Special keys
            
    def run(self):
        """Main daemon loop"""
        print("🚀 Pynput Echo Daemon Starting")
        print("Press and hold RIGHT ALT to record")
        print("Press ESC to exit")
        
        try:
            # Start keyboard listener
            with keyboard.Listener(
                on_press=self.on_press,
                on_release=self.on_release
            ) as listener:
                listener.join()
                
        except KeyboardInterrupt:
            print("\n👋 Daemon stopped")
            if self.recording:
                self.stop_recording()

if __name__ == "__main__":
    daemon = PynputEchoDaemon()
    daemon.run()
