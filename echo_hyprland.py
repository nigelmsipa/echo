#!/usr/bin/env python3
"""
Echo for Hyprland - Uses Hyprland binds instead of direct input monitoring
This is the proper way to do hotkeys in Hyprland/Wayland
"""
import sys
import subprocess
import tempfile
import os
import time
import argparse
from faster_whisper import WhisperModel

class HyprlandEcho:
    def __init__(self, model_size="base"):
        self.model_size = model_size
        self.model = None
        self.recording = False
        self.record_process = None
        self.temp_path = None
        
        print("🔄 Loading Whisper model...")
        self.model = WhisperModel(model_size, device="cpu", compute_type="int8")
        print("✅ Echo ready for Hyprland!")
    
    def start_recording(self):
        """Start recording"""
        if self.recording:
            return
        
        self.recording = True
        print("🎤 Recording started...")
        
        # Create temp file
        temp_file = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
        self.temp_path = temp_file.name
        temp_file.close()
        
        # Start recording
        self.record_process = subprocess.Popen([
            'arecord',
            '-f', 'S16_LE',
            '-c', '1', 
            '-r', '16000',
            self.temp_path
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        return "Recording started"
    
    def stop_recording(self):
        """Stop recording and transcribe"""
        if not self.recording:
            return "Not recording"
        
        self.recording = False
        print("🔄 Processing...")
        
        # Stop recording
        if self.record_process:
            self.record_process.terminate()
            self.record_process.wait()
        
        time.sleep(0.1)  # Brief pause
        
        # Transcribe
        if os.path.exists(self.temp_path) and os.path.getsize(self.temp_path) > 1024:
            segments, info = self.model.transcribe(self.temp_path, beam_size=5)
            text = ""
            for segment in segments:
                text += segment.text
            
            if text.strip():
                print(f"📝 Transcribed: {text.strip()}")
                self.insert_text(text.strip())
                result = f"Typed: {text.strip()}"
            else:
                print("❌ No speech detected")
                result = "No speech detected"
        else:
            print("❌ No audio recorded")
            result = "No audio recorded"
        
        # Clean up
        if os.path.exists(self.temp_path):
            os.unlink(self.temp_path)
        
        return result
    
    def toggle_recording(self):
        """Toggle recording state"""
        if self.recording:
            return self.stop_recording()
        else:
            return self.start_recording()
    
    def insert_text(self, text):
        """Insert text using wtype"""
        try:
            subprocess.run(['wtype', text], check=True)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            print(f"❌ Failed to type text: {e}")
            # Fallback to clipboard
            try:
                subprocess.run(['wl-copy'], input=text.encode(), check=True)
                print("📋 Text copied to clipboard instead")
            except:
                print("❌ Failed to copy to clipboard too")

def main():
    parser = argparse.ArgumentParser(description="Echo Speech-to-Text for Hyprland")
    parser.add_argument('action', choices=['start', 'stop', 'toggle'], 
                       help='Action to perform')
    parser.add_argument('--model', default='base', 
                       help='Whisper model size (default: base)')
    
    args = parser.parse_args()
    
    echo = HyprlandEcho(model_size=args.model)
    
    
    if args.action == 'start':
        result = echo.start_recording()
    elif args.action == 'stop':
        result = echo.stop_recording()
    elif args.action == 'toggle':
        result = echo.toggle_recording()
    
    print(result)

if __name__ == "__main__":
    main()