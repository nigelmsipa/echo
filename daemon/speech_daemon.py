#!/usr/bin/env python3
"""
Robust Speech-to-Text Daemon - Fixed Version
Usage: Press F12 ONCE, speak for 5 seconds, done!
"""

import subprocess
import tempfile
import os
import sys
import time
import threading
from pathlib import Path

try:
    from pynput import keyboard
    from pynput.keyboard import Key, Listener
except ImportError:
    print("❌ pynput not installed. Run: pip install --user pynput")
    sys.exit(1)

class SpeechDaemon:
    def __init__(self):
        self.recording = False
        self.listener = None
        self.whisper_bin = Path.home() / "apps/speech-to-text/whisper.cpp/build/bin/whisper-cli"
        if not self.whisper_bin.exists():
            self.whisper_bin = Path.home() / "apps/speech-to-text/whisper.cpp/build/bin/main"
        
        self.model = Path.home() / "apps/speech-to-text/whisper.cpp/models/ggml-base.en.bin"
        
        print("🎤 Speech-to-Text Daemon (Fixed Version)")
        print("="*45)
        print("USAGE:")
        print("  1. Press F12 ONCE (don't hold!)")
        print("  2. Speak for 5 seconds")
        print("  3. Text auto-copies to clipboard")
        print("  4. Paste with Alt+V")
        print()
        print(f"Whisper: {self.whisper_bin}")
        print(f"Model: {self.model}")
        print()
        print("🚀 Ready! Press F12 from any application...")
        
    def record_and_transcribe(self):
        """Record audio and transcribe it - with better error handling"""
        if self.recording:
            print("🔄 Already recording, ignoring key press")
            return
            
        self.recording = True
        
        try:
            print("\n🎤 F12 pressed - Starting recording...")
            
            # Show notification that recording started
            subprocess.run([
                "notify-send", 
                "🎤 Recording Started", 
                "Speak now for 5 seconds...\n(Don't hold any keys!)", 
                "-t", "3000"
            ], capture_output=True, check=False)
            
            # Record audio
            temp_audio = "/tmp/speech_daemon_recording.wav"
            print("🎤 Recording for 5 seconds... SPEAK NOW!")
            
            # Use timeout to automatically stop after 5 seconds
            record_cmd = [
                "timeout", "5",
                "parecord", 
                "--format=s16le", 
                "--rate=16000", 
                "--channels=1", 
                temp_audio
            ]
            
            result = subprocess.run(record_cmd, capture_output=True)
            
            if not os.path.exists(temp_audio) or os.path.getsize(temp_audio) < 1000:
                print("❌ Recording failed or too small")
                subprocess.run([
                    "notify-send", 
                    "❌ Recording Failed", 
                    "No audio recorded or too quiet", 
                    "-t", "3000"
                ], check=False)
                return
            
            print(f"✅ Recorded {os.path.getsize(temp_audio)} bytes")
            
            # Show transcribing notification
            subprocess.run([
                "notify-send", 
                "🧠 Processing", 
                "Transcribing speech...", 
                "-t", "2000"
            ], check=False)
            
            print("🧠 Transcribing...")
            
            # Transcribe with whisper
            if "whisper-cli" in str(self.whisper_bin):
                cmd = [
                    str(self.whisper_bin),
                    "-m", str(self.model),
                    "-f", temp_audio,
                    "-t", "8",
                    "--no-timestamps"
                ]
            else:
                cmd = [
                    str(self.whisper_bin),
                    "--model", str(self.model),
                    "--file", temp_audio,
                    "--threads", "8",
                    "--no-timestamps"
                ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Extract transcription
            transcription = ""
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and not any(word in line.lower() for word in 
                    ['warning', 'deprecated', 'github.com', 'whisper-cli', 'loading', 'whisper_']):
                    transcription = line
                    break
            
            # Clean up audio file
            try:
                os.unlink(temp_audio)
            except:
                pass
            
            if transcription and len(transcription) > 2:
                print(f"✅ Transcribed: '{transcription}'")
                
                # Copy to clipboard
                subprocess.run(["wl-copy"], input=transcription, text=True, check=False)
                print("📋 Copied to clipboard!")
                
                # Show success notification
                subprocess.run([
                    "notify-send", 
                    "✅ Speech-to-Text Success", 
                    f"📋 Copied: {transcription}", 
                    "-t", "8000"
                ], check=False)
            else:
                print("❌ No speech detected or transcription failed")
                subprocess.run([
                    "notify-send", 
                    "❌ No Speech Detected", 
                    "Try speaking louder or closer to mic", 
                    "-t", "5000"
                ], check=False)
                
        except Exception as e:
            print(f"❌ Error during transcription: {e}")
            subprocess.run([
                "notify-send", 
                "❌ Speech-to-Text Error", 
                f"Error: {str(e)[:50]}...", 
                "-t", "5000"
            ], check=False)
        finally:
            print("🔄 Ready for next F12 press...\n")
            self.recording = False
    
    def on_key_press(self, key):
        """Handle key press events"""
        try:
            if key == Key.f12:
                print("🔑 F12 detected!")
                # Run in thread to avoid blocking the key listener
                threading.Thread(
                    target=self.record_and_transcribe, 
                    daemon=True,
                    name="TranscriptionThread"
                ).start()
                
        except Exception as e:
            print(f"Key handler error: {e}")
    
    def on_key_release(self, key):
        """Handle key release events"""
        if key == Key.esc:
            print("ESC pressed - stopping daemon")
            return False
    
    def start(self):
        """Start the daemon with auto-restart on error"""
        while True:
            try:
                print("🎧 Starting keyboard listener...")
                
                with Listener(
                    on_press=self.on_key_press,
                    on_release=self.on_key_release
                ) as listener:
                    listener.join()
                    
            except Exception as e:
                print(f"❌ Listener crashed: {e}")
                print("🔄 Restarting in 3 seconds...")
                time.sleep(3)
                continue
            
            # If we get here, ESC was pressed
            break

if __name__ == "__main__":
    print("Starting robust speech daemon...")
    daemon = SpeechDaemon()
    daemon.start()
