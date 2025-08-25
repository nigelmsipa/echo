#!/usr/bin/env python3
"""
Complete Echo daemon with RIGHT CTRL hotkey and Whisper transcription
Includes clipboard integration and notifications
"""

import sys
import time
import subprocess
import tempfile
import threading
from pathlib import Path
from evdev import InputDevice, categorize, ecodes

class WorkingEchoDaemon:
    def __init__(self):
        self.device_path = "/dev/input/event2"  # MX Keys Mini
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
        try:
            self.record_process = subprocess.Popen([
                'parecord', 
                '--format', 's16le',
                '--rate', '16000', 
                '--channels', '1',
                self.temp_file.name
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"❌ Recording failed: {e}")
            self.recording = False
        
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
            
        # Check if we have audio data
        audio_file = Path(self.temp_file.name)
        if not audio_file.exists() or audio_file.stat().st_size < 1000:
            print("⚠️  Recording too short, skipping transcription")
            audio_file.unlink(missing_ok=True)
            return
            
        # Transcribe in background thread to avoid blocking hotkey detection
        threading.Thread(target=self._transcribe_audio, args=(audio_file,), daemon=True).start()
        
    def _transcribe_audio(self, audio_file):
        """Transcribe audio file using Whisper"""
        try:
            print("🧠 Transcribing...")
            
            # Run Whisper
            result = subprocess.run([
                'whisper', 
                str(audio_file),
                '--model', 'base',
                '--output_format', 'txt',
                '--output_dir', '/tmp',
                '--language', 'en'
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Find the output text file
                txt_file = audio_file.with_suffix('.txt')
                if txt_file.exists():
                    with open(txt_file, 'r') as f:
                        text = f.read().strip()
                    
                    if text:
                        print(f"✅ Transcribed: '{text}'")
                        self._copy_to_clipboard(text)
                        self._show_notification(text)
                    else:
                        print("⚠️  No speech detected")
                    
                    # Cleanup
                    txt_file.unlink(missing_ok=True)
                else:
                    print("❌ Whisper output file not found")
            else:
                print(f"❌ Whisper failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print("❌ Transcription timeout")
        except Exception as e:
            print(f"❌ Transcription error: {e}")
        finally:
            # Always cleanup audio file
            audio_file.unlink(missing_ok=True)
            
    def _copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        try:
            # Use wl-copy for Wayland
            subprocess.run(['wl-copy'], input=text, text=True, check=True)
            print("📋 Copied to clipboard")
        except subprocess.CalledProcessError:
            try:
                # Fallback to xclip
                subprocess.run(['xclip', '-selection', 'clipboard'], 
                             input=text, text=True, check=True)
                print("📋 Copied to clipboard (xclip)")
            except subprocess.CalledProcessError:
                print("⚠️  Could not copy to clipboard")
                
    def _show_notification(self, text):
        """Show desktop notification"""
        try:
            # Truncate long text for notification
            display_text = text[:100] + "..." if len(text) > 100 else text
            subprocess.run([
                'notify-send', 
                'Echo STT',
                f'Transcribed: {display_text}',
                '--icon=audio-input-microphone'
            ], check=True)
        except subprocess.CalledProcessError:
            pass  # Notifications are optional
            
    def listen_for_hotkey(self):
        """Listen for RIGHT CTRL press/release"""
        try:
            device = InputDevice(self.device_path)
            print(f"👂 Listening for RIGHT CTRL on {device.name}")
            print("Press and hold RIGHT CTRL to record speech")
            print("Press Ctrl+C to exit")
            
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
        print("🚀 Complete Echo Daemon Starting")
        print("Features: RIGHT CTRL hotkey + Whisper + Clipboard + Notifications")
        
        try:
            self.listen_for_hotkey()
        except KeyboardInterrupt:
            print("\n👋 Daemon stopped")
            if self.recording:
                self.stop_recording()

if __name__ == "__main__":
    daemon = WorkingEchoDaemon()
    daemon.run()
