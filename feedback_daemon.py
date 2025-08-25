#!/usr/bin/env python3
"""
Echo daemon with extensive feedback and Whisper fallback
Shows clear status updates and handles Whisper library issues
"""

import sys
import time
import subprocess
import tempfile
import threading
from pathlib import Path
from evdev import InputDevice, categorize, ecodes

class FeedbackEchoDaemon:
    def __init__(self):
        self.device_path = "/dev/input/event2"  # MX Keys Mini
        self.recording = False
        self.temp_file = None
        self.record_process = None
        self.session_count = 0
        
    def show_status(self, message, icon="🔵"):
        """Show status with timestamp"""
        timestamp = time.strftime("%H:%M:%S")
        print(f"{icon} [{timestamp}] {message}")
        
        # Also try to show notification
        try:
            subprocess.run([
                'notify-send', 
                'Echo Daemon',
                message,
                '--icon=audio-input-microphone',
                '--expire-time=2000'
            ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass  # Notifications are optional
        
    def start_recording(self):
        """Start audio recording with feedback"""
        if self.recording:
            return
            
        self.session_count += 1
        self.show_status(f"🎤 Recording session #{self.session_count} started", "🎤")
        self.recording = True
        
        # Create temp file for recording
        self.temp_file = tempfile.NamedTemporaryFile(suffix='.wav', delete=False)
        self.temp_file.close()
        
        # Start parecord with feedback
        try:
            self.record_process = subprocess.Popen([
                'parecord', 
                '--format', 's16le',
                '--rate', '16000', 
                '--channels', '1',
                self.temp_file.name
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            self.show_status(f"✅ Audio recording to {Path(self.temp_file.name).name}", "🔊")
            
        except Exception as e:
            self.show_status(f"❌ Recording failed: {e}", "❌")
            self.recording = False
        
    def stop_recording(self):
        """Stop recording and transcribe with feedback"""
        if not self.recording:
            return
            
        self.show_status("🛑 Recording stopped, processing...", "🛑")
        self.recording = False
        
        # Stop recording
        if self.record_process:
            self.record_process.terminate()
            self.record_process.wait()
            
        # Check if we have audio data
        audio_file = Path(self.temp_file.name)
        if not audio_file.exists():
            self.show_status("❌ No audio file created", "❌")
            return
            
        file_size = audio_file.stat().st_size
        duration = file_size / (16000 * 2)  # Rough estimate for 16kHz 16-bit mono
        
        if file_size < 1000:
            self.show_status(f"⚠️  Recording too short ({file_size} bytes), skipping", "⚠️")
            audio_file.unlink(missing_ok=True)
            return
            
        self.show_status(f"📊 Audio captured: {file_size} bytes (~{duration:.1f}s)", "📊")
            
        # Transcribe in background thread
        threading.Thread(target=self._transcribe_audio, args=(audio_file,), daemon=True).start()
        
    def _transcribe_audio(self, audio_file):
        """Transcribe audio with multiple fallback methods"""
        try:
            self.show_status("🧠 Starting transcription...", "🧠")
            
            # Method 1: Try whisper-cpp first (faster, fewer dependencies)
            if self._try_whisper_cpp(audio_file):
                return
                
            # Method 2: Try openai-whisper
            if self._try_openai_whisper(audio_file):
                return
                
            # Method 3: Try whisper CLI with different approach
            if self._try_whisper_simple(audio_file):
                return
                
            self.show_status("❌ All transcription methods failed", "❌")
                
        except Exception as e:
            self.show_status(f"❌ Transcription error: {e}", "❌")
        finally:
            # Always cleanup
            audio_file.unlink(missing_ok=True)
            
    def _try_whisper_cpp(self, audio_file):
        """Try whisper.cpp (C++ implementation)"""
        try:
            self.show_status("🔄 Trying whisper.cpp...", "🔄")
            
            # Look for whisper.cpp binary
            whisper_cpp = None
            for path in ['/usr/bin/whisper-cpp', '/usr/local/bin/whisper-cpp', 'whisper-cpp']:
                if subprocess.run(['which', path], capture_output=True).returncode == 0:
                    whisper_cpp = path
                    break
                    
            if not whisper_cpp:
                self.show_status("⚠️  whisper.cpp not found", "⚠️")
                return False
                
            result = subprocess.run([
                whisper_cpp, 
                '-m', '/usr/share/whisper.cpp/models/ggml-base.bin',
                '-f', str(audio_file)
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout.strip():
                text = result.stdout.strip()
                self.show_status(f"✅ whisper.cpp: '{text}'", "✅")
                self._handle_success(text)
                return True
                
        except Exception as e:
            self.show_status(f"⚠️  whisper.cpp failed: {e}", "⚠️")
        return False
        
    def _try_openai_whisper(self, audio_file):
        """Try OpenAI Whisper Python package"""
        try:
            self.show_status("🔄 Trying OpenAI Whisper...", "🔄")
            
            # Try importing whisper first
            import whisper
            model = whisper.load_model("base")
            result = model.transcribe(str(audio_file))
            text = result["text"].strip()
            
            if text:
                self.show_status(f"✅ OpenAI Whisper: '{text}'", "✅")
                self._handle_success(text)
                return True
                
        except ImportError:
            self.show_status("⚠️  OpenAI Whisper not installed", "⚠️")
        except Exception as e:
            self.show_status(f"⚠️  OpenAI Whisper failed: {e}", "⚠️")
        return False
        
    def _try_whisper_simple(self, audio_file):
        """Try simple whisper CLI without complex dependencies"""
        try:
            self.show_status("🔄 Trying simple whisper CLI...", "🔄")
            
            # Convert to format whisper likes
            wav_file = audio_file.with_suffix('.wav')
            subprocess.run([
                'ffmpeg', '-i', str(audio_file), 
                '-ar', '16000', '-ac', '1', 
                str(wav_file), '-y'
            ], capture_output=True, check=True)
            
            # Try basic whisper command
            result = subprocess.run([
                'python3', '-c', 
                f"""
import whisper
model = whisper.load_model('base')
result = model.transcribe('{wav_file}')
print(result['text'])
"""
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                text = result.stdout.strip()
                if text:
                    self.show_status(f"✅ Simple Whisper: '{text}'", "✅")
                    self._handle_success(text)
                    return True
                    
            wav_file.unlink(missing_ok=True)
                
        except Exception as e:
            self.show_status(f"⚠️  Simple whisper failed: {e}", "⚠️")
        return False
        
    def _handle_success(self, text):
        """Handle successful transcription"""
        self._copy_to_clipboard(text)
        
    def _copy_to_clipboard(self, text):
        """Copy text to clipboard with feedback"""
        try:
            # Try wl-copy for Wayland
            subprocess.run(['wl-copy'], input=text, text=True, check=True)
            self.show_status("📋 Copied to clipboard (wl-copy)", "📋")
        except subprocess.CalledProcessError:
            try:
                # Fallback to xclip
                subprocess.run(['xclip', '-selection', 'clipboard'], 
                             input=text, text=True, check=True)
                self.show_status("📋 Copied to clipboard (xclip)", "📋")
            except subprocess.CalledProcessError:
                self.show_status("⚠️  Could not copy to clipboard", "⚠️")
                
    def listen_for_hotkey(self):
        """Listen for RIGHT CTRL press/release with feedback"""
        try:
            device = InputDevice(self.device_path)
            self.show_status(f"👂 Listening on {device.name}", "👂")
            self.show_status("Press and hold RIGHT CTRL to record", "ℹ️")
            
            for event in device.read_loop():
                if event.type == ecodes.EV_KEY:
                    key_event = categorize(event)
                    
                    if key_event.keycode == 'KEY_RIGHTCTRL':
                        if key_event.keystate == 1:  # Pressed
                            self.start_recording()
                        elif key_event.keystate == 0:  # Released
                            self.stop_recording()
                            
        except Exception as e:
            self.show_status(f"❌ Hotkey error: {e}", "❌")
            
    def run(self):
        """Main daemon loop with startup feedback"""
        print("=" * 60)
        self.show_status("🚀 Echo Daemon with Feedback Starting", "🚀")
        self.show_status("Features: RIGHT CTRL + Multiple Whisper backends", "ℹ️")
        print("=" * 60)
        
        try:
            self.listen_for_hotkey()
        except KeyboardInterrupt:
            self.show_status("👋 Daemon stopped by user", "👋")
            if self.recording:
                self.stop_recording()

if __name__ == "__main__":
    daemon = FeedbackEchoDaemon()
    daemon.run()
