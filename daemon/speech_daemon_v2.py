#!/usr/bin/env python3
"""
Echo Speech-to-Text Daemon v0.2
Multiple activation methods + better debugging
"""

import subprocess
import tempfile
import os
import sys
import time
import threading
import signal
from pathlib import Path

# Try multiple keyboard libraries
KEYBOARD_LIB = None
try:
    from pynput import keyboard
    from pynput.keyboard import Key, Listener
    KEYBOARD_LIB = "pynput"
    print("✅ Using pynput for global hotkeys")
except ImportError:
    try:
        import keyboard as kb
        KEYBOARD_LIB = "keyboard"
        print("✅ Using keyboard library for global hotkeys")
    except ImportError:
        print("❌ No keyboard library available")
        print("   Install with: pip install --user pynput keyboard")

class EchoDaemon:
    def __init__(self):
        self.recording = False
        self.running = True
        
        # Find whisper binary
        self.whisper_bin = Path.home() / "apps/speech-to-text/whisper.cpp/build/bin/whisper-cli"
        if not self.whisper_bin.exists():
            self.whisper_bin = Path.home() / "apps/speech-to-text/whisper.cpp/build/bin/main"
        
        self.model = Path.home() / "apps/speech-to-text/whisper.cpp/models/ggml-base.en.bin"
        
        print("🎤 Echo Speech-to-Text Daemon v0.2")
        print("=" * 40)
        print(f"Whisper binary: {self.whisper_bin}")
        print(f"Model: {self.model}")
        print(f"Keyboard library: {KEYBOARD_LIB}")
        print()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
    def signal_handler(self, signum, frame):
        print(f"\n🛑 Received signal {signum}, shutting down...")
        self.running = False
        sys.exit(0)
        
    def record_and_transcribe(self):
        """Enhanced recording with better error handling"""
        if self.recording:
            print("🔄 Already recording, please wait...")
            return
            
        self.recording = True
        temp_audio = "/tmp/echo_recording.wav"
        
        try:
            print("\n🎤 RECORDING STARTED")
            print("=" * 20)
            
            # Enhanced notification
            subprocess.run([
                "notify-send", 
                "🎤 Echo Recording", 
                "Speak now for 5 seconds!\n(Recording in progress...)", 
                "-t", "4000",
                "-u", "normal"
            ], capture_output=True)
            
            # Record with better error handling
            print("🎙️  Recording 5 seconds of audio...")
            
            # Try parecord first (PipeWire/PulseAudio)
            record_cmd = [
                "timeout", "5s",
                "parecord", 
                "--format=s16le", 
                "--rate=16000", 
                "--channels=1", 
                temp_audio
            ]
            
            result = subprocess.run(record_cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"❌ parecord failed: {result.stderr}")
                # Try arecord fallback
                record_cmd = [
                    "arecord",
                    "-f", "S16_LE",
                    "-r", "16000", 
                    "-c", "1",
                    "-d", "5",
                    temp_audio
                ]
                result = subprocess.run(record_cmd, capture_output=True)
            
            # Check if recording succeeded
            if not os.path.exists(temp_audio):
                raise Exception("No audio file created")
                
            file_size = os.path.getsize(temp_audio)
            print(f"📁 Recorded {file_size} bytes")
            
            if file_size < 1000:
                raise Exception(f"Audio file too small ({file_size} bytes)")
            
            # Transcription notification
            subprocess.run([
                "notify-send", 
                "🧠 Echo Processing", 
                "Transcribing speech...", 
                "-t", "3000"
            ], capture_output=True)
            
            print("🧠 Transcribing with whisper...")
            
            # Transcribe with enhanced command
            if "whisper-cli" in str(self.whisper_bin):
                cmd = [
                    str(self.whisper_bin),
                    "-m", str(self.model),
                    "-f", temp_audio,
                    "-t", "8",
                    "--no-timestamps",
                    "--language", "en"
                ]
            else:
                cmd = [
                    str(self.whisper_bin),
                    "--model", str(self.model),
                    "--file", temp_audio,
                    "--threads", "8",
                    "--no-timestamps",
                    "--language", "en"
                ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Better transcription extraction
            transcription = ""
            lines = result.stdout.strip().split('\n')
            
            for line in reversed(lines):  # Check from end
                line = line.strip()
                if line and not any(skip in line.lower() for skip in [
                    'warning', 'deprecated', 'github.com', 'whisper-cli', 
                    'loading', 'whisper_', 'processing', 'model'
                ]):
                    transcription = line
                    break
            
            # Cleanup
            try:
                os.unlink(temp_audio)
            except:
                pass
                
            if transcription and len(transcription.strip()) > 2:
                print(f"✅ SUCCESS: '{transcription}'")
                
                # Copy to clipboard with both methods
                try:
                    subprocess.run(["wl-copy"], input=transcription, text=True, check=True)
                    print("📋 Copied to clipboard (Wayland)")
                except:
                    try:
                        subprocess.run(["xclip", "-selection", "clipboard"], 
                                     input=transcription, text=True, check=True)
                        print("📋 Copied to clipboard (X11)")
                    except:
                        print("⚠️  Clipboard copy failed")
                
                # Success notification
                subprocess.run([
                    "notify-send", 
                    "✅ Echo Success", 
                    f"📋 Transcribed: {transcription}", 
                    "-t", "8000"
                ])
                
            else:
                print("❌ No speech detected or transcription failed")
                print(f"Raw output: {result.stdout}")
                subprocess.run([
                    "notify-send", 
                    "❌ Echo Failed", 
                    "No speech detected\nTry speaking louder", 
                    "-t", "5000"
                ])
            
        except Exception as e:
            print(f"❌ Error: {e}")
            subprocess.run([
                "notify-send", 
                "❌ Echo Error", 
                f"Error: {str(e)[:50]}...", 
                "-t", "5000"
            ])
        finally:
            print("🔄 Ready for next activation\n")
            self.recording = False
    
    def start_pynput_listener(self):
        """Start pynput-based listener"""
        def on_press(key):
            try:
                if key == Key.f12:
                    print("🔑 F12 detected (pynput)")
                    threading.Thread(target=self.record_and_transcribe, daemon=True).start()
                elif hasattr(key, 'char') and key.char == 'm':
                    # Check for Super+M (might work better)
                    print("🔑 M key detected")
            except AttributeError:
                pass
        
        def on_release(key):
            if key == Key.esc:
                print("ESC pressed - stopping daemon")
                self.running = False
                return False
        
        print("🎧 Starting pynput listener...")
        try:
            with Listener(on_press=on_press, on_release=on_release) as listener:
                listener.join()
        except Exception as e:
            print(f"❌ pynput listener failed: {e}")
            return False
        return True
    
    def start_keyboard_listener(self):
        """Start keyboard library listener"""
        import keyboard as kb
        
        print("🎧 Starting keyboard library listener...")
        try:
            # Multiple hotkey options
            kb.add_hotkey('f12', lambda: threading.Thread(target=self.record_and_transcribe, daemon=True).start())
            kb.add_hotkey('ctrl+shift+space', lambda: threading.Thread(target=self.record_and_transcribe, daemon=True).start())
            kb.add_hotkey('alt+space', lambda: threading.Thread(target=self.record_and_transcribe, daemon=True).start())
            
            print("✅ Hotkeys registered:")
            print("   F12 - Primary activation")
            print("   Ctrl+Shift+Space - Alternative")
            print("   Alt+Space - Alternative")
            
            kb.wait('esc')  # Wait until ESC is pressed
            return True
            
        except Exception as e:
            print(f"❌ keyboard library failed: {e}")
            return False
    
    def start_polling_mode(self):
        """Fallback: Check for trigger file"""
        trigger_file = "/tmp/echo_trigger"
        print("🔄 Fallback mode: Create /tmp/echo_trigger to activate")
        print("   Or use: echo trigger > /tmp/echo_trigger")
        
        while self.running:
            if os.path.exists(trigger_file):
                print("🔑 Trigger file detected")
                os.unlink(trigger_file)
                threading.Thread(target=self.record_and_transcribe, daemon=True).start()
            time.sleep(0.5)
    
    def start(self):
        """Start daemon with multiple fallback options"""
        print("🚀 Starting Echo daemon...")
        
        if KEYBOARD_LIB == "pynput":
            if self.start_pynput_listener():
                return
        
        if KEYBOARD_LIB == "keyboard":
            if self.start_keyboard_listener():
                return
        
        # Final fallback
        print("⚠️  Global hotkeys failed, using polling mode")
        self.start_polling_mode()

if __name__ == "__main__":
    daemon = EchoDaemon()
    daemon.start()
