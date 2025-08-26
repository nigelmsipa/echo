#!/usr/bin/env python3
"""
Echo - Final Speech-to-Text Daemon for NigelOS
Like WhisperFlow but better - clear feedback at every step
"""

import sys
import time
import subprocess
import tempfile
import os
import glob
from pathlib import Path
from evdev import InputDevice, categorize, ecodes

class EchoDaemon:
    def __init__(self):
        self.device_path = None
        self.recording = False
        self.temp_file = None
        self.record_process = None
        
        # Initialize
        print("🚀 Echo Speech-to-Text Daemon Starting...")
        print("📍 Part of NigelOS ecosystem (Arch Linux + Hyprland)")
        
        # Check dependencies
        self._check_dependencies()
        
        # Auto-detect keyboard device
        self.device_path = self._find_keyboard_device()
        if not self.device_path:
            print("❌ No suitable keyboard device found!")
            sys.exit(1)
        
        # Load Whisper model
        print("🧠 Loading Whisper model...")
        try:
            from faster_whisper import WhisperModel
            self.model = WhisperModel("base", device="cpu", compute_type="int8")
            print("✅ Whisper model loaded successfully")
        except Exception as e:
            print(f"❌ Failed to load Whisper model: {e}")
            sys.exit(1)
        
        print("🎯 Echo daemon ready!")
        print("👂 Listening for RIGHT CTRL key...")
        print("📝 Press and hold RIGHT CTRL to record speech")
        print("🔄 Release RIGHT CTRL to transcribe and auto-type")
        print("⏹️  Press Ctrl+C to stop daemon")
        print("-" * 50)
    
    def _check_dependencies(self):
        """Check if required tools are available"""
        required_tools = ['arecord', 'wtype', 'notify-send']
        missing = []
        
        for tool in required_tools:
            try:
                # Use 'which' to check if tool exists
                result = subprocess.run(['which', tool], 
                                      stdout=subprocess.DEVNULL, 
                                      stderr=subprocess.DEVNULL)
                if result.returncode != 0:
                    missing.append(tool)
            except:
                missing.append(tool)
        
        if missing:
            print(f"❌ Missing required tools: {', '.join(missing)}")
            print("📦 Install with: sudo pacman -S alsa-utils wtype libnotify")
            sys.exit(1)
        
        print("✅ All dependencies found")
    
    def _notify(self, title, message, icon="dialog-information"):
        """Send desktop notification"""
        try:
            subprocess.run(['notify-send', '-i', icon, title, message], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass  # Notifications are nice-to-have, not critical
    
    def _find_keyboard_device(self):
        """Auto-detect the keyboard device that supports RIGHT CTRL"""
        print("🔍 Auto-detecting keyboard device...")
        
        # Priority order: prefer MX Keys Mini, then any keyboard with RIGHT CTRL
        device_paths = sorted(glob.glob('/dev/input/event*'))
        
        keyboard_devices = []
        
        for device_path in device_paths:
            try:
                device = InputDevice(device_path)
                
                # Check if device supports keyboard events
                if ecodes.EV_KEY not in device.capabilities():
                    continue
                    
                # Check if device supports RIGHT CTRL key
                if ecodes.KEY_RIGHTCTRL not in device.capabilities().get(ecodes.EV_KEY, []):
                    continue
                
                # This device can handle RIGHT CTRL
                device_info = {
                    'path': device_path,
                    'name': device.name,
                    'is_mx_keys': 'MX Keys' in device.name
                }
                keyboard_devices.append(device_info)
                print(f"   📱 Found: {device_path} - {device.name}")
                
            except (PermissionError, OSError):
                continue
        
        if not keyboard_devices:
            print("❌ No keyboard devices with RIGHT CTRL support found")
            return None
        
        # Prefer MX Keys Mini if available, otherwise use first keyboard found
        for device in keyboard_devices:
            if device['is_mx_keys']:
                print(f"✅ Selected MX Keys: {device['path']} - {device['name']}")
                return device['path']
        
        # Fallback to first available keyboard
        selected = keyboard_devices[0]
        print(f"✅ Selected keyboard: {selected['path']} - {selected['name']}")
        return selected['path']
    
    def start_recording(self):
        """Start audio recording with clear feedback"""
        if self.recording:
            return
        
        print("🎤 RECORDING STARTED")
        self._notify("Echo Recording", "🎤 Recording speech...", "audio-input-microphone")
        
        self.recording = True
        
        # Create temp file
        temp_file = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
        self.temp_file = temp_file.name
        temp_file.close()
        
        # Start recording with arecord
        try:
            self.record_process = subprocess.Popen([
                'arecord',
                '-f', 'S16_LE',
                '-c', '1',
                '-r', '16000',
                self.temp_file
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            print("🔴 Recording in progress... (speak now)")
            
        except Exception as e:
            print(f"❌ Recording failed: {e}")
            self._notify("Echo Error", f"Recording failed: {e}", "dialog-error")
            self.recording = False
    
    def stop_recording(self):
        """Stop recording and transcribe with clear feedback"""
        if not self.recording:
            return
        
        print("🛑 RECORDING STOPPED")
        self.recording = False
        
        # Stop recording process
        if self.record_process:
            self.record_process.terminate()
            self.record_process.wait()
        
        # Brief pause for file to be written
        time.sleep(0.2)
        
        # Check if we have audio
        if not os.path.exists(self.temp_file) or os.path.getsize(self.temp_file) < 1024:
            print("⚠️  No audio recorded (file too small)")
            self._notify("Echo Warning", "No audio detected", "dialog-warning")
            self._cleanup()
            return
        
        print("🧠 TRANSCRIBING...")
        self._notify("Echo Processing", "🧠 Transcribing speech...", "system-run")
        
        # Transcribe audio
        try:
            segments, info = self.model.transcribe(self.temp_file, beam_size=5)
            text = ""
            for segment in segments:
                text += segment.text
            text = text.strip()
            
            if text:
                print(f"📝 TRANSCRIBED: '{text}'")
                self._notify("Echo Success", f"Transcribed: {text}", "dialog-information")
                
                # Auto-type the text
                print("⌨️  AUTO-TYPING...")
                self._type_text(text)
                
            else:
                print("❌ No speech detected in audio")
                self._notify("Echo Warning", "No speech detected", "dialog-warning")
                
        except Exception as e:
            print(f"❌ Transcription failed: {e}")
            self._notify("Echo Error", f"Transcription failed: {e}", "dialog-error")
        
        self._cleanup()
    
    def _type_text(self, text):
        """Type text at cursor position"""
        try:
            subprocess.run(['wtype', text], check=True)
            print("✅ Text typed successfully")
            self._notify("Echo Complete", "✅ Text inserted!", "dialog-information")
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to type text: {e}")
            # Fallback to clipboard
            try:
                subprocess.run(['wl-copy'], input=text.encode(), check=True)
                print("📋 Text copied to clipboard instead")
                self._notify("Echo Fallback", "📋 Text copied to clipboard", "edit-copy")
            except:
                print("❌ Failed to copy to clipboard too")
                self._notify("Echo Error", "Failed to insert or copy text", "dialog-error")
    
    def _cleanup(self):
        """Clean up temporary files"""
        if self.temp_file and os.path.exists(self.temp_file):
            os.unlink(self.temp_file)
            self.temp_file = None
    
    def listen_for_hotkey(self):
        """Main loop - listen for RIGHT CTRL key presses"""
        try:
            device = InputDevice(self.device_path)
            print(f"🎯 Connected to: {device.name}")
            
            for event in device.read_loop():
                if event.type == ecodes.EV_KEY:
                    key_event = categorize(event)
                    
                    if key_event.keycode == 'KEY_RIGHTCTRL':
                        if key_event.keystate == 1:  # Key pressed
                            self.start_recording()
                        elif key_event.keystate == 0:  # Key released
                            self.stop_recording()
                            
        except PermissionError:
            print(f"❌ Permission denied accessing {self.device_path}")
            print("💡 Fix: sudo usermod -a -G input $USER && reboot")
            sys.exit(1)
            
        except FileNotFoundError:
            print(f"❌ Device {self.device_path} not found")
            print("💡 Check available devices: ls /dev/input/event*")
            sys.exit(1)
            
        except KeyboardInterrupt:
            print("\n👋 Echo daemon stopped by user")
            self._cleanup()
            
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            self._cleanup()
            sys.exit(1)

def main():
    """Main entry point"""
    daemon = EchoDaemon()
    daemon.listen_for_hotkey()

if __name__ == "__main__":
    main()
