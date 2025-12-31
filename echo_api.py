#!/usr/bin/env python3
"""
Echo API - Clean Speech-to-Text Daemon using OpenAI Whisper API
No local model bloat. Just works.
"""

import sys
import time
import subprocess
import tempfile
import os
import glob
import select
from pathlib import Path
from evdev import InputDevice, categorize, ecodes

# OpenAI client
from openai import OpenAI


class EchoAPI:
    def __init__(self):
        self.device_paths = []
        self.devices = []
        self.recording = False
        self.temp_file = None
        self.record_process = None
        self.client = None

        print("Echo API - Speech-to-Text Daemon")
        print("-" * 40)

        # Load config and API key
        self._load_config()

        # Check dependencies
        self._check_dependencies()

        # Auto-detect keyboard devices
        self.device_paths = self._find_keyboard_devices()
        if not self.device_paths:
            print("ERROR: No keyboard devices found!")
            sys.exit(1)

        print("-" * 40)
        print("Ready! Hold RIGHT CTRL to record, release to transcribe")
        print("Press Ctrl+C to stop")
        print("-" * 40)

    def _load_config(self):
        """Load API key from ~/nvoice file"""
        api_key = None

        # Read from ~/nvoice
        nvoice_path = Path.home() / "nvoice"
        if nvoice_path.exists():
            try:
                api_key = nvoice_path.read_text().strip()
            except Exception as e:
                print(f"Warning: Could not read {nvoice_path}: {e}")

        # Fall back to environment variable
        if not api_key:
            api_key = os.environ.get("OPENAI_API_KEY")

        if not api_key:
            print("ERROR: No API key found!")
            print("Add your OpenAI API key to ~/nvoice")
            sys.exit(1)

        # Initialize OpenAI client
        self.client = OpenAI(api_key=api_key)
        print("API key loaded")

    def _check_dependencies(self):
        """Check required system tools"""
        tools = ['arecord', 'wtype', 'notify-send']
        missing = []

        for tool in tools:
            result = subprocess.run(['which', tool],
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
            if result.returncode != 0:
                missing.append(tool)

        if missing:
            print(f"ERROR: Missing tools: {', '.join(missing)}")
            print("Install: sudo pacman -S alsa-utils wtype libnotify")
            sys.exit(1)

    def _notify(self, title, message, urgency="normal", icon="audio-input-microphone"):
        """Desktop notification with replaceable tag"""
        subprocess.run([
            'notify-send',
            '--app-name=Echo',
            f'--urgency={urgency}',
            f'--icon={icon}',
            '--hint=string:x-dunst-stack-tag:echo',
            '--hint=string:x-canonical-private-synchronous:echo',
            title, message
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _find_keyboard_devices(self):
        """Find real keyboard devices with RIGHT CTRL"""
        keyboards = []

        for path in sorted(glob.glob('/dev/input/event*')):
            try:
                dev = InputDevice(path)

                # Must support keyboard events
                if ecodes.EV_KEY not in dev.capabilities():
                    continue

                # Must have RIGHT CTRL
                if ecodes.KEY_RIGHTCTRL not in dev.capabilities().get(ecodes.EV_KEY, []):
                    continue

                # Skip virtual keyboards
                name = dev.name.lower()
                if any(v in name for v in ['virtual', 'keyd', 'ydotool', 'uinput']):
                    continue

                keyboards.append(path)
                print(f"Found keyboard: {dev.name}")

            except (PermissionError, OSError):
                continue

        return keyboards

    def start_recording(self):
        """Start recording audio"""
        if self.recording:
            return

        self.recording = True
        print("Recording...")
        self._notify("Echo Recording", "Speak now...", urgency="critical", icon="media-record")

        # Create temp WAV file
        temp = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
        self.temp_file = temp.name
        temp.close()

        # Start arecord
        self.record_process = subprocess.Popen([
            'arecord', '-f', 'S16_LE', '-c', '1', '-r', '16000', self.temp_file
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop_recording(self):
        """Stop recording and transcribe via API"""
        if not self.recording:
            return

        self.recording = False
        print("Processing...")
        self._notify("Echo", "Processing...", icon="system-run")

        # Stop recording
        if self.record_process:
            self.record_process.terminate()
            self.record_process.wait()

        time.sleep(0.1)

        # Check file exists and has content
        if not os.path.exists(self.temp_file) or os.path.getsize(self.temp_file) < 1024:
            print("No audio detected")
            self._notify("Echo", "No audio detected", icon="dialog-warning")
            self._cleanup()
            return

        # Transcribe via OpenAI API
        try:
            with open(self.temp_file, "rb") as audio_file:
                response = self.client.audio.transcriptions.create(
                    model="whisper-1",
                    file=audio_file
                )

            text = response.text.strip()

            if text:
                print(f"Transcribed: {text}")
                self._type_text(text)
                # Show brief preview of what was transcribed
                preview = text[:50] + "..." if len(text) > 50 else text
                self._notify("Echo Done", preview, icon="dialog-ok")
            else:
                print("No speech detected")
                self._notify("Echo", "No speech detected", icon="dialog-warning")

        except Exception as e:
            print(f"API error: {e}")
            self._notify("Echo Error", str(e))

        self._cleanup()

    def _type_text(self, text):
        """Type text at cursor position"""
        try:
            subprocess.run(['wtype', text], check=True)
            print("Text inserted")
        except subprocess.CalledProcessError:
            # Fallback to clipboard
            subprocess.run(['wl-copy'], input=text.encode())
            print("Copied to clipboard (wtype failed)")
            self._notify("Echo", "Text copied to clipboard")

    def _cleanup(self):
        """Remove temp file"""
        if self.temp_file and os.path.exists(self.temp_file):
            os.unlink(self.temp_file)
            self.temp_file = None

    def run(self):
        """Main event loop"""
        try:
            # Open all keyboard devices
            self.devices = []
            for path in self.device_paths:
                try:
                    self.devices.append(InputDevice(path))
                except Exception as e:
                    print(f"Warning: Could not open {path}: {e}")

            if not self.devices:
                print("ERROR: Could not open any keyboard devices")
                sys.exit(1)

            fd_map = {dev.fd: dev for dev in self.devices}

            # Event loop
            while True:
                r, _, _ = select.select(fd_map.keys(), [], [])

                for fd in r:
                    device = fd_map[fd]
                    for event in device.read():
                        if event.type == ecodes.EV_KEY:
                            key = categorize(event)
                            if key.keycode == 'KEY_RIGHTCTRL':
                                if key.keystate == 1:  # pressed
                                    self.start_recording()
                                elif key.keystate == 0:  # released
                                    self.stop_recording()

        except PermissionError:
            print("ERROR: Permission denied for input devices")
            print("Fix: sudo usermod -a -G input $USER && reboot")
            sys.exit(1)

        except KeyboardInterrupt:
            print("\nStopped")
            self._cleanup()


def main():
    daemon = EchoAPI()
    daemon.run()


if __name__ == "__main__":
    main()
