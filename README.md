# Echo

A fast, hotkey-driven speech-to-text system for Linux desktop environments.

## What is Echo?

Echo transforms your voice into text with a simple hotkey press. Hold Right Ctrl, speak, release - your words appear as typed text in any application. Perfect for quick dictation, coding comments, or hands-free text input.

## Features

- **Hotkey activation**: Right Ctrl to start/stop recording
- **Fast transcription**: Optimized CPU performance with 4-thread processing
- **Offline processing**: Uses local OpenAI Whisper models, no internet required
- **Desktop integration**: Works with any Linux application
- **Multiple interfaces**: CLI daemon, GUI, and unified launcher
- **Visual feedback**: System notifications and status indicators

## Quick Start

1. **Install dependencies**:
```bash
# Install system dependencies
bash scripts/setup.sh

# Install Python packages
pip install -r requirements/server.txt
```

2. **Run Echo**:
```bash
# Simple daemon
python echo_daemon.py

# GUI version  
python echo_gui.py

# Unified launcher (recommended)
python echo_launcher.py
```

3. **Use it**: Hold Right Ctrl, speak, release. Your text appears!

## Configuration

### Models Available
- `tiny`: Fastest, basic accuracy (0.4s transcription)
- `base`: Good balance - **recommended** (1.1s transcription) 
- `small`: Better accuracy, slower (3.2s transcription)
- `medium/large`: Best accuracy, much slower

### Performance Tuning
Echo automatically uses 4 CPU threads for optimal performance. Transcription times:
- **11 seconds of audio** → **1.1 seconds** processing time
- Model loads in 0.37 seconds

## Technical Details

**Built with:**
- [OpenAI Whisper](https://github.com/openai/whisper) for speech recognition
- [faster-whisper](https://github.com/SYSTRAN/faster-whisper) for optimized inference
- Python evdev for hotkey detection
- Linux audio stack (arecord/pactl)

**System Requirements:**
- Linux (tested on Arch Linux)
- Python 3.8+
- Audio input device (microphone)
- Right Ctrl key for hotkey activation

## Project Structure

```
echo/
├── echo_daemon.py          # Core daemon (CLI)
├── echo_gui.py             # GUI interface
├── echo_launcher.py        # Unified launcher
├── echo_simple.py          # Minimal implementation
├── requirements/           # Python dependencies
└── scripts/setup.sh        # System setup script
```

## Why Echo?

- **Privacy**: Everything runs locally, no cloud services
- **Speed**: Optimized for real-time usage
- **Simplicity**: One hotkey, immediate results
- **Free**: Built on open-source Whisper models

## License

MIT License - built on OpenAI's open-source Whisper project.