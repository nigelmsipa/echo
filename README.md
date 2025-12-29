# Echo

A fast, hotkey-driven speech-to-text system for Linux desktop environments.

## What is Echo?

Echo transforms your voice into text with a simple hotkey press. Hold Right Ctrl, speak, release - your words appear as typed text in any application. Perfect for quick dictation, coding comments, or hands-free text input.

## Features

- **Hotkey activation**: Right Ctrl to start/stop recording
- **Dual mode transcription**: Local (offline) or OpenAI API (higher accuracy)
- **Fast local processing**: Optimized CPU performance with 4-thread processing
- **Superior API accuracy**: Optional OpenAI Whisper API for better transcription
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

Echo supports two transcription modes configured via `config.json`:

### Mode 1: Local (Default)
Uses faster-whisper with local models for **zero internet, instant feedback**.

**Models Available:**
- `tiny`: Fastest, basic accuracy (0.4s transcription)
- `base`: Good balance - **default** (1.1s transcription)
- `small`: Better accuracy, slower (3.2s transcription)
- `medium/large`: Best accuracy, much slower

**Setup:**
```json
{
  "mode": "local",
  "local_model": "base"
}
```

### Mode 2: OpenAI API
Uses OpenAI's Whisper API for **superior accuracy** (recommended for important transcriptions).

**Setup:**
1. Get your API key from [OpenAI](https://platform.openai.com/api-keys)
2. Edit `config.json`:
```json
{
  "mode": "api",
  "openai_api_key": "sk-...",
  "api_model": "whisper-1"
}
```
3. Install the OpenAI package (included in requirements):
```bash
pip install openai>=1.0.0
```

**Benefits:**
- Higher accuracy than local models
- No GPU required (uses OpenAI's servers)
- Works offline from your machine's perspective

**Costs:**
- ~$0.02 per minute of audio (check OpenAI pricing)
- Make sure billing is enabled on your account

### Performance Tuning (Local Mode)
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

- **Flexible**: Choose between privacy (local) or accuracy (API)
- **Privacy**: Local mode runs everything offline, no cloud services
- **Accuracy**: API mode offers superior transcription quality
- **Speed**: Optimized for real-time usage with instant feedback
- **Simplicity**: One hotkey, immediate results
- **Cost-effective**: Local mode is completely free

## License

MIT License - built on OpenAI's open-source Whisper project.