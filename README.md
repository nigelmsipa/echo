# 🎤 Echo - Fast Speech-to-Text

Ultra-fast local speech transcription using whisper.cpp with global hotkey support.

## ✨ Features

- **🚀 Ultra-fast transcription** - Uses optimized whisper.cpp
- **🌐 Global hotkey** - Press F12 from any application  
- **📋 Auto-clipboard** - Transcribed text automatically copied
- **🔒 100% local** - No internet required, privacy-focused
- **🎯 Multi-desktop** - Works on Hyprland, GNOME, KDE, etc.
- **⚡ GPU accelerated** - Supports NVIDIA CUDA and AMD ROCm

## 🚀 Quick Start

```bash
# Clone and install
git clone https://github.com/nigelmsipa/echo.git
cd echo
./install.sh

# Start the daemon
~/apps/speech-daemon/start_daemon.sh

# Use it!
# Press F12 from any app → speak for 5 seconds → text in clipboard
```

## 📖 Usage

### Method 1: Global Daemon (Recommended)
1. **Start daemon:** `~/apps/speech-daemon/start_daemon.sh`
2. **Press F12** from any application (browser, terminal, IDE, etc.)
3. **Speak clearly** for 5 seconds
4. **Text auto-copies** to clipboard
5. **Paste anywhere** with Ctrl+V

### Method 2: Direct Script
```bash
# Record for 5 seconds (default)
~/apps/speech-to-text/quick_transcribe.sh

# Record for custom duration
~/apps/speech-to-text/quick_transcribe.sh 10
```

## 🎯 Perfect For

- **Coding** - Voice comments and documentation
- **Writing** - Quick notes and dictation  
- **Accessibility** - Hands-free text input
- **Multilingual** - Supports many languages
- **Note-taking** - Instant voice memos

## 🔧 System Requirements

- **OS:** Linux (Arch, Ubuntu, Fedora, etc.)
- **Audio:** Working microphone
- **CPU:** Multi-core recommended for speed
- **GPU:** Optional (NVIDIA/AMD for acceleration)
- **RAM:** 2GB+ recommended

## 📁 Project Structure

```
echo/
├── install.sh              # One-click installation
├── scripts/
│   └── quick_transcribe.sh  # Direct transcription script
├── daemon/
│   ├── speech_daemon.py     # Background daemon
│   ├── start_daemon.sh      # Start daemon
│   └── stop_daemon.sh       # Stop daemon
└── docs/
    └── troubleshooting.md   # Common issues and fixes
```

## 🛠️ How It Works

1. **Audio Recording** - Uses PulseAudio/PipeWire/ALSA
2. **AI Transcription** - whisper.cpp (C++ implementation)
3. **Global Hotkeys** - Python pynput for F12 detection  
4. **Clipboard Integration** - wl-clipboard (Wayland) / xclip (X11)
5. **Desktop Notifications** - libnotify for status updates

## ⚡ Performance

- **Transcription Speed:** ~0.5-2 seconds for 5-second audio
- **CPU Usage:** Optimized for multi-core systems
- **Memory:** ~500MB during transcription
- **First Run:** Slower due to model loading

## 🎤 Supported Hardware

- **USB Microphones** - HyperX, Blue Yeti, etc.
- **Laptop Built-in** - Most laptop microphones
- **Headset Mics** - Gaming and office headsets
- **Bluetooth Audio** - Wireless headphones with mic

## 🔧 Configuration

### Desktop Environment Integration

**Hyprland:**
```bash
# Auto-starts with system
exec-once = ~/apps/speech-daemon/start_daemon.sh
```

**GNOME/KDE:**
```bash
# Add to startup applications
~/apps/speech-daemon/start_daemon.sh
```

### Custom Keybindings
Edit `daemon/speech_daemon.py` to change from F12 to other keys.

## 🐛 Current Status

**✅ Working:**
- Speech transcription engine
- Audio recording (HyperX SoloCast tested)
- Direct script execution
- Whisper.cpp compilation and model download

**🔧 In Progress:**
- Global F12 hotkey daemon
- Consistent keybinding activation
- Desktop environment integration

**📋 Known Issues:**
- Daemon may not respond to F12 on some systems
- First transcription slower (model loading)
- pynput dependency issues on some Linux distros

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin feature-name`
5. Submit pull request

## 📄 License

MIT License - see LICENSE file for details.

## 🙏 Acknowledgments

- **whisper.cpp** - Georgi Gerganov's excellent C++ implementation
- **OpenAI Whisper** - Original speech recognition model
- **pynput** - Global keyboard detection

---

**Echo** - Fast, local, privacy-focused speech-to-text for Linux
