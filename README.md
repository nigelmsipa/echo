# 🎤 Echo - Fast Speech-to-Text v0.2

Ultra-fast local speech transcription with **multiple activation methods** and enhanced reliability.

## 🆕 What's New in v0.2

- **🎯 Multiple activation methods** - No more keybinding issues!
- **🔧 Enhanced error handling** - Better debugging and recovery
- **⚡ Improved performance** - Faster transcription and response  
- **🖥️ Better desktop integration** - Works across all environments
- **📋 Fallback mechanisms** - Always have a way to activate Echo

## 🚀 Installation

```bash
git clone https://github.com/nigelmsipa/echo.git
cd echo
./install.sh
```

## 🎤 Activation Methods

Echo now provides **5 different ways** to activate speech transcription:

### Method 1: Global Hotkeys 🌐
- **F12** - Primary global hotkey
- **Ctrl+Shift+Space** - Alternative
- **Alt+Space** - Alternative

### Method 2: Desktop Shortcuts ⌨️
- **Super+M** - Hyprland/KDE
- **Super+F12** - File trigger method

### Method 3: Command Line 💻
```bash
echo-speak        # Activate Echo
echo-direct       # Direct transcription  
echo-start        # Start daemon
echo-stop         # Stop daemon
```

### Method 4: Application Menu 📱
- Search **"Echo Speech"** in your app launcher
- Click to activate transcription

### Method 5: Manual Trigger 🔧
```bash
echo trigger > /tmp/echo_trigger  # Activate via file
```

## ✨ Features

- **🚀 Ultra-fast** - Optimized whisper.cpp transcription
- **🔒 100% local** - No internet required, privacy-focused
- **🎯 Multi-desktop** - Works on Hyprland, GNOME, KDE, etc.
- **📋 Auto-clipboard** - Text automatically copied
- **⚡ GPU accelerated** - NVIDIA CUDA / AMD ROCm support
- **🛠️ Multiple fallbacks** - Always works, even if hotkeys fail

## 📖 Usage

1. **Start Echo daemon:**
   ```bash
   echo-start
   ```

2. **Activate transcription** (choose any method):
   - Press **F12** from any application
   - Run **echo-speak** in terminal
   - Use **Super+M** in Hyprland
   - Search "Echo Speech" in app launcher

3. **Speak clearly** for 5 seconds

4. **Text auto-copies** to clipboard

5. **Paste anywhere** with Ctrl+V

## 🎯 Perfect For

- **Development** - Voice comments and documentation
- **Writing** - Dictation and note-taking
- **Accessibility** - Hands-free text input
- **Productivity** - Quick voice memos
- **Languages** - Multilingual transcription

## 🔧 System Requirements

- **Linux** (Arch, Ubuntu, Fedora, etc.)
- **Working microphone** (USB, built-in, Bluetooth)
- **2GB+ RAM** recommended
- **Multi-core CPU** for best performance

## 📊 Performance

- **Transcription Speed:** 0.5-2 seconds for 5-second audio
- **Accuracy:** High-quality with whisper.cpp
- **Resource Usage:** ~500MB RAM during transcription
- **Hardware Support:** CPU optimized, GPU accelerated

## 🎤 Tested Hardware

- ✅ **HyperX SoloCast** - Excellent quality
- ✅ **Built-in laptop mics** - Good quality
- ✅ **USB headsets** - Reliable
- ✅ **Bluetooth headphones** - Works well

## 🛠️ Troubleshooting

### Global Hotkeys Not Working?
Try alternative activation methods:
```bash
echo-speak           # Command line
Super+M             # Desktop shortcut
echo trigger > /tmp/echo_trigger  # File trigger
```

### Audio Issues?
```bash
# Test microphone
parecord test.wav   # Speak, then Ctrl+C
paplay test.wav     # Should hear your voice

# Check devices
pactl list sources short

# Increase volume  
pactl set-source-volume @DEFAULT_SOURCE@ 80%
```

### Daemon Not Starting?
```bash
# Install dependencies
pip install --user pynput keyboard

# Check for errors
python3 ~/echo/daemon/speech_daemon_v2.py

# Direct fallback
echo-direct
```

## 📁 Project Structure

```
echo/
├── install.sh                 # One-click installation
├── scripts/
│   ├── quick_transcribe.sh    # Direct transcription
│   ├── echo_activate.sh       # Manual activation
│   └── integrate_echo.sh      # System integration
├── daemon/
│   ├── speech_daemon_v2.py    # Enhanced daemon
│   ├── start_daemon.sh        # Start daemon
│   └── stop_daemon.sh         # Stop daemon
└── docs/
    └── troubleshooting.md     # Detailed troubleshooting
```

## 🤝 Contributing

Echo is open source! We welcome:
- 🐛 **Bug reports** - Found an issue?
- 💡 **Feature requests** - Have an idea?
- 🔧 **Pull requests** - Want to contribute code?
- 📖 **Documentation** - Help improve the docs

## 📄 License

MIT License - Free for personal and commercial use.

## 🙏 Acknowledgments

- **whisper.cpp** - Georgi Gerganov's C++ implementation
- **OpenAI Whisper** - Original speech recognition model
- **Linux community** - Testing and feedback

---

**Echo v0.2** - Reliable, fast, local speech-to-text for everyone! 🎤⚡
