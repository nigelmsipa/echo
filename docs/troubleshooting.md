# 🔧 Echo Troubleshooting Guide

## Common Issues and Solutions

### 1. F12 Key Not Working

**Symptoms:** Daemon starts but F12 doesn't trigger recording

**Solutions:**
```bash
# Check if daemon is running
pgrep -f speech_daemon

# Check for pynput issues
python3 -c "from pynput import keyboard; print('pynput OK')"

# Install missing dependencies
pip install --user pynput
sudo pacman -S python-xlib  # Arch Linux

# Try alternative key in daemon/speech_daemon.py
# Change Key.f12 to Key.f11 or other key
```

### 2. No Audio Recording

**Symptoms:** "Recording failed or empty" error

**Solutions:**
```bash
# Test microphone directly
parecord --format=s16le --rate=16000 --channels=1 test.wav
# Speak for 3 seconds, then Ctrl+C

# Check audio devices
pactl list sources short

# Set correct default source
pactl set-default-source [device-name]

# Increase microphone volume
pactl set-source-volume @DEFAULT_SOURCE@ 80%
```

### 3. Whisper Not Found

**Symptoms:** "whisper binary not found" error

**Solutions:**
```bash
# Rebuild whisper.cpp
cd ~/apps/speech-to-text/whisper.cpp
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel $(nproc)

# Download model if missing
./models/download-ggml-model.sh base.en
```

### 4. Daemon Crashes After First Use

**Symptoms:** Works once then stops responding

**Solutions:**
```bash
# Use the fixed daemon version
cp daemon/speech_daemon.py ~/apps/speech-daemon/
chmod +x ~/apps/speech-daemon/speech_daemon.py

# Restart daemon
~/apps/speech-daemon/stop_daemon.sh
~/apps/speech-daemon/start_daemon.sh
```

### 5. Poor Transcription Quality

**Solutions:**
- Speak clearly and at normal pace
- Position microphone 6-8 inches from mouth
- Reduce background noise
- Increase microphone volume
- Use better quality microphone

### 6. Clipboard Not Working

**Solutions:**
```bash
# Wayland (default)
echo "test" | wl-copy
wl-paste

# X11 fallback
echo "test" | xclip -selection clipboard
xclip -o -selection clipboard
```

## Performance Optimization

### GPU Acceleration

**NVIDIA (CUDA):**
```bash
cd ~/apps/speech-to-text/whisper.cpp
cmake -B build -DCMAKE_BUILD_TYPE=Release -DWHISPER_CUBLAS=ON
cmake --build build --config Release --parallel $(nproc)
```

**AMD (ROCm):**
```bash
# Install ROCm first
# Then rebuild with:
cmake -B build -DCMAKE_BUILD_TYPE=Release -DWHISPER_HIPBLAS=ON
cmake --build build --config Release --parallel $(nproc)
```

### CPU Optimization

```bash
# Use all CPU cores
export OMP_NUM_THREADS=$(nproc)

# For older CPUs, try smaller model
cd ~/apps/speech-to-text/whisper.cpp
./models/download-ggml-model.sh tiny.en  # Faster but less accurate
```

## Getting Help

1. **Check logs:** `journalctl --user -f | grep speech`
2. **Test components:** Run scripts directly
3. **System info:** Include CPU, GPU, desktop environment
4. **Audio setup:** Test microphone with other applications

## Useful Commands

```bash
# Check system info
uname -a
lscpu | grep "Model name"
lspci | grep -i vga

# Audio debugging
pactl info
pactl list sources
arecord -l

# Process monitoring
ps aux | grep speech
top -p $(pgrep -f speech_daemon)
```
