#!/bin/bash

# Echo Speech-to-Text Installation v0.2
set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

echo "🎤 Echo Speech-to-Text v0.2"
echo "=========================="
echo "Enhanced keybinding support + multiple activation methods"
echo

# System dependencies
log_info "Installing system dependencies..."
if command -v pacman &> /dev/null; then
    sudo pacman -S --noconfirm git cmake make gcc pkgconf alsa-utils \
        libnotify xclip wl-clipboard python python-pip
else
    log_info "Please install: git cmake make gcc alsa-utils libnotify python3 pip"
fi

# Python dependencies
log_info "Installing Python packages..."
pip install --user pynput keyboard

# Create directories
mkdir -p ~/apps/{speech-to-text,speech-daemon}

# Copy files
log_info "Installing Echo components..."
cp scripts/quick_transcribe.sh ~/apps/speech-to-text/
cp daemon/speech_daemon_v2.py ~/apps/speech-daemon/speech_daemon.py
cp daemon/*.sh ~/apps/speech-daemon/
chmod +x ~/apps/speech-to-text/*.sh ~/apps/speech-daemon/*

# Build whisper.cpp
log_info "Building whisper.cpp (this may take a few minutes)..."
cd ~/apps/speech-to-text

if [ ! -d "whisper.cpp" ]; then
    git clone https://github.com/ggerganov/whisper.cpp.git
fi

cd whisper.cpp
git pull
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel $(nproc)

if [ ! -f "models/ggml-base.en.bin" ]; then
    ./models/download-ggml-model.sh base.en
fi

cd ~/echo

# System integration
log_info "Setting up system integration..."
./scripts/integrate_echo.sh

log_success "Echo v0.2 installation complete!"

echo
echo "🎉 What's new in v0.2:"
echo "======================="
echo "✅ Multiple activation methods"
echo "✅ Better error handling" 
echo "✅ Enhanced debugging"
echo "✅ Fallback mechanisms"
echo "✅ System integration"
echo
echo "🎤 Try these activation methods:"
echo "   1. F12 (global hotkey)"
echo "   2. Super+M (Hyprland)"
echo "   3. echo-speak (command)"
echo "   4. Direct: echo-direct"
echo
echo "🚀 Start daemon: echo-start"
