#!/bin/bash

# Echo - Speech-to-Text Installation Script
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

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

echo "🎤 Echo - Fast Speech-to-Text"
echo "============================="
echo "Local AI-powered speech transcription"
echo

# Check system
if ! command -v git &> /dev/null; then
    echo "❌ Git not found. Install with: sudo pacman -S git"
    exit 1
fi

# Install system dependencies
log_info "Installing system dependencies..."
if command -v pacman &> /dev/null; then
    sudo pacman -S --noconfirm git cmake make gcc pkgconf alsa-utils \
        libnotify xclip wl-clipboard python python-pip
elif command -v apt &> /dev/null; then
    sudo apt update
    sudo apt install -y git cmake build-essential pkg-config \
        alsa-utils libnotify-bin xclip wl-clipboard python3 python3-pip
else
    log_warning "Unsupported package manager. Install dependencies manually."
fi

# Install Python packages
log_info "Installing Python packages..."
pip install --user pynput

# Create app directories
mkdir -p ~/apps/speech-to-text ~/apps/speech-daemon

# Copy scripts
cp scripts/quick_transcribe.sh ~/apps/speech-to-text/
cp daemon/* ~/apps/speech-daemon/
chmod +x ~/apps/speech-to-text/quick_transcribe.sh
chmod +x ~/apps/speech-daemon/*.sh ~/apps/speech-daemon/*.py

# Build whisper.cpp
log_info "Building whisper.cpp..."
cd ~/apps/speech-to-text

if [ ! -d "whisper.cpp" ]; then
    git clone https://github.com/ggerganov/whisper.cpp.git
fi

cd whisper.cpp
git pull
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel $(nproc)

# Download model
if [ ! -f "models/ggml-base.en.bin" ]; then
    ./models/download-ggml-model.sh base.en
fi

log_success "Installation complete!"

echo
echo "🎤 Usage:"
echo "  Start daemon: ~/apps/speech-daemon/start_daemon.sh"
echo "  Press F12 from any application to record speech"
echo "  Or run directly: ~/apps/speech-to-text/quick_transcribe.sh"

