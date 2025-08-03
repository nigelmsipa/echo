#!/bin/bash

echo "🚀 Starting Echo Speech-to-Text Daemon v0.2"
echo "==========================================="

# Kill any existing daemons
pkill -f speech_daemon 2>/dev/null || true
pkill -f echo 2>/dev/null || true
sleep 1

# Install keyboard library as backup
pip install --user keyboard 2>/dev/null || true

echo "🔧 System check:"
echo "   Audio: $(pactl --version 2>/dev/null | head -1 || echo 'ALSA fallback')"
echo "   Clipboard: $(wl-copy --version 2>/dev/null || echo 'xclip fallback')"
echo "   Python: $(python3 --version)"

# Start daemon
cd ~/apps/speech-daemon
python3 speech_daemon_v2.py &

DAEMON_PID=$!
echo "✅ Echo daemon started (PID: $DAEMON_PID)"

# Save PID and create status file
echo $DAEMON_PID > ~/.echo_daemon_pid
echo "running" > ~/.echo_status

echo
echo "🎤 ACTIVATION METHODS:"
echo "====================="
echo "Method 1: F12 key (if global hotkeys work)"
echo "Method 2: Ctrl+Shift+Space (alternative)"  
echo "Method 3: Alt+Space (alternative)"
echo "Method 4: Trigger file - echo trigger > /tmp/echo_trigger"
echo "Method 5: Direct script - ~/apps/speech-to-text/quick_transcribe.sh"
echo
echo "💡 Multiple methods ensure you can always activate Echo!"
echo
echo "🛑 To stop: pkill -f speech_daemon"
