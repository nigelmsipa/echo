#!/bin/bash

echo "🚀 Starting Fixed Speech-to-Text Daemon..."

# Kill any existing daemon
pkill -f speech_daemon 2>/dev/null || true
sleep 1

# Start new fixed daemon
cd ~/apps/speech-daemon
python3 speech_daemon_fixed.py &

DAEMON_PID=$!
echo "✅ Fixed Speech Daemon started (PID: $DAEMON_PID)"
echo ""
echo "📖 USAGE INSTRUCTIONS:"
echo "======================"
echo "1. Press F12 ONCE (don't hold!)"
echo "2. Speak clearly for 5 seconds"  
echo "3. Text auto-copies to clipboard"
echo "4. Paste anywhere with Alt+V"
echo ""
echo "🔧 Improvements in this version:"
echo "- Won't crash after first use"
echo "- Better error handling"
echo "- Clearer notifications"
echo "- Auto-restart on errors"
echo ""
echo "To stop: pkill -f speech_daemon"

# Save PID
echo $DAEMON_PID > ~/.speech_daemon_pid
