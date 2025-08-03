#!/bin/bash

# Manual Echo activation (fallback method)
echo "🎤 Manual Echo Activation"

# Check if daemon is running
if pgrep -f speech_daemon > /dev/null; then
    echo "✅ Daemon running - triggering via file"
    echo "trigger" > /tmp/echo_trigger
    echo "🎙️  Recording should start now..."
else
    echo "❌ Daemon not running - using direct script"
    ~/apps/speech-to-text/quick_transcribe.sh
fi
