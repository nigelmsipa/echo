#!/bin/bash

# Fast Speech-to-Text with whisper.cpp (FIXED VERSION)
WHISPER_DIR="$HOME/apps/speech-to-text/whisper.cpp"
# Use the new whisper-cli binary instead of deprecated main
WHISPER_BIN="$WHISPER_DIR/build/bin/whisper-cli"
# Fallback to main if whisper-cli doesn't exist
if [ ! -f "$WHISPER_BIN" ]; then
    WHISPER_BIN="$WHISPER_DIR/build/bin/main"
fi
MODEL="$WHISPER_DIR/models/ggml-base.en.bin"
TEMP_AUDIO="/tmp/speech_recording.wav"

# Default recording duration
DURATION=${1:-5}

echo "🎤 Recording for $DURATION seconds... Speak now!"

# Record audio with your working HyperX SoloCast
timeout $DURATION parecord --format=s16le --rate=16000 --channels=1 "$TEMP_AUDIO" 2>/dev/null

if [ ! -f "$TEMP_AUDIO" ] || [ ! -s "$TEMP_AUDIO" ]; then
    echo "❌ Recording failed or empty"
    notify-send "Speech-to-Text" "Recording failed" -t 3000 2>/dev/null || true
    exit 1
fi

echo "🧠 Transcribing..."

# Use whisper-cli with proper output handling
if [ -f "$WHISPER_DIR/build/bin/whisper-cli" ]; then
    # New binary
    TRANSCRIPTION=$("$WHISPER_DIR/build/bin/whisper-cli" \
        -m "$MODEL" \
        -f "$TEMP_AUDIO" \
        -t 12 \
        --output-txt \
        --no-timestamps \
        --no-prints 2>/dev/null | grep -v "^$" | tail -1)
else
    # Old binary - filter out warnings
    TRANSCRIPTION=$("$WHISPER_BIN" \
        --model "$MODEL" \
        --file "$TEMP_AUDIO" \
        --threads 12 \
        --no-timestamps \
        --output-txt 2>/dev/null | grep -v "WARNING" | grep -v "deprecated" | grep -v "whisper-cli" | grep -v "github.com" | grep -v "^$" | tail -1)
fi

# Clean up audio file
rm -f "$TEMP_AUDIO"

# Clean the transcription text
TRANSCRIPTION=$(echo "$TRANSCRIPTION" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')

# Check if we got actual speech (not warnings or empty)
if [ -z "$TRANSCRIPTION" ] || echo "$TRANSCRIPTION" | grep -q "github.com\|WARNING\|deprecated\|whisper-cli"; then
    echo "❌ No speech detected (or got warning messages)"
    notify-send "Speech-to-Text" "No speech detected - try speaking louder" -t 3000 2>/dev/null || true
    exit 1
fi

echo "📝 Transcribed: $TRANSCRIPTION"

# Copy to clipboard (Wayland)
echo "$TRANSCRIPTION" | wl-copy

# Show notification  
notify-send "Speech-to-Text" "📋 Copied: $TRANSCRIPTION" -t 5000 2>/dev/null || true

# Print result for scripts
echo "$TRANSCRIPTION"
