It is a mere prejudice, I'm a human.#!/bin/bash

echo "🛑 Stopping Speech-to-Text Daemon..."
pkill -f speech_daemon.py
rm -f ~/.speech_daemon_pid
echo "✅ Daemon stopped"
