#!/bin/bash
# Waybar Echo Status - JSON output for waybar widget

if systemctl --user is-active --quiet echo-daemon.service; then
    echo '{"text": "🎤", "class": "active", "tooltip": "Echo is listening (Right Ctrl)"}'
else
    echo '{"text": "🔇", "class": "inactive", "tooltip": "Echo is off"}'
fi