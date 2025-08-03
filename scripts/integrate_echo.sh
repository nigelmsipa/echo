#!/bin/bash

echo "🔧 Echo System Integration v0.2"
echo "==============================="

# Create desktop entry
mkdir -p ~/.local/share/applications
cat > ~/.local/share/applications/echo-speech.desktop << 'DESKTOP_EOF'
[Desktop Entry]
Name=Echo Speech-to-Text
Comment=Fast local speech transcription
Exec=/home/nigel/echo/scripts/echo_activate.sh
Icon=audio-input-microphone
Terminal=true
Type=Application
Categories=AudioVideo;Audio;Utility;
Keywords=speech;voice;transcription;dictation;AI;
StartupNotify=true
DESKTOP_EOF

# Add to system PATH
if ! grep -q "echo/scripts" ~/.bashrc; then
    echo 'export PATH="$HOME/echo/scripts:$PATH"' >> ~/.bashrc
    echo "✅ Added echo scripts to PATH"
fi

# Create convenient aliases
cat >> ~/.bashrc << 'ALIAS_EOF'

# Echo Speech-to-Text aliases
alias echo-start='~/echo/daemon/start_daemon.sh'
alias echo-stop='pkill -f speech_daemon'
alias echo-speak='~/echo/scripts/echo_activate.sh'
alias echo-direct='~/apps/speech-to-text/quick_transcribe.sh'
ALIAS_EOF

# Hyprland integration
if [ -f ~/.config/hypr/hyprland.conf ]; then
    # Remove old entries
    sed -i '/speech.*text/d; /Speech.*Text/d' ~/.config/hypr/hyprland.conf
    
    # Add new bindings
    cat >> ~/.config/hypr/hyprland.conf << 'HYPR_EOF'

# Echo Speech-to-Text v0.2
exec-once = ~/echo/daemon/start_daemon.sh
bind = SUPER, M, exec, ~/echo/scripts/echo_activate.sh
bind = SUPER SHIFT, M, exec, ~/apps/speech-to-text/quick_transcribe.sh
bind = SUPER, F12, exec, echo trigger > /tmp/echo_trigger
HYPR_EOF

    hyprctl reload
    echo "✅ Updated Hyprland integration"
fi

echo
echo "🎉 Integration complete!"
echo
echo "📱 Usage options:"
echo "   Command: echo-speak"
echo "   Menu: Search 'Echo Speech' in app launcher"
echo "   Hotkey: Super+M (Hyprland)"
echo "   Global: F12 (if daemon works)"
echo "   Direct: echo-direct"
echo
echo "🔄 Restart terminal to use new aliases"

