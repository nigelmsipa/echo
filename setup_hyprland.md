# Echo Setup for Hyprland

## The Proper Solution

Based on research, here are two approaches:

### 1. GUI Testing (Available Now)
```bash
source venv/bin/activate
python echo_gui.py
```
- Click and hold the record button
- Speak your text
- Release to transcribe and see results
- Use "Type Text" button to insert into focused window

### 2. Hyprland Integration (Recommended)

Add these keybindings to your Hyprland config (`~/.config/hypr/hyprland.conf`):

```bash
# Echo speech-to-text bindings  
bind = , RIGHTCTRL, exec, cd /home/nigel/echo && source venv/bin/activate && python echo_hyprland.py toggle
```

Then reload Hyprland config:
```bash
hyprctl reload
```

### Usage:
- **F12**: Toggle recording (press once to start, again to stop and transcribe)
- **Super+Shift+S**: Start recording
- **Super+Shift+E**: Stop recording and transcribe

### 3. Better Solution: whisper-overlay

Install the existing solution that's proven to work:
```bash
# This is a Rust application that does exactly what we want
cargo install whisper-overlay
```

It provides a real-time overlay with hotkey support specifically designed for Hyprland.

## Why This Approach Works

1. **Uses Hyprland's native keybinding system** instead of fighting evdev
2. **Works with Wayland security model** - compositor handles the hotkeys
3. **No permission issues** - runs as regular user
4. **Reliable and simple** - leverages existing infrastructure

The GUI version lets you test the transcription immediately, and the Hyprland integration gives you the hotkey functionality you want.