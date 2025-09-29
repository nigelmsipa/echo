#!/usr/bin/env python3
"""
Waybar Echo Widget
Shows recording status with waveform animation in waybar
"""

import json
import time
import os
from pathlib import Path

def get_echo_status():
    """Read echo status from cache file"""
    status_file = Path.home() / ".cache" / "echo_status.json"
    
    try:
        if status_file.exists():
            with open(status_file, 'r') as f:
                data = json.load(f)
            
            # Check if status is recent (within last 5 seconds)
            current_time = int(time.time())
            if current_time - data.get('timestamp', 0) > 5:
                return None
            
            return data
    except:
        pass
    
    return None

def generate_waveform(intensity=1.0):
    """Generate ASCII waveform based on intensity"""
    waveforms = {
        0: "",
        1: "▁",
        2: "▁▂", 
        3: "▁▂▃",
        4: "▁▂▃▄",
        5: "▂▃▄▅",
        6: "▃▄▅▆",
        7: "▄▅▆▇",
        8: "▅▆▇█"
    }
    
    # Cycle through different intensities for animation
    cycle = int(time.time() * 3) % 8
    return waveforms.get(cycle, "")

def main():
    """Main waybar widget output"""
    status = get_echo_status()
    
    if not status:
        # No active echo status - show nothing or minimal indicator
        output = {
            "text": "",
            "class": "idle",
            "tooltip": "Echo ready (RIGHT CTRL)"
        }
    else:
        status_type = status.get('status', 'idle')
        
        if status_type == "recording":
            # Show animated waveform during recording
            waveform = generate_waveform()
            output = {
                "text": f"🎤{waveform}",
                "class": "recording",
                "tooltip": "Recording speech..."
            }
        elif status_type == "processing":
            # Show processing indicator
            dots = "..." if int(time.time()) % 2 else "••"
            output = {
                "text": f"🧠{dots}",
                "class": "processing", 
                "tooltip": "Transcribing speech..."
            }
        elif status_type == "success":
            output = {
                "text": "✅",
                "class": "success",
                "tooltip": status.get('tooltip', 'Transcription complete')
            }
        elif status_type == "error":
            output = {
                "text": "❌",
                "class": "error",
                "tooltip": status.get('tooltip', 'Echo error')
            }
        else:
            output = {
                "text": "",
                "class": "idle",
                "tooltip": "Echo ready"
            }
    
    print(json.dumps(output))

if __name__ == "__main__":
    main()