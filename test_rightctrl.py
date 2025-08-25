#!/usr/bin/env python3
"""
Simple test to see if we can detect RIGHT CTRL on MX Keys Mini
"""
from evdev import InputDevice, categorize, ecodes
import time

def test_right_ctrl():
    """Test RIGHT CTRL detection on event2"""
    try:
        device = InputDevice("/dev/input/event2")
        print(f"🎯 Testing RIGHT CTRL on: {device.name}")
        print("Press and release RIGHT CTRL key...")
        print("Press Ctrl+C to exit")
        
        for event in device.read_loop():
            if event.type == ecodes.EV_KEY:
                key_event = categorize(event)
                
                # Print ALL key events to see what we get
                print(f"Key: {key_event.keycode} | State: {key_event.keystate}")
                
                # Check for RIGHT CTRL specifically
                if key_event.keycode == 'KEY_RIGHTCTRL':
                    if key_event.keystate == 1:
                        print("✅ RIGHT CTRL PRESSED!")
                    elif key_event.keystate == 0:
                        print("✅ RIGHT CTRL RELEASED!")
                        
    except KeyboardInterrupt:
        print("\n👋 Test stopped")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    test_right_ctrl()
