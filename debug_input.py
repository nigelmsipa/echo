#!/usr/bin/env python3
"""
Debug input devices to find the right keyboard
"""
from evdev import InputDevice, list_devices, categorize, ecodes

print("Available input devices:")
for device_path in list_devices():
    try:
        device = InputDevice(device_path)
        print(f"\n{device_path}: {device.name}")
        
        # Check capabilities
        caps = device.capabilities()
        if ecodes.EV_KEY in caps:
            keys = caps[ecodes.EV_KEY]
            has_letters = any(k in keys for k in [ecodes.KEY_A, ecodes.KEY_SPACE, ecodes.KEY_ENTER])
            has_alt = ecodes.KEY_RIGHTALT in keys
            print(f"  Has keyboard keys: {has_letters}")
            print(f"  Has RIGHT ALT: {has_alt}")
            
            if has_letters and has_alt:
                print("  🎯 This looks like your main keyboard!")
                
    except Exception as e:
        print(f"  Error: {e}")

print("\nTesting keyboard input (press some keys, Ctrl+C to exit):")
# Find a good keyboard device
keyboard_path = None
for device_path in list_devices():
    try:
        device = InputDevice(device_path)
        caps = device.capabilities()
        if ecodes.EV_KEY in caps:
            keys = caps[ecodes.EV_KEY]
            has_letters = any(k in keys for k in [ecodes.KEY_A, ecodes.KEY_SPACE, ecodes.KEY_ENTER])
            has_alt = ecodes.KEY_RIGHTALT in keys
            if has_letters and has_alt:
                keyboard_path = device_path
                break
    except:
        continue

if keyboard_path:
    print(f"Using {keyboard_path}")
    device = InputDevice(keyboard_path)
    try:
        for event in device.read_loop():
            if event.type == ecodes.EV_KEY:
                key_event = categorize(event)
                if key_event.keystate in [0, 1]:  # Press or release
                    action = "pressed" if key_event.keystate == 1 else "released"
                    print(f"{key_event.keycode} {action}")
    except KeyboardInterrupt:
        print("\nDone!")
else:
    print("No suitable keyboard found!")