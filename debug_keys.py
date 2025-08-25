#!/usr/bin/env python3
"""
Enhanced key detection to debug RIGHT CTRL issues
This will show ALL key events from keyboard devices
"""
from evdev import InputDevice, categorize, ecodes
import threading
import time
import sys

class KeyDebugger:
    def __init__(self):
        self.monitoring = True
        
    def monitor_device(self, device_path):
        """Monitor a single device and show ALL key events"""
        try:
            device = InputDevice(device_path)
            
            # Only monitor keyboard devices
            if ecodes.EV_KEY not in device.capabilities():
                return
                
            print(f"🎹 Monitoring keyboard: {device_path} - {device.name}")
            
            for event in device.read_loop():
                if not self.monitoring:
                    break
                    
                if event.type == ecodes.EV_KEY:
                    key_event = categorize(event)
                    
                    # Show ALL key events
                    state_name = {0: "RELEASED", 1: "PRESSED", 2: "REPEAT"}
                    state = state_name.get(key_event.keystate, str(key_event.keystate))
                    
                    print(f"   {device_path}: {key_event.keycode} -> {state}")
                    
                    # Highlight control keys
                    if 'CTRL' in key_event.keycode:
                        print(f"   🚨 CONTROL KEY DETECTED: {key_event.keycode} -> {state}")
                        
        except Exception as e:
            print(f"   ❌ Error monitoring {device_path}: {e}")
    
    def debug_all_keyboards(self):
        """Monitor all keyboard devices for key events"""
        print("🔍 Debugging keyboard input...")
        print("👆 Press ANY keys (especially RIGHT CTRL) to see events")
        print("⏰ Monitoring for 15 seconds...")
        print("🛑 Press Ctrl+C to stop early")
        print("-" * 60)
        
        # Get all event devices
        import glob
        device_paths = glob.glob('/dev/input/event*')
        device_paths.sort()
        
        # Start monitoring threads for keyboard devices only
        threads = []
        keyboard_count = 0
        
        for device_path in device_paths:
            try:
                device = InputDevice(device_path)
                if ecodes.EV_KEY in device.capabilities():
                    keyboard_count += 1
                    thread = threading.Thread(target=self.monitor_device, args=(device_path,))
                    thread.daemon = True
                    thread.start()
                    threads.append(thread)
            except:
                continue
        
        print(f"📊 Monitoring {keyboard_count} keyboard devices...")
        print()
        
        try:
            # Wait for 15 seconds
            time.sleep(15)
        except KeyboardInterrupt:
            print("\n👋 Monitoring stopped by user")
        
        self.monitoring = False
        print("\n" + "=" * 60)
        print("🏁 Monitoring complete!")

def main():
    debugger = KeyDebugger()
    debugger.debug_all_keyboards()

if __name__ == "__main__":
    main()
