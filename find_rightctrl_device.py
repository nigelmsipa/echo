#!/usr/bin/env python3
"""
Find which input device receives RIGHT CTRL events
This will scan all available input devices to find the right one
"""
from evdev import InputDevice, categorize, ecodes
import threading
import time
import sys

class DeviceScanner:
    def __init__(self):
        self.found_devices = []
        self.scanning = True
        
    def scan_device(self, device_path):
        """Scan a single device for RIGHT CTRL events"""
        try:
            device = InputDevice(device_path)
            print(f"📱 Scanning {device_path}: {device.name}")
            
            # Check if device supports keyboard events
            if ecodes.EV_KEY not in device.capabilities():
                print(f"   ⏭️  Skipping - no keyboard events")
                return
                
            # Check if device supports RIGHT CTRL key
            if ecodes.KEY_RIGHTCTRL not in device.capabilities().get(ecodes.EV_KEY, []):
                print(f"   ⏭️  Skipping - no RIGHT CTRL capability")
                return
                
            print(f"   🎯 Monitoring for RIGHT CTRL events...")
            
            # Monitor for events
            for event in device.read_loop():
                if not self.scanning:
                    break
                    
                if event.type == ecodes.EV_KEY:
                    key_event = categorize(event)
                    
                    if key_event.keycode == 'KEY_RIGHTCTRL':
                        if key_event.keystate == 1:
                            print(f"   ✅ RIGHT CTRL PRESSED on {device_path}!")
                            self.found_devices.append((device_path, device.name))
                        elif key_event.keystate == 0:
                            print(f"   ✅ RIGHT CTRL RELEASED on {device_path}!")
                            
        except PermissionError:
            print(f"   ❌ Permission denied for {device_path}")
        except Exception as e:
            print(f"   ❌ Error scanning {device_path}: {e}")
    
    def scan_all_devices(self):
        """Scan all available input devices"""
        print("🔍 Scanning all input devices for RIGHT CTRL events...")
        print("👆 Press and release RIGHT CTRL key now!")
        print("⏰ Scanning for 10 seconds...")
        print("-" * 60)
        
        # Get all event devices
        import glob
        device_paths = glob.glob('/dev/input/event*')
        device_paths.sort()
        
        # Start scanning threads
        threads = []
        for device_path in device_paths:
            thread = threading.Thread(target=self.scan_device, args=(device_path,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for 10 seconds
        time.sleep(10)
        self.scanning = False
        
        print("\n" + "=" * 60)
        if self.found_devices:
            print("🎉 Found RIGHT CTRL on these devices:")
            for device_path, device_name in self.found_devices:
                print(f"   ✅ {device_path}: {device_name}")
        else:
            print("❌ No RIGHT CTRL events detected!")
            print("💡 Try:")
            print("   1. Make sure you pressed RIGHT CTRL (not left)")
            print("   2. Check if you're in the 'input' group: groups $USER")
            print("   3. Add yourself to input group: sudo usermod -a -G input $USER")
        
        return self.found_devices

def main():
    scanner = DeviceScanner()
    try:
        devices = scanner.scan_all_devices()
        
        if devices:
            print(f"\n🔧 Update your daemon to use: {devices[0][0]}")
        
    except KeyboardInterrupt:
        print("\n👋 Scan interrupted")
        scanner.scanning = False

if __name__ == "__main__":
    main()
