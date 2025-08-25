#!/usr/bin/env python3
"""
Debug script to test if hotkey is working
"""
import sys
import datetime
import os

print(f"[{datetime.datetime.now()}] Echo debug script called with args: {sys.argv}")
print(f"Current working directory: {os.getcwd()}")

try:
    os.chdir('/home/nigel/echo')
    print(f"Changed to: {os.getcwd()}")
    
    from echo_hyprland import HyprlandEcho
    print("Successfully imported HyprlandEcho")
    
    if len(sys.argv) > 1:
        action = sys.argv[1]
        print(f"Action: {action}")
        
        echo = HyprlandEcho()
        if action == 'toggle':
            result = echo.toggle_recording()
            print(f"Result: {result}")
    else:
        print("No action specified")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()