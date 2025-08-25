#!/usr/bin/env python3
"""
Test script to verify echo components work
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from echo_daemon import EchoDaemon

def test_transcription():
    """Test just the transcription part"""
    print("Testing transcription with 'base' model...")
    
    daemon = EchoDaemon(model_size="base")
    
    print("Say something and press Enter when done...")
    input()
    
    print("Recording for 3 seconds...")
    daemon.start_recording()
    
    import time
    time.sleep(3)
    
    daemon.stop_recording()
    print("Test complete!")

if __name__ == "__main__":
    test_transcription()