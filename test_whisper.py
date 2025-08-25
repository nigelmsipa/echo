#!/usr/bin/env python3
"""
Test if whisper model loads correctly
"""
print("Testing Whisper model loading...")

try:
    from faster_whisper import WhisperModel
    print("✅ faster_whisper imported successfully")
    
    print("Loading base model...")
    model = WhisperModel("base", device="cpu", compute_type="int8")
    print("✅ Model loaded successfully")
    
    # Test with the included audio file
    import os
    test_file = "assets/jfk.flac"
    if os.path.exists(test_file):
        print(f"Testing transcription with {test_file}...")
        segments, info = model.transcribe(test_file, beam_size=5)
        
        text = ""
        for segment in segments:
            text += segment.text
            
        print(f"✅ Transcription: {text.strip()}")
    else:
        print("❌ Test file not found")
        
except Exception as e:
    print(f"❌ Error: {e}")
    
print("Test complete!")