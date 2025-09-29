#!/usr/bin/env python3
"""
Echo Adaptive Visual Feedback
Automatically chooses overlay vs waybar based on fullscreen state
"""

import subprocess
import json
import threading
import time
import os
from pathlib import Path

class AdaptiveFeedback:
    def __init__(self):
        self.current_mode = "windowed"  # "windowed" or "fullscreen"
        self.overlay = None
        self.waybar_widget = None
        self.monitoring = False
        
    def is_fullscreen(self):
        """Detect if current window is fullscreen using Hyprland"""
        try:
            # Get active window info from Hyprland
            result = subprocess.run(['hyprctl', 'activewindow', '-j'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                window_info = json.loads(result.stdout)
                return window_info.get('fullscreen', False)
        except:
            pass
        return False
    
    def monitor_fullscreen_state(self):
        """Monitor fullscreen state changes"""
        self.monitoring = True
        while self.monitoring:
            try:
                is_fs = self.is_fullscreen()
                new_mode = "fullscreen" if is_fs else "windowed"
                
                if new_mode != self.current_mode:
                    self.current_mode = new_mode
                    print(f"🔄 Mode changed to: {self.current_mode}")
                    
                time.sleep(0.5)  # Check twice per second
            except:
                time.sleep(1)
    
    def start_monitoring(self):
        """Start monitoring fullscreen state in background"""
        monitor_thread = threading.Thread(target=self.monitor_fullscreen_state, daemon=True)
        monitor_thread.start()
    
    def show_recording(self):
        """Show recording feedback based on current mode"""
        if self.current_mode == "fullscreen":
            self._show_overlay_recording()
        else:
            self._show_waybar_recording()
    
    def show_processing(self):
        """Show processing feedback"""
        if self.current_mode == "fullscreen":
            self._show_overlay_processing()
        else:
            self._update_waybar_status("processing")
    
    def show_success(self, text):
        """Show success feedback"""
        if self.current_mode == "fullscreen":
            self._show_overlay_success(text)
        else:
            self._update_waybar_status("success", text)
    
    def show_error(self, error_msg):
        """Show error feedback"""
        if self.current_mode == "fullscreen":
            self._show_overlay_error(error_msg)
        else:
            self._update_waybar_status("error", error_msg)
    
    def hide(self):
        """Hide all feedback"""
        self._hide_overlay()
        self._update_waybar_status("idle")
    
    def _show_overlay_recording(self):
        """Show glassmorphism overlay for fullscreen"""
        # Import here to avoid tkinter issues
        try:
            from echo_visual_feedback import show_recording
            show_recording()
        except ImportError:
            # Fallback to notification
            subprocess.run(['notify-send', '-i', 'audio-input-microphone', 
                          'Echo Recording', '🎤 Recording speech...'], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    def _show_overlay_processing(self):
        """Show processing overlay"""
        try:
            from echo_visual_feedback import show_processing
            show_processing()
        except ImportError:
            subprocess.run(['notify-send', '-i', 'system-run', 
                          'Echo Processing', '🧠 Transcribing speech...'], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    def _show_overlay_success(self, text):
        """Show success overlay"""
        try:
            from echo_visual_feedback import show_success
            show_success(text)
        except ImportError:
            subprocess.run(['notify-send', '-i', 'dialog-information', 
                          'Echo Complete', f'✅ {text[:50]}...'], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    def _show_overlay_error(self, error_msg):
        """Show error overlay"""
        try:
            from echo_visual_feedback import show_error
            show_error(error_msg)
        except ImportError:
            subprocess.run(['notify-send', '-i', 'dialog-error', 
                          'Echo Error', f'❌ {error_msg}'], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    def _hide_overlay(self):
        """Hide overlay"""
        try:
            from echo_visual_feedback import hide_overlay
            hide_overlay()
        except ImportError:
            pass
    
    def _show_waybar_recording(self):
        """Show recording state in waybar"""
        self._update_waybar_status("recording")
    
    def _update_waybar_status(self, status, text=""):
        """Update waybar echo widget status"""
        # Create status file that waybar can read
        status_file = Path.home() / ".cache" / "echo_status.json"
        status_file.parent.mkdir(exist_ok=True)
        
        status_data = {
            "status": status,
            "text": text,
            "timestamp": int(time.time())
        }
        
        # Icons and classes for different states
        status_config = {
            "idle": {"text": "", "class": "idle", "tooltip": "Echo ready"},
            "recording": {"text": "🔴", "class": "recording", "tooltip": "Recording speech..."},
            "processing": {"text": "🧠", "class": "processing", "tooltip": "Transcribing..."},
            "success": {"text": "✅", "class": "success", "tooltip": f"Complete: {text[:30]}..."},
            "error": {"text": "❌", "class": "error", "tooltip": f"Error: {text}"}
        }
        
        config = status_config.get(status, status_config["idle"])
        status_data.update(config)
        
        try:
            with open(status_file, 'w') as f:
                json.dump(status_data, f)
        except:
            pass
        
        # Signal waybar to update (if it supports it)
        try:
            subprocess.run(['pkill', '-SIGUSR1', 'waybar'], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass

# Global instance
adaptive_feedback = None

def get_feedback_system():
    """Get or create the adaptive feedback system"""
    global adaptive_feedback
    if not adaptive_feedback:
        adaptive_feedback = AdaptiveFeedback()
        adaptive_feedback.start_monitoring()
    return adaptive_feedback

# Convenience functions that match the original API
def show_recording():
    get_feedback_system().show_recording()

def show_processing():
    get_feedback_system().show_processing()

def show_success(text):
    get_feedback_system().show_success(text)

def show_error(error_msg):
    get_feedback_system().show_error(error_msg)

def hide_feedback():
    get_feedback_system().hide()

if __name__ == "__main__":
    # Test the adaptive system
    print("Testing adaptive feedback system...")
    
    system = get_feedback_system()
    
    try:
        while True:
            print(f"Current mode: {system.current_mode}")
            
            # Test sequence
            show_recording()
            time.sleep(2)
            
            show_processing()
            time.sleep(1)
            
            show_success("Test transcription successful")
            time.sleep(2)
            
            hide_feedback()
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\nStopping test...")