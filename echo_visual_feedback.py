#!/usr/bin/env python3
"""
Echo Visual Feedback System
Glassmorphism-style overlay for enhanced recording feedback
"""

import tkinter as tk
from tkinter import ttk
import threading
import time
import subprocess
import os
from pathlib import Path

class GlassOverlay:
    def __init__(self):
        self.root = None
        self.is_visible = False
        self.animation_thread = None
        self.recording = False
        
    def create_overlay(self):
        """Create the glassmorphism overlay window"""
        if self.root:
            return
            
        self.root = tk.Toplevel()
        self.root.title("Echo Recording")
        
        # Make it a floating overlay
        self.root.overrideredirect(True)  # No window decorations
        self.root.attributes('-topmost', True)  # Always on top
        self.root.attributes('-alpha', 0.0)  # Start transparent
        
        # Position in top-right corner
        width, height = 320, 120
        screen_width = self.root.winfo_screenwidth()
        x = screen_width - width - 20
        y = 20
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        
        # Glassmorphism styling
        self.setup_glassmorphism_style()
        
        # Main frame with blur effect simulation
        self.main_frame = tk.Frame(self.root, bg='#1a1a1a')
        self.main_frame.pack(fill='both', expand=True, padx=2, pady=2)
        
        # Inner frame for content
        self.content_frame = tk.Frame(self.main_frame, bg='#2a2a2a')
        self.content_frame.pack(fill='both', expand=True, padx=8, pady=8)
        
        # Status icon and text
        self.status_frame = tk.Frame(self.content_frame, bg='#2a2a2a')
        self.status_frame.pack(expand=True, fill='both')
        
        self.status_icon = tk.Label(self.status_frame, text="🎤", font=('Arial', 24), 
                                   bg='#2a2a2a', fg='#00ff88')
        self.status_icon.pack(pady=(10, 5))
        
        self.status_text = tk.Label(self.status_frame, text="Ready", font=('Arial', 12, 'bold'),
                                   bg='#2a2a2a', fg='#ffffff')
        self.status_text.pack()
        
        self.detail_text = tk.Label(self.status_frame, text="Press RIGHT CTRL", font=('Arial', 9),
                                   bg='#2a2a2a', fg='#888888')
        self.detail_text.pack(pady=(2, 10))
        
        # Progress bar for recording
        self.progress = ttk.Progressbar(self.content_frame, mode='indeterminate', length=200)
        
        # Bind window events
        self.root.bind('<Button-1>', self.on_click)
        
    def setup_glassmorphism_style(self):
        """Setup glassmorphism visual effects"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure progressbar style
        style.configure("Glass.Horizontal.TProgressbar",
                       background='#00ff88',
                       troughcolor='#3a3a3a',
                       borderwidth=0,
                       lightcolor='#00ff88',
                       darkcolor='#00ff88')
        
    def show_recording(self):
        """Show recording state with animation"""
        if not self.root:
            self.create_overlay()
            
        self.recording = True
        self.status_icon.config(text="🔴", fg='#ff4444')
        self.status_text.config(text="Recording...", fg='#ff4444')
        self.detail_text.config(text="Speak now")
        
        # Show progress bar
        self.progress.pack(pady=(5, 10), padx=20)
        self.progress.configure(style="Glass.Horizontal.TProgressbar")
        self.progress.start(10)  # Animated progress
        
        self.fade_in()
        
    def show_processing(self):
        """Show processing state"""
        if not self.root:
            return
            
        self.recording = False
        self.progress.stop()
        
        self.status_icon.config(text="🧠", fg='#4488ff')
        self.status_text.config(text="Processing...", fg='#4488ff')
        self.detail_text.config(text="Transcribing speech")
        
    def show_success(self, text):
        """Show success state with transcribed text"""
        if not self.root:
            return
            
        self.status_icon.config(text="✅", fg='#00ff88')
        self.status_text.config(text="Complete!", fg='#00ff88')
        self.detail_text.config(text=f"'{text[:30]}{'...' if len(text) > 30 else ''}'")
        
        # Auto-hide after 2 seconds
        self.root.after(2000, self.hide)
        
    def show_error(self, error_msg):
        """Show error state"""
        if not self.root:
            return
            
        self.status_icon.config(text="❌", fg='#ff4444')
        self.status_text.config(text="Error", fg='#ff4444')
        self.detail_text.config(text=error_msg[:40])
        
        # Auto-hide after 3 seconds
        self.root.after(3000, self.hide)
        
    def hide(self):
        """Hide the overlay with fade out"""
        if not self.root or not self.is_visible:
            return
            
        self.progress.stop()
        self.progress.pack_forget()
        self.fade_out()
        
    def fade_in(self):
        """Smooth fade in animation"""
        if not self.root:
            return
            
        self.is_visible = True
        self.root.deiconify()
        
        # Animate alpha from 0 to 0.95
        def animate():
            for alpha in range(0, 96, 8):
                if not self.is_visible or not self.root:
                    break
                try:
                    self.root.attributes('-alpha', alpha / 100.0)
                    time.sleep(0.02)
                except:
                    break
                    
        self.animation_thread = threading.Thread(target=animate, daemon=True)
        self.animation_thread.start()
        
    def fade_out(self):
        """Smooth fade out animation"""
        if not self.root or not self.is_visible:
            return
            
        def animate():
            current_alpha = self.root.attributes('-alpha')
            steps = int(current_alpha * 100 / 8)
            
            for i in range(steps):
                if not self.root:
                    break
                try:
                    alpha = current_alpha - (current_alpha * (i + 1) / steps)
                    self.root.attributes('-alpha', alpha)
                    time.sleep(0.02)
                except:
                    break
                    
            # Hide the window
            try:
                if self.root:
                    self.root.withdraw()
                    self.is_visible = False
            except:
                pass
                
        self.animation_thread = threading.Thread(target=animate, daemon=True)
        self.animation_thread.start()
        
    def on_click(self, event):
        """Handle click to dismiss"""
        self.hide()
        
    def destroy(self):
        """Clean up the overlay"""
        if self.root:
            try:
                self.root.destroy()
            except:
                pass
            self.root = None
            self.is_visible = False

# Global overlay instance
overlay = None

def show_recording():
    """Show recording overlay"""
    global overlay
    if not overlay:
        overlay = GlassOverlay()
    overlay.show_recording()

def show_processing():
    """Show processing overlay"""
    global overlay
    if overlay:
        overlay.show_processing()

def show_success(text):
    """Show success overlay"""
    global overlay
    if overlay:
        overlay.show_success(text)

def show_error(error_msg):
    """Show error overlay"""
    global overlay
    if overlay:
        overlay.show_error(error_msg)

def hide_overlay():
    """Hide the overlay"""
    global overlay
    if overlay:
        overlay.hide()

def cleanup():
    """Clean up resources"""
    global overlay
    if overlay:
        overlay.destroy()
        overlay = None

if __name__ == "__main__":
    # Test the overlay
    import time
    
    root = tk.Tk()
    root.withdraw()  # Hide main window
    
    try:
        print("Testing visual feedback...")
        
        # Test recording
        show_recording()
        time.sleep(2)
        
        # Test processing
        show_processing()
        time.sleep(1.5)
        
        # Test success
        show_success("Hello world, this is a test transcription")
        time.sleep(3)
        
        # Test error
        show_error("Microphone not found")
        time.sleep(3)
        
    except KeyboardInterrupt:
        pass
    finally:
        cleanup()