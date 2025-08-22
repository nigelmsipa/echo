#!/usr/bin/env python3
"""
Echo Launcher - Simple GUI to start/stop the Echo daemon
Part of NigelOS ecosystem
"""

import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import threading
import time
import sys
import os
from pathlib import Path

class EchoLauncher:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Echo Speech-to-Text")
        self.root.geometry("450x300")
        self.root.resizable(False, False)
        
        # State
        self.daemon_process = None
        self.daemon_running = False
        
        self.setup_ui()
        self.check_daemon_status()
    
    def setup_ui(self):
        """Create the GUI interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="🎤 Echo Speech-to-Text", 
                               font=("Arial", 18, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 10))
        
        # Subtitle
        subtitle_label = ttk.Label(main_frame, text="NigelOS Background Daemon", 
                                  font=("Arial", 10))
        subtitle_label.grid(row=1, column=0, columnspan=2, pady=(0, 20))
        
        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="Daemon Status", padding="10")
        status_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 20))
        
        self.status_var = tk.StringVar(value="Checking...")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var,
                                     font=("Arial", 12))
        self.status_label.grid(row=0, column=0, sticky=tk.W)
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=(0, 20))
        
        self.start_button = ttk.Button(button_frame, text="🚀 Start Daemon", 
                                      command=self.start_daemon, width=15)
        self.start_button.grid(row=0, column=0, padx=(0, 10))
        
        self.stop_button = ttk.Button(button_frame, text="⏹️ Stop Daemon", 
                                     command=self.stop_daemon, width=15)
        self.stop_button.grid(row=0, column=1, padx=(10, 0))
        
        # Instructions
        instructions_frame = ttk.LabelFrame(main_frame, text="How to Use", padding="10")
        instructions_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        instructions = [
            "1. Click 'Start Daemon' to begin listening",
            "2. Press and hold RIGHT CTRL to record",
            "3. Speak clearly while holding the key",
            "4. Release RIGHT CTRL to transcribe and auto-type",
            "5. Text appears at your cursor position"
        ]
        
        for i, instruction in enumerate(instructions):
            ttk.Label(instructions_frame, text=instruction, font=("Arial", 9)).grid(
                row=i, column=0, sticky=tk.W, pady=1)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
    
    def check_daemon_status(self):
        """Check if daemon is already running"""
        try:
            result = subprocess.run(['pgrep', '-f', 'echo_daemon_final.py'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                self.daemon_running = True
                self.status_var.set("🟢 Daemon Running - Listening for RIGHT CTRL")
                self.start_button.config(state="disabled")
                self.stop_button.config(state="normal")
            else:
                self.daemon_running = False
                self.status_var.set("🔴 Daemon Stopped")
                self.start_button.config(state="normal")
                self.stop_button.config(state="disabled")
        except Exception as e:
            self.status_var.set(f"❌ Error checking status: {e}")
    
    def start_daemon(self):
        """Start the Echo daemon"""
        try:
            daemon_path = Path(__file__).parent / "echo_daemon_final.py"
            if not daemon_path.exists():
                messagebox.showerror("Error", f"Daemon not found at {daemon_path}")
                return
            
            self.status_var.set("🔄 Starting daemon...")
            self.start_button.config(state="disabled")
            
            # Start daemon in background
            def start_daemon_thread():
                try:
                    self.daemon_process = subprocess.Popen([
                        sys.executable, str(daemon_path)
                    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    
                    # Wait a moment to see if it starts successfully
                    time.sleep(2)
                    
                    if self.daemon_process.poll() is None:
                        # Daemon is running
                        self.root.after(0, self.on_daemon_started)
                    else:
                        # Daemon failed to start
                        stdout, stderr = self.daemon_process.communicate()
                        error_msg = stderr.decode() if stderr else "Unknown error"
                        self.root.after(0, lambda: self.on_daemon_error(error_msg))
                        
                except Exception as e:
                    self.root.after(0, lambda: self.on_daemon_error(str(e)))
            
            threading.Thread(target=start_daemon_thread, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start daemon: {e}")
            self.start_button.config(state="normal")
    
    def on_daemon_started(self):
        """Called when daemon starts successfully"""
        self.daemon_running = True
        self.status_var.set("🟢 Daemon Running - Listening for RIGHT CTRL")
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        
        # Show success notification
        messagebox.showinfo("Echo Started", 
                           "Echo daemon is now running!\n\n" +
                           "Press and hold RIGHT CTRL to record speech.")
    
    def on_daemon_error(self, error_msg):
        """Called when daemon fails to start"""
        self.status_var.set("❌ Failed to start daemon")
        self.start_button.config(state="normal")
        messagebox.showerror("Daemon Error", f"Failed to start daemon:\n\n{error_msg}")
    
    def stop_daemon(self):
        """Stop the Echo daemon"""
        try:
            # Kill any running daemon processes
            subprocess.run(['pkill', '-f', 'echo_daemon_final.py'], 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            if self.daemon_process:
                self.daemon_process.terminate()
                self.daemon_process = None
            
            self.daemon_running = False
            self.status_var.set("🔴 Daemon Stopped")
            self.start_button.config(state="normal")
            self.stop_button.config(state="disabled")
            
            messagebox.showinfo("Echo Stopped", "Echo daemon has been stopped.")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to stop daemon: {e}")
    
    def on_closing(self):
        """Handle window closing"""
        if self.daemon_running:
            result = messagebox.askyesno("Echo Running", 
                                       "Echo daemon is still running.\n\n" +
                                       "Do you want to stop it before closing?")
            if result:
                self.stop_daemon()
        
        self.root.destroy()
    
    def run(self):
        """Start the GUI"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

def main():
    """Main entry point"""
    launcher = EchoLauncher()
    launcher.run()

if __name__ == "__main__":
    main()
