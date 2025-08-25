#!/usr/bin/env python3
"""
Echo GUI - Simple click-to-test interface for speech-to-text
"""
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import subprocess
import tempfile
import os
import time
from faster_whisper import WhisperModel

class EchoGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Echo - Speech to Text")
        self.root.geometry("500x400")
        
        # State
        self.recording = False
        self.model = None
        self.record_process = None
        self.temp_path = None
        
        self.setup_ui()
        self.load_model()
    
    def setup_ui(self):
        """Create the GUI interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="🎤 Echo Speech-to-Text", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Status
        self.status_var = tk.StringVar(value="Loading model...")
        self.status_label = ttk.Label(main_frame, textvariable=self.status_var)
        self.status_label.grid(row=1, column=0, columnspan=2, pady=(0, 10))
        
        # Record button
        self.record_button = ttk.Button(main_frame, text="🎤 Hold to Record", 
                                       state="disabled")
        self.record_button.grid(row=2, column=0, columnspan=2, pady=10, ipadx=20, ipady=10)
        
        # Bind mouse events for hold-to-record
        self.record_button.bind("<Button-1>", self.start_recording)
        self.record_button.bind("<ButtonRelease-1>", self.stop_recording)
        
        # Result text area
        ttk.Label(main_frame, text="Transcribed Text:").grid(row=3, column=0, sticky=tk.W, pady=(20, 5))
        
        self.text_area = tk.Text(main_frame, height=10, width=60, wrap=tk.WORD)
        self.text_area.grid(row=4, column=0, columnspan=2, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Scrollbar for text area
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.text_area.yview)
        scrollbar.grid(row=4, column=2, sticky=(tk.N, tk.S))
        self.text_area.configure(yscrollcommand=scrollbar.set)
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=20)
        
        # Clear button
        ttk.Button(button_frame, text="Clear", command=self.clear_text).pack(side=tk.LEFT, padx=5)
        
        # Copy button
        ttk.Button(button_frame, text="Copy to Clipboard", command=self.copy_text).pack(side=tk.LEFT, padx=5)
        
        # Insert button
        ttk.Button(button_frame, text="Type Text", command=self.type_text).pack(side=tk.LEFT, padx=5)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(4, weight=1)
    
    def load_model(self):
        """Load Whisper model in background thread"""
        def load():
            try:
                self.status_var.set("Loading Whisper model...")
                self.model = WhisperModel("base", device="cpu", compute_type="int8")
                self.status_var.set("✅ Ready! Hold button to record, release to transcribe")
                self.record_button.config(state="normal")
            except Exception as e:
                self.status_var.set(f"❌ Error loading model: {str(e)}")
                messagebox.showerror("Error", f"Failed to load Whisper model: {str(e)}")
        
        thread = threading.Thread(target=load, daemon=True)
        thread.start()
    
    def start_recording(self, event=None):
        """Start recording audio"""
        if self.recording or not self.model:
            return
        
        self.recording = True
        self.record_button.config(text="🔴 Recording... (release to stop)")
        self.status_var.set("🎤 Recording... speak now!")
        
        # Create temp file
        temp_file = tempfile.NamedTemporaryFile(suffix=".wav", delete=False)
        self.temp_path = temp_file.name
        temp_file.close()
        
        # Start recording with arecord
        try:
            self.record_process = subprocess.Popen([
                'arecord',
                '-f', 'S16_LE',
                '-c', '1',
                '-r', '16000',
                self.temp_path
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            messagebox.showerror("Error", "arecord not found. Install with: sudo pacman -S alsa-utils")
            self.recording = False
            self.record_button.config(text="🎤 Hold to Record")
            return
    
    def stop_recording(self, event=None):
        """Stop recording and transcribe"""
        if not self.recording:
            return
        
        self.recording = False
        self.record_button.config(text="🎤 Hold to Record", state="disabled")
        self.status_var.set("🔄 Transcribing...")
        
        # Stop recording
        if self.record_process:
            self.record_process.terminate()
            self.record_process.wait()
        
        # Transcribe in background thread
        def transcribe():
            try:
                time.sleep(0.1)  # Brief pause
                
                if os.path.exists(self.temp_path) and os.path.getsize(self.temp_path) > 1024:
                    segments, info = self.model.transcribe(self.temp_path, beam_size=5)
                    text = ""
                    for segment in segments:
                        text += segment.text
                    
                    # Update UI in main thread
                    self.root.after(0, self.show_result, text.strip())
                else:
                    self.root.after(0, self.show_result, "")
                
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Transcription failed: {str(e)}"))
            finally:
                # Clean up
                if os.path.exists(self.temp_path):
                    os.unlink(self.temp_path)
                self.root.after(0, self.reset_ui)
        
        thread = threading.Thread(target=transcribe, daemon=True)
        thread.start()
    
    def show_result(self, text):
        """Show transcription result"""
        if text:
            self.text_area.insert(tk.END, f"{text}\n\n")
            self.text_area.see(tk.END)
            self.status_var.set(f"✅ Transcribed: {len(text)} characters")
        else:
            self.status_var.set("❌ No speech detected")
    
    def reset_ui(self):
        """Reset UI after transcription"""
        self.record_button.config(state="normal")
        self.root.after(2000, lambda: self.status_var.set("✅ Ready! Hold button to record, release to transcribe"))
    
    def clear_text(self):
        """Clear the text area"""
        self.text_area.delete(1.0, tk.END)
    
    def copy_text(self):
        """Copy text to clipboard"""
        text = self.text_area.get(1.0, tk.END).strip()
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("Copied", "Text copied to clipboard!")
        else:
            messagebox.showwarning("Nothing to Copy", "No text to copy!")
    
    def type_text(self):
        """Type the text using wtype"""
        text = self.text_area.get(1.0, tk.END).strip()
        if not text:
            messagebox.showwarning("Nothing to Type", "No text to type!")
            return
        
        # Hide window temporarily
        self.root.withdraw()
        
        try:
            # Wait a moment for focus to change
            time.sleep(0.5)
            subprocess.run(['wtype', text], check=True)
            messagebox.showinfo("Success", "Text typed successfully!")
        except subprocess.CalledProcessError:
            messagebox.showerror("Error", "Failed to type text")
        except FileNotFoundError:
            messagebox.showerror("Error", "wtype not found. Install with: sudo pacman -S wtype")
        finally:
            # Show window again
            self.root.deiconify()
    
    def run(self):
        """Run the GUI"""
        self.root.mainloop()

if __name__ == "__main__":
    app = EchoGUI()
    app.run()