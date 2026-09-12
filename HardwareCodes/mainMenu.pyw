import os
import sys
import subprocess
import threading
import time

def ensure_dependencies():
    """Auto-install required packages so the toolkit is 1-click plug-and-play."""
    deps = {
        "pyserial": "serial", 
        "esptool": "esptool",
        "Pillow": "PIL",
        "matplotlib": "matplotlib"
    }
    for pkg, mod in deps.items():
        try:
            __import__(mod)
        except ImportError:
            print(f"Auto-installing missing dependency: {pkg}...")
            # Use pip to install the missing package
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

ensure_dependencies()

try:
    import tkinter as tk
    from tkinter import ttk
    from PIL import Image, ImageTk
except ImportError:
    print("Error: Tkinter is required but not installed.")
    print("Please reinstall Python and make sure 'tcl/tk' is checked.")
    input("Press Enter to exit...")
    sys.exit(1)

import ctypes

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    script_path = os.path.abspath(__file__)
    # Request UAC admin privileges
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script_path}"', None, 1)

class HexWardenApp:
    def __init__(self, root):
        self.root = root
        self.root.title("HexWarden - Hardware Security Toolkit")
        self.root.geometry("850x650")
        self.root.configure(bg="#1e1e2e")  # Dark modern theme
        
        # Set Window Icon using Pillow (to support JPEG)
        logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logo.jpeg")
        if os.path.exists(logo_path):
            try:
                img = Image.open(logo_path)
                self.icon_photo = ImageTk.PhotoImage(img)
                self.root.iconphoto(True, self.icon_photo)
            except Exception as e:
                print(f"Could not load logo: {e}")
        
        # Modern Styling
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Frames and Labels
        self.style.configure('TFrame', background="#1e1e2e")
        self.style.configure('TLabel', background="#1e1e2e", foreground="#cdd6f4", font=('Segoe UI', 11))
        self.style.configure('Header.TLabel', font=('Segoe UI', 22, 'bold'), foreground="#89b4fa")
        
        # Buttons
        self.style.configure('TButton', font=('Segoe UI', 12, 'bold'), padding=12, background="#89b4fa", foreground="#11111b", borderwidth=0)
        self.style.map('TButton', background=[('active', '#b4befe'), ('disabled', '#45475a')], foreground=[('disabled', '#a6adc8')])
        
        # Main container
        self.main_frame = ttk.Frame(self.root, padding=25)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        self.header_lbl = ttk.Label(self.main_frame, text="HexWarden Control Center", style='Header.TLabel')
        self.header_lbl.pack(pady=(0, 25))
        
        # Buttons Layout
        self.btn_frame = ttk.Frame(self.main_frame)
        self.btn_frame.pack(fill=tk.X, pady=(0, 25))
        
        # Button 1
        self.btn_extract = ttk.Button(self.btn_frame, text="Extract Firmware", command=self.run_extraction)
        self.btn_extract.pack(side=tk.LEFT, padx=10, expand=True, fill=tk.X)
        
        # Button 2
        self.btn_side_channel = ttk.Button(self.btn_frame, text="Side Channel Analysis", command=self.run_side_channel)
        self.btn_side_channel.pack(side=tk.LEFT, padx=10, expand=True, fill=tk.X)
        
        # Terminal / Output Panel
        self.console_frame = ttk.Frame(self.main_frame)
        self.console_frame.pack(fill=tk.BOTH, expand=True)
        
        self.console_lbl = ttk.Label(self.console_frame, text="Terminal Output:")
        self.console_lbl.pack(anchor=tk.W, pady=(0, 5))
        
        # Text widget for log
        self.console = tk.Text(self.console_frame, bg="#11111b", fg="#a6e3a1", font=('Consolas', 10), 
                               state=tk.DISABLED, wrap=tk.WORD, relief=tk.FLAT, padx=10, pady=10)
        self.console.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Scrollbar for console
        self.scrollbar = ttk.Scrollbar(self.console_frame, command=self.console.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.console.config(yscrollcommand=self.scrollbar.set)
        
        self.process = None

    def log(self, text):
        """Thread-safe logging to the text widget."""
        def append():
            self.console.config(state=tk.NORMAL)
            self.console.insert(tk.END, text + "\n")
            self.console.see(tk.END)
            self.console.config(state=tk.DISABLED)
        self.root.after(0, append)

    def run_extraction(self):
        if self.process and self.process.poll() is None:
            self.log("\n[!] A process is already running...")
            return
            
        self.console.config(state=tk.NORMAL)
        self.console.delete(1.0, tk.END)
        self.console.config(state=tk.DISABLED)
        
        self.log("[System] Initializing Firmware Extraction module...")
        self.btn_extract.state(['disabled'])
        self.btn_side_channel.state(['disabled'])
        
        # Start a background thread so UI doesn't freeze
        threading.Thread(target=self._run_extraction_thread, daemon=True).start()

    def _run_extraction_thread(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        script_path = os.path.join(script_dir, "FirmwareExtraction", "extractespfirmware.py")
        
        if not os.path.exists(script_path):
            self.log(f"[Error] Could not locate: {script_path}")
            self.root.after(0, lambda: self.btn_extract.state(['!disabled']))
            self.root.after(0, lambda: self.btn_side_channel.state(['!disabled']))
            return

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        env["GUI_MODE"] = "1"

        try:
            self.process = subprocess.Popen(
                [sys.executable, "-u", script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=env,
                creationflags=0x08000000 
            )
            
            for line in self.process.stdout:
                clean_line = line.replace('\r', '').strip('\n')
                if clean_line:
                    self.log(clean_line)
                
                if "Press Enter to exit..." in clean_line:
                    try:
                        self.process.stdin.write("\n")
                        self.process.stdin.flush()
                    except Exception:
                        pass
                        
            self.process.stdout.close()
            self.process.wait()
            self.log(f"\n[System] Process finished (Exit Code {self.process.returncode})")
            
        except Exception as e:
            self.log(f"\n[Error] Execution failed: {e}")
            
        finally:
            self.root.after(0, lambda: self.btn_extract.state(['!disabled']))
            self.root.after(0, lambda: self.btn_side_channel.state(['!disabled']))

    def run_side_channel(self):
        if self.process and self.process.poll() is None:
            self.log("\n[!] A process is already running...")
            return
            
        self.console.config(state=tk.NORMAL)
        self.console.delete(1.0, tk.END)
        self.console.config(state=tk.DISABLED)
        
        self.log("[System] Launching Logic Analyzer Interface...")
        self.btn_extract.state(['disabled'])
        self.btn_side_channel.state(['disabled'])
        
        threading.Thread(target=self._run_logic_thread, daemon=True).start()

    def _run_logic_thread(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        script_path = os.path.join(script_dir, "LogicAnalysis", "logic_analyzer.py")
        
        if not os.path.exists(script_path):
            self.log(f"[Error] Could not locate: {script_path}")
            self.root.after(0, lambda: self.btn_extract.state(['!disabled']))
            self.root.after(0, lambda: self.btn_side_channel.state(['!disabled']))
            return

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        env["GUI_MODE"] = "1"

        try:
            self.process = subprocess.Popen(
                [sys.executable, "-u", script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=env,
                creationflags=0x08000000 
            )
            
            for line in self.process.stdout:
                clean_line = line.replace('\r', '').strip('\n')
                if clean_line:
                    self.log(clean_line)
                        
            self.process.stdout.close()
            self.process.wait()
            self.log(f"\n[System] Logic Analyzer finished (Exit Code {self.process.returncode})")
            
        except Exception as e:
            self.log(f"\n[Error] Execution failed: {e}")
            
        finally:
            self.root.after(0, lambda: self.btn_extract.state(['!disabled']))
            self.root.after(0, lambda: self.btn_side_channel.state(['!disabled']))

def main():
    if not is_admin():
        run_as_admin()
        sys.exit()
        
    root = tk.Tk()
    app = HexWardenApp(root)
    
    # Configure grid weights so UI resizes gracefully
    root.grid_columnconfigure(0, weight=1)
    root.grid_rowconfigure(0, weight=1)
    
    root.mainloop()

if __name__ == "__main__":
    main()
