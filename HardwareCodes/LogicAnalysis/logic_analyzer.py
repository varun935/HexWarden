import os
import sys
import subprocess
import threading
import io
import matplotlib.pyplot as plt

# Look for sigrok-cli in the standard Windows installation path
SIGROK_CLI = r"C:\Program Files\sigrok\PulseView\sigrok-cli.exe"

def check_sigrok():
    if not os.path.exists(SIGROK_CLI):
        print("="*70)
        print(" ERROR: Hardware driver software (PulseView/sigrok) not found!")
        print("="*70)
        print("To use the generic USB Logic Analyzer, you must install the drivers first:")
        print(" 1. Go to https://sigrok.org/wiki/Downloads and download PulseView for Windows.")
        print(" 2. Install it (this will install sigrok-cli in C:\\Program Files\\sigrok\\PulseView).")
        print(" 3. Plug in your Logic Analyzer via USB.")
        print(" 4. Open the 'Zadig' tool (it should have installed with PulseView).")
        print(" 5. In Zadig, go to 'Options' -> check 'List All Devices'.")
        print(" 6. Select 'Unknown Device' (or 'Saleae Logic') from the main dropdown.")
        print(" 7. Ensure the driver selected is 'WinUSB', then click 'Install Driver'.")
        print("="*70)
        if not os.environ.get("GUI_MODE"): input("Press Enter to exit and return to the main menu...")
        sys.exit(1)

def ensure_pandas():
    try:
        import pandas as pd
        return pd
    except ImportError:
        print("Installing pandas for data parsing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pandas"])
        import pandas as pd
        return pd

def capture_data():
    print("Connecting to Logic Analyzer...")
    print("Capturing 5000 samples at 1MHz...")
    try:
        # fx2lafw is the open-source firmware for generic 24MHz 8CH analyzers
        # We capture 5000 samples and output as CSV
        result = subprocess.run(
            [SIGROK_CLI, "--driver", "fx2lafw", "--config", "samplerate=1M", "--samples", "5000", "-O", "csv"],
            capture_output=True, text=True, check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"\n[Hardware Error]: Failed to capture data.")
        print(f"Details: {e.stderr.strip()}")
        print("\nMake sure:")
        print("1. The logic analyzer is securely plugged in.")
        print("2. You have used Zadig to install the WinUSB driver for it.")
        if not os.environ.get("GUI_MODE"): input("Press Enter to exit...")
        sys.exit(1)

def main():
    check_sigrok()
    pd = ensure_pandas()
    
    csv_data = capture_data()
    
    print("Data captured successfully! Parsing and plotting...")
    
    # Read the CSV data. Output typically looks like:
    # id, D0, D1, D2, D3, D4, D5, D6, D7
    try:
        df = pd.read_csv(io.StringIO(csv_data))
    except Exception as e:
        print(f"Error parsing data: {e}")
        if not os.environ.get("GUI_MODE"): input("Press Enter to exit...")
        sys.exit(1)
    
    # Extract just the data channels (D0 through D7)
    channels_to_plot = [col for col in df.columns if 'D' in col][:4] # Plot first 4 channels for clarity
    
    if not channels_to_plot:
        print("No data channels found in output.")
        if not os.environ.get("GUI_MODE"): input("Press Enter to exit...")
        sys.exit(1)

    fig, axs = plt.subplots(len(channels_to_plot), 1, figsize=(10, 6), sharex=True)
    if len(channels_to_plot) == 1:
        axs = [axs]
        
    fig.canvas.manager.set_window_title('Logic Analyzer - Real Capture')
    fig.suptitle('Generic USB Logic Analyzer (Live Hardware Data)', fontsize=14)
    
    for i, col in enumerate(channels_to_plot):
        axs[i].step(df.index, df[col], where='post', color=f'C{i}')
        axs[i].set_ylim(-0.2, 1.2)
        axs[i].set_ylabel(col.strip())
        axs[i].set_yticks([0, 1])
        axs[i].grid(True, linestyle='--', alpha=0.5)
        
    axs[-1].set_xlabel('Sample Index (Time)')
    
    plt.tight_layout()
    print("Displaying graph. Close the plot window to save and exit.")
    plt.show() # Blocks until window is closed
    
    # Save the last frame
    script_dir = os.path.dirname(os.path.abspath(__file__))
    counter = 1
    while True:
        output_img = os.path.join(script_dir, f"analysis_capture_{counter}.png")
        if not os.path.exists(output_img):
            break
        counter += 1
        
    fig.savefig(output_img)
    print(f"Graph saved to {output_img}")
    sys.exit(0)

if __name__ == "__main__":
    main()
