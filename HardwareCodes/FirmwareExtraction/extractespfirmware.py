import os
import sys
import subprocess
import ctypes

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    script_path = os.path.abspath(__file__)
    print("Requesting administrative privileges...")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script_path}"', None, 1)

def install_dependencies():
    deps = {"pyserial": "serial", "esptool": "esptool"}
    for pkg, mod in deps.items():
        try:
            __import__(mod)
        except ImportError:
            print(f"Installing {pkg}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
            
def find_esp32():
    import serial.tools.list_ports
    ports = serial.tools.list_ports.comports()
    for port in ports:
        print(f"Checking {port.device}...")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "esptool", "--port", port.device, "chip_id"],
                capture_output=True, text=True, timeout=5
            )
            if "ESP32" in result.stdout:
                return port.device
        except Exception:
            continue
    return None

def get_flash_size(port):
    try:
        result = subprocess.run(
            [sys.executable, "-m", "esptool", "--port", port, "flash_id"],
            capture_output=True, text=True
        )
        for line in result.stdout.split('\n'):
            if "Detected flash size:" in line:
                size_str = line.split(":")[1].strip()
                if size_str == "1MB": return 0x100000
                if size_str == "2MB": return 0x200000
                if size_str == "4MB": return 0x400000
                if size_str == "8MB": return 0x800000
                if size_str == "16MB": return 0x1000000
    except:
        pass
    return 0x400000 

def main():
    if not is_admin():
        run_as_admin()
        sys.exit()
        
    print("Running with administrative privileges.")
    
    print("Checking dependencies...")
    install_dependencies()
    
    # Save the bin file in the same directory as this script (which is FirmwareExtraction)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Generate a uniquely numbered filename
    counter = 1
    while True:
        output_bin = os.path.join(script_dir, f"esp32_firmware_{counter}.bin")
        if not os.path.exists(output_bin):
            break
        counter += 1
        
    print("Scanning COM ports for ESP32...")
    esp32_port = find_esp32()
    
    if not esp32_port:
        print("No ESP32 found on any COM port. Please ensure it is connected and the drivers are installed.")
        if not os.environ.get("GUI_MODE"): input("Press Enter to exit...")
        return
        
    print(f"ESP32 found on {esp32_port}!")
    
    flash_size_bytes = get_flash_size(esp32_port)
    print(f"Flash size to read: {hex(flash_size_bytes)} bytes")
    
    print(f"Extracting firmware to {output_bin}...")
    print("This may take a few minutes. Please do not disconnect the device.")
    
    try:
        subprocess.run(
            [sys.executable, "-m", "esptool", "--port", esp32_port, "--baud", "115200", "read-flash", "0x0", str(flash_size_bytes), output_bin],
            check=True
        )
        print(f"Success! Firmware saved to {os.path.abspath(output_bin)}")
    except subprocess.CalledProcessError as e:
        print(f"Error extracting firmware: {e}")
        
    if not os.environ.get("GUI_MODE"): input("Press Enter to exit...")

if __name__ == "__main__":
    main()
