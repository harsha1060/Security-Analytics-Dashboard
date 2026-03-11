import subprocess
import time
import os

# --- CONFIGURATION ---
# NOTE: The destination path is automatically set to the current directory ('access.log')
# The user's provided SCP command is:
# scp -i "C:\Users\harsh\Downloads\login.pem" ubuntu@ec2-3-80-121-33.compute-1.amazonaws.com:/var/log/apache2/access.log W:\Project\access.log
# We will use the parts of this command:
SCP_COMMAND = [
    'scp',
    '-i', 'C:\\Users\\harsh\\Downloads\\login.pem', # Use double backslashes for path in Windows
    'ubuntu@ec2-3-80-121-33.compute-1.amazonaws.com:/var/log/apache2/access.log',
    'access.log' # Save to the current project directory
]

SYNC_INTERVAL_SECONDS = 10 # Check for and fetch new logs every 10 seconds
# ---------------------

def fetch_and_sync_log_file():
    """
    Executes the SCP command to download the remote log file.
    """
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Attempting to fetch access.log from EC2...")
    
    try:
        # Run the SCP command
        result = subprocess.run(
            SCP_COMMAND,
            check=True,  # Raise an exception for non-zero return codes
            capture_output=True,
            text=True
        )
        
        # Check if the file was actually downloaded or overwritten
        if os.path.exists('access.log'):
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] SUCCESS: access.log updated locally.")
        else:
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] WARNING: SCP succeeded but access.log not found locally.")

    except subprocess.CalledProcessError as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ERROR: SCP failed.")
        print(f"  Return Code: {e.returncode}")
        print(f"  STDOUT: {e.stdout.strip()}")
        print(f"  STDERR: {e.stderr.strip()}")
        print("Please ensure your 'login.pem' path is correct, the key has the right permissions, and the EC2 instance is reachable.")
    except FileNotFoundError:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] CRITICAL ERROR: The 'scp' command was not found.")
        print("Ensure 'scp' (part of SSH client) is installed and available in your system's PATH.")
    except Exception as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] UNEXPECTED ERROR: {e}")

def continuous_sync_loop():
    """
    Runs the log fetching task repeatedly.
    """
    print("--- Log Synchronizer Started ---")
    print(f"Will fetch logs every {SYNC_INTERVAL_SECONDS} seconds.")
    
    while True:
        fetch_and_sync_log_file()
        time.sleep(SYNC_INTERVAL_SECONDS)

if __name__ == '__main__':
    continuous_sync_loop()