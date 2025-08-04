import time
import argparse
import subprocess
import signal
import os
import toml
import readchar
from pystyle import Colors, Colorate
from utils.Logger import Log
from core import PluginHandler

BASE_DIR = os.getcwd()

CONFIG_FILE = os.path.join(BASE_DIR, "config.toml")
LOG_FILE = os.path.join(BASE_DIR, "app.log")
PID_FILE = os.path.join(BASE_DIR, "app.pid")

with open(CONFIG_FILE, "r", encoding="utf-8", errors="replace") as f:
    data = toml.loads(f.read())

def motd():
    """Display Novel Anti-Abuse MOTD"""
    Log.v(f"""
                    o    o                      8 
                    8b   8                      8 
                    8`b  8 .oPYo. o    o .oPYo. 8 
                    8 `b 8 8    8 Y.  .P 8oooo8 8 
                    8  `b8 8    8 `b..d' 8.     8 
                    8   `8 `YooP'  `YP'  `Yooo' 8 
                    ..:::..:.....:::...:::.....:..
                    ::::::::::::::::::::::::::::::

            Product - ANTI-ABUSE
            Release - {data['ver']}
            License - GNU GENERAL PUBLIC LICENSE, Version 3
        """)

def session_app():
    """Start the application in the current terminal"""
    motd()
    PluginHandler().app_run()

def stop_app():
    """Stop the running application"""
    if os.path.exists(PID_FILE):
        with open(PID_FILE, "r", encoding="utf-8") as f:
            pid = int(f.read())
        try:
            os.kill(pid, signal.SIGTERM)
            os.remove(PID_FILE)
            Log.v("Application stopped.")
        except ProcessLookupError:
            Log.v("No running instance found.")

def start_app():
    """Start the application in the background"""
    stop_app()
    motd()
    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        process = subprocess.Popen(
            [os.path.join(BASE_DIR, "main.py"), "--session"], 
            stdout=log_file, 
            stderr=log_file, 
            bufsize=1,
            universal_newlines=True,
            start_new_session=True,
        )

    with open(PID_FILE, "w", encoding="utf-8") as f:
        f.write(str(process.pid))

    Log.v("Application started and running in background.")

def restart_app():
    """Restart the application"""
    stop_app()
    start_app()
    Log.v("Application restarted.")

def load_logs():
    """Load logs from file"""
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            return f.readlines()
    return ["No log file found."]

def show_logs():
    """SSH-friendly log viewer with arrow key scrolling"""
    logs = load_logs()
    max_lines = 30
    offset = max(0, len(logs) - max_lines)

    clear_screen = lambda: os.system("cls" if os.name == "nt" else "clear")

    def display_logs():
        clear_screen()
        print(Colorate.Horizontal(Colors.blue_to_white, " Novel Anti-Abuse - LOGS ", 1))
        print(Colorate.Horizontal(Colors.green_to_white, " ↑↓ Scroll | D Bottom | U Top | Q Quit ", 1))

        for line in logs[offset: offset + max_lines]:
            print(line.strip())

    display_logs()
    
    while True:
        key = readchar.readkey()

        if key == readchar.key.UP and offset > 0:
            offset -= 1
        elif key == readchar.key.DOWN and offset < len(logs) - max_lines:
            offset += 1
        elif key.lower() == "u":
            offset = 0
        elif key.lower() == "d":
            offset = max(0, len(logs) - max_lines)
        elif key.lower() == "q":
            Log.v("Exiting log viewer.")
            break
        else:
            continue

        display_logs()
        time.sleep(0.05)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Manage the Anti-Abuse application")
    parser.add_argument("--session", action="store_true", help="Start the application in current terminal")
    parser.add_argument("--logs", action="store_true", help="Show the latest log output")

    args = parser.parse_args()

    if args.session:
        session_app()
    elif args.logs:
        show_logs()
    else:
        Log.v("Displaying auto-generated parser help")
        parser.print_help()
