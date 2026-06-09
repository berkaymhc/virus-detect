import time
import hashlib
import requests
import os
import logging
import threading
import shutil
import sys
import webbrowser
import platform
import socket
import winreg
import tkinter as tk
from tkinter import messagebox, ttk, simpledialog
from dotenv import load_dotenv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- SYSTEM TRAY LIBRARIES ---
import pystray
from PIL import Image

# --- YARA (OFFLINE ENGINE) ---
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

# --- SINGLETON MUTEX ---
try:
    from win32event import CreateMutex
    from win32api import GetLastError
    from winerror import ERROR_ALREADY_EXISTS
    mutex = CreateMutex(None, False, "Global\\SentinelVTApp_Securev1.0")
    if GetLastError() == ERROR_ALREADY_EXISTS:
        sys.exit()
except ImportError:
    pass

class ConfigManager:
    def __init__(self):
        if getattr(sys, 'frozen', False):
            self.base_dir = os.path.dirname(sys.executable)
            self.exe_path = sys.executable
            # Load bundled icon from PyInstaller temp folder
            self.icon_path = os.path.join(sys._MEIPASS, 'logo.png')
        else:
            self.base_dir = os.path.dirname(os.path.abspath(__file__))
            self.exe_path = os.path.abspath(__file__)
            self.icon_path = os.path.join(self.base_dir, 'logo.png')
        self.quarantine_dir = os.path.join(self.base_dir, 'Quarantine')
        self.env_path = os.path.join(self.base_dir, '.env')
        self.rules_path = os.path.join(self.base_dir, 'rules.yar')
        self.log_path = os.path.join(self.base_dir, 'sentinel_log.txt')
        self.app_name = "Sentinel-VT"
        
        self.vt_base_url = 'https://www.virustotal.com/api/v3'
        self.max_file_size_mb = 32
        self.watch_directory = os.path.join(os.path.expanduser("~"), "Downloads")
        
        self._ensure_directories()
        self.load_env()

    def _ensure_directories(self):
        try:
            if not os.path.exists(self.quarantine_dir):
                os.makedirs(self.quarantine_dir)
        except Exception as e:
            logging.error(f"Error in ConfigManager._ensure_directories: {e}")

    def load_env(self):
        try:
            load_dotenv(self.env_path)
            self.vt_api_key = os.getenv('VT_API_KEY')
            self.telegram_bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
            self.telegram_chat_id = os.getenv('TELEGRAM_CHAT_ID')
        except Exception as e:
            logging.error(f"Error in ConfigManager.load_env: {e}")
            
    def add_to_startup(self):
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "SentinelVT", 0, winreg.REG_SZ, self.exe_path)
            key.Close()
            return True
        except Exception as e:
            logging.error(f"Error in ConfigManager.add_to_startup: {e}")
            return False

class LoggerService:
    @staticmethod
    def setup_logging(log_path):
        try:
            logging.basicConfig(
                filename=log_path, 
                level=logging.INFO, 
                format='%(asctime)s - %(levelname)s - %(message)s', 
                datefmt='%Y-%m-%d %H:%M:%S', 
                encoding='utf-8'
            )
            logging.info("Logging initialized.")
        except Exception as e:
            print(f"Failed to initialize logging: {e}")

class NotificationService:
    def __init__(self, config: ConfigManager):
        self.config = config
        self.icon_instance = None # Registered when setup_tray runs

    def _get_os_friendly_name(self):
        try:
            ver = sys.getwindowsversion()
            if ver.major == 10 and ver.build >= 22000: return "Windows 11"
            return f"{platform.system()} {platform.release()}"
        except Exception as e:
            logging.error(f"Error in NotificationService._get_os_friendly_name: {e}")
            return f"{platform.system()} {platform.release()}"

    def send_telemetry(self, title, message):
        if not self.config.telegram_bot_token or not self.config.telegram_chat_id: 
            return
        
        def _send():
            try:
                os_name = self._get_os_friendly_name()
                user_info = f"👤 User: {os.getlogin()}\n💻 PC: {socket.gethostname()}\n⚙️ OS: {os_name}"
                full_text = f"<b>{title}</b>\n\n{message}\n\n----------------\n{user_info}"
                requests.post(
                    f"https://api.telegram.org/bot{self.config.telegram_bot_token}/sendMessage", 
                    data={"chat_id": self.config.telegram_chat_id, "text": full_text, "parse_mode": "HTML"},
                    timeout=10
                )
            except Exception as e:
                logging.error(f"Error in NotificationService.send_telemetry: {e}")
                
        threading.Thread(target=_send, daemon=True).start()

    def send_toast(self, title, message, sound=False, active=True):
        if not active: return
        logging.info(f"Notification: [{title}] {message}")
        if self.icon_instance:
            try:
                self.icon_instance.notify(message, title)
            except Exception as e:
                logging.error(f"Error in NotificationService.send_toast (pystray): {e}")


class YaraScanner:
    def __init__(self, config: ConfigManager):
        self.config = config
        self.rules = None
        self._load_rules()

    def _load_rules(self):
        if not YARA_AVAILABLE:
            logging.warning("yara-python is not installed. Offline scanning is disabled.")
            return

        if not os.path.exists(self.config.rules_path):
            logging.info(f"YARA rules file not found at: {self.config.rules_path}")
            return

        try:
            self.rules = yara.compile(filepath=self.config.rules_path)
            logging.info("YARA rules successfully loaded and compiled.")
        except Exception as e:
            logging.error(f"Error compiling YARA rules: {e}")

    def scan(self, filepath):
        if not self.rules:
            return False, None
        try:
            matches = self.rules.match(filepath)
            if matches:
                return True, matches[0].rule
            return False, None
        except Exception as e:
            logging.error(f"Error scanning file with YARA: {e}")
            return False, None


class VirusTotalScanner:
    def __init__(self, config: ConfigManager, notifier: NotificationService, watcher):
        self.config = config
        self.notifier = notifier
        self.watcher = watcher # to call quarantine

    def get_hash(self, filepath):
        sha = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""): 
                    sha.update(chunk)
            return sha.hexdigest()
        except Exception as e:
            logging.error(f"Error in VirusTotalScanner.get_hash: {e}")
            return None

    def check_file(self, filepath):
        f_hash = self.get_hash(filepath)
        if not f_hash: return
        
        filename = os.path.basename(filepath)
        try:
            headers = {'x-apikey': self.config.vt_api_key}
            resp = requests.get(f"{self.config.vt_base_url}/files/{f_hash}", headers=headers, timeout=10)
            
            if resp.status_code == 200:
                stats = resp.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                self._evaluate_stats(stats, filepath)
            elif resp.status_code == 404:
                size = os.path.getsize(filepath)
                if size > (self.config.max_file_size_mb * 1024 * 1024):
                    self.notifier.send_toast("Error", "File exceeds 32MB limit.", sound=True, active=self.watcher.is_active)
                    self.notifier.send_telemetry("⚠️ SIZE EXCEEDED", f"File: {filename}\nSize: {size/1024/1024:.2f} MB")
                else:
                    self.notifier.send_toast("Analyzing", "Uploading file to server...", active=self.watcher.is_active)
                    self.notifier.send_telemetry("📤 UPLOADING", f"File: {filename}")
                    self._upload_file(filepath)
            elif resp.status_code == 401: 
                self.notifier.send_telemetry("💀 API ERROR", "Invalid API Key.")
                logging.error("Invalid VT API Key.")
            else:
                logging.error(f"VirusTotal API returned status: {resp.status_code}")
        except Exception as e:
            logging.error(f"Error in VirusTotalScanner.check_file: {e}")

    def _upload_file(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                headers = {'x-apikey': self.config.vt_api_key}
                files = {'file': (os.path.basename(filepath), f)}
                resp = requests.post(f"{self.config.vt_base_url}/files", headers=headers, files=files, timeout=30)
                
            if resp.status_code == 200: 
                analysis_id = resp.json().get('data', {}).get('id')
                if analysis_id:
                    self._poll_analysis(analysis_id, filepath)
        except Exception as e:
            logging.error(f"Error in VirusTotalScanner._upload_file: {e}")

    def _poll_analysis(self, analysis_id, filepath):
        try:
            headers = {'x-apikey': self.config.vt_api_key}
            for _ in range(60):
                time.sleep(5)
                r = requests.get(f"{self.config.vt_base_url}/analyses/{analysis_id}", headers=headers, timeout=10)
                if r.status_code == 200:
                    data = r.json().get('data', {}).get('attributes', {})
                    if data.get('status') == 'completed':
                        self._evaluate_stats(data.get('stats', {}), filepath)
                        return
        except Exception as e:
            logging.error(f"Error in VirusTotalScanner._poll_analysis: {e}")

    def _evaluate_stats(self, stats, filepath):
        try:
            malicious = stats.get('malicious', 0)
            filename = os.path.basename(filepath)
            if malicious > 0:
                self.watcher.quarantine_file(filepath, reason="VirusTotal Malicious Verdict")
            else:
                self.notifier.send_toast("✅ Safe", f"{filename} is clean.", active=self.watcher.is_active)
                self.notifier.send_telemetry("✅ CLEAN FILE", f"File: {filename}")
        except Exception as e:
            logging.error(f"Error in VirusTotalScanner._evaluate_stats: {e}")


class DirectoryEventHandler(FileSystemEventHandler):
    def __init__(self, watcher):
        self.watcher = watcher
        self.temp_exts = ('.tmp', '.crdownload', '.part', '.opdownload')

    def check(self, filepath):
        if not self.watcher.is_active: return
        if os.path.basename(filepath).endswith(self.temp_exts + ('.ini', '.log')): return
        threading.Thread(target=self.process, args=(filepath,), daemon=True).start()

    def on_created(self, event): 
        if not event.is_directory: self.check(event.src_path)
        
    def on_modified(self, event):
        if not event.is_directory: self.check(event.src_path)
        
    def on_moved(self, event):
        if not event.is_directory and os.path.splitext(event.src_path)[1] in self.temp_exts: 
            self.check(event.dest_path)

    def process(self, filepath):
        filename = os.path.basename(filepath)
        with self.watcher.lock:
            if filepath in self.watcher.processed_files:
                if (time.time() - self.watcher.processed_files[filepath]) < 5: return
            self.watcher.processed_files[filepath] = time.time()

        start = time.time()
        last_size, stable = -1, 0
        while time.time() - start < 30:
            if not os.path.exists(filepath): return
            try:
                size = os.path.getsize(filepath)
                if size == 0: 
                    time.sleep(0.5)
                    continue
                if size == last_size: 
                    stable += 1
                else: 
                    stable = 0
                last_size = size
                if stable >= 2: break
                time.sleep(0.5)
            except Exception as e:
                logging.error(f"Error checking file size in process: {e}")
                time.sleep(0.5)

        self.watcher.notifier.send_toast("Scanning...", f"Checking {filename}.", active=self.watcher.is_active)
        
        # Step 1: Offline YARA check
        logging.info(f"Scanning with YARA: {filename}")
        is_virus, rule_name = self.watcher.local_scanner.scan(filepath)
        if is_virus:
            logging.warning(f"YARA Match: {rule_name} on file: {filename}")
            self.watcher.quarantine_file(filepath, reason=f"YARA Rule: {rule_name}")
            return
            
        # Step 2: Online VirusTotal check
        logging.info(f"YARA clean. Querying VirusTotal: {filename}")
        self.watcher.scanner.check_file(filepath)


class DirectoryWatcher(threading.Thread):
    def __init__(self, config: ConfigManager, notifier: NotificationService):
        super().__init__()
        self.config = config
        self.notifier = notifier
        self.local_scanner = YaraScanner(config)
        self.scanner = VirusTotalScanner(config, notifier, self)
        
        self.observer = Observer()
        self.processed_files = {} 
        self.lock = threading.Lock()
        self.running = True
        self.is_active = True 
        
    def run(self):
        event_handler = DirectoryEventHandler(self)
        self.observer.schedule(event_handler, self.config.watch_directory, recursive=False)
        self.observer.start()
        logging.info(f"Started watching directory: {self.config.watch_directory}")
        while self.running: 
            time.sleep(1)
        self.observer.stop()
        self.observer.join()

    def stop(self): 
        self.running = False
        logging.info("Stopping DirectoryWatcher.")

    def toggle_protection(self):
        self.is_active = not self.is_active
        status = "ON" if self.is_active else "OFF"
        self.notifier.send_toast("Protection Status", f"Protection is currently: {status}", active=True)
        return self.is_active

    def quarantine_file(self, filepath, reason="Unknown"):
        try:
            filename = os.path.basename(filepath)
            if os.path.exists(os.path.join(self.config.quarantine_dir, filename + ".quarantine")):
                filename = f"{int(time.time())}_{filename}"
                
            dest = os.path.join(self.config.quarantine_dir, filename + ".quarantine")
            shutil.move(filepath, dest)
            self.notifier.send_telemetry("🚨 THREAT BLOCKED", f"File: {filename}\nReason: {reason}\nStatus: Quarantined.")
            self.notifier.send_toast("🚫 BLOCKED", f"{filename} blocked.\nReason: {reason}", sound=True, active=self.is_active)
            logging.info(f"Quarantined malicious file: {filepath} (Reason: {reason})")
        except Exception as e:
            logging.error(f"Error in DirectoryWatcher.quarantine_file: {e}")


class SentinelApp:
    def __init__(self):
        self.config = ConfigManager()
        LoggerService.setup_logging(self.config.log_path)
        self.notifier = NotificationService(self.config)
        
    def run(self):
        if not self.config.vt_api_key:
            self.run_setup_wizard()
            self.config.load_env()

        if not self.config.vt_api_key:
            logging.error("No API key provided. Exiting.")
            sys.exit()

        self.watcher_thread = DirectoryWatcher(self.config, self.notifier)
        self.watcher_thread.daemon = True
        self.watcher_thread.start()
        
        try:
            self.setup_tray()
        except KeyboardInterrupt:
            self.watcher_thread.stop()
            sys.exit()
        except Exception as e:
            logging.error(f"Error running SentinelApp: {e}")
            self.watcher_thread.stop()
            sys.exit()

    def run_setup_wizard(self):
        def open_vt_signup(): 
            webbrowser.open("https://www.virustotal.com/gui/join-us")
            
        def open_existing(root):
            u = simpledialog.askstring("Account", "Enter your VirusTotal username:", parent=root)
            if u: webbrowser.open(f"https://www.virustotal.com/gui/user/{u.strip()}/apikey")

        root = tk.Tk()
        root.title("Sentinel-VT Setup")
        w, h = 550, 480
        root.geometry(f"{w}x{h}+{int((root.winfo_screenwidth()-w)/2)}+{int((root.winfo_screenheight()-h)/2)}")
        root.resizable(False, False)
        
        if os.path.exists(self.config.icon_path):
            try: 
                root.iconphoto(False, tk.PhotoImage(file=self.config.icon_path))
            except Exception as e: 
                logging.error(f"Could not load icon in setup wizard: {e}")

        tk.Label(root, text="Sentinel-VT Activation", font=("Segoe UI", 16, "bold")).pack(pady=(20, 10))
        tk.Label(root, text="For security, additional configurations (like Telegram tokens)\nmust be added manually to the .env file.", font=("Segoe UI", 9)).pack(pady=(0, 10))

        f_btns = tk.Frame(root, pady=10)
        f_btns.pack()
        tk.Button(f_btns, text="Create New Account", bg="#3498db", fg="white", width=18, command=open_vt_signup).pack(side="left", padx=5)
        tk.Button(f_btns, text="Open API Key Page", bg="#9b59b6", fg="white", width=18, command=lambda: open_existing(root)).pack(side="right", padx=5)

        tk.Label(root, text="API Key:", font=("Segoe UI", 10, "bold")).pack(pady=(15, 5))
        f_entry = tk.Frame(root)
        f_entry.pack(pady=5)
        entry_key = ttk.Entry(f_entry, width=45)
        entry_key.pack(side="left", padx=(0, 5))
        
        def paste_key():
            try:
                content = root.clipboard_get().strip()
                if len(content) >= 60: # typical VT API key length
                    entry_key.delete(0, tk.END)
                    entry_key.insert(0, content)
                    btn_paste.config(text="✅ OK", bg="#27ae60")
                else: 
                    messagebox.showwarning("Error", "Clipboard content does not appear to be a valid API Key format.")
            except Exception as e: 
                logging.error(f"Error pasting key: {e}")
                
        btn_paste = tk.Button(f_entry, text="📋 Paste", bg="#e0e0e0", command=paste_key)
        btn_paste.pack(side="right")

        var_start = tk.IntVar(value=1)
        tk.Checkbutton(root, text="Start automatically when Windows starts", variable=var_start).pack(pady=15)

        def save():
            k = entry_key.get().strip()
            if len(k) < 60: 
                messagebox.showerror("Error", "Invalid API Key!")
                return
            try:
                with open(self.config.env_path, "a") as f: 
                    f.write(f"\nVT_API_KEY={k}")
                
                if var_start.get(): 
                    self.config.add_to_startup()
                
                self.config.load_env()
                self.notifier.send_telemetry("🚀 SETUP COMPLETED", f"🔑 Key added.\n👤 User: {os.getlogin()}")
                messagebox.showinfo("Success", "Setup complete! You can manage the app from the system tray.")
                root.destroy()
            except Exception as e: 
                messagebox.showerror("Error", str(e))
                logging.error(f"Error saving config: {e}")

        tk.Button(root, text="SAVE AND START", bg="#2ecc71", fg="white", font=("Segoe UI", 10, "bold"), padx=20, pady=10, command=save).pack(pady=10)
        root.protocol("WM_DELETE_WINDOW", sys.exit)
        root.mainloop()

    def setup_tray(self):
        try:
            image = Image.open(self.config.icon_path)
        except Exception as e:
            logging.error(f"Failed to load tray icon: {e}")
            image = Image.new('RGB', (64, 64), color = (73, 109, 137))
            
        def quit_action(icon, item):
            icon.stop()
            self.watcher_thread.stop()
            sys.exit()

        def toggle_protection_action(icon, item):
            self.watcher_thread.toggle_protection()

        menu = pystray.Menu(
            pystray.MenuItem("Protection Active", toggle_protection_action, checked=lambda item: self.watcher_thread.is_active),
            pystray.MenuItem("Exit", quit_action)
        )
        
        icon = pystray.Icon("SentinelVT", image, "Sentinel-VT", menu)
        self.notifier.icon_instance = icon # Register the icon for notifications
        icon.run()

if __name__ == '__main__':
    app = SentinelApp()
    app.run()