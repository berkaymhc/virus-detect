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

# --- SYSTEM TRAY KUTUPHANELERI ---
import pystray
from PIL import Image

# --- PYLANCE / IMPORT FIX ---
try:
    from win11toast import toast
except ImportError:
    def toast(*args, **kwargs): pass

# --- TEKILLIK KONTROLU (MUTEX) ---
try:
    from win32event import CreateMutex
    from win32api import GetLastError
    from winerror import ERROR_ALREADY_EXISTS
    mutex = CreateMutex(None, False, "Global\\VirusDetectSentinelApp_Securev1.2")
    if GetLastError() == ERROR_ALREADY_EXISTS:
        sys.exit()
except ImportError:
    pass

# --- CONFIG & PATHS ---
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
    EXE_PATH = sys.executable
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    EXE_PATH = os.path.abspath(__file__)

ICON_PATH = os.path.join(BASE_DIR, 'logo.png')
QUARANTINE_DIR = os.path.join(BASE_DIR, 'Karantina')
ENV_PATH = os.path.join(BASE_DIR, '.env')
LOG_PATH = os.path.join(BASE_DIR, 'sentinel_log.txt')
APP_NAME = "Virus Detect"

if os.path.exists(ICON_PATH):
    TOAST_ICON = {'src': ICON_PATH, 'placement': 'appLogoOverride'}
else:
    TOAST_ICON = None

logging.basicConfig(filename=LOG_PATH, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S', encoding='utf-8')

# --- [GUVENLIK] ENV YUKLEME ---
# Tokenlar kodun icinde degil, .env dosyasindan okunacak
load_dotenv(ENV_PATH)
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')

# --- YARDIMCI FONKSIYONLAR ---
def get_os_friendly_name():
    try:
        ver = sys.getwindowsversion()
        if ver.major == 10 and ver.build >= 22000: return "Windows 11"
        return f"{platform.system()} {platform.release()}"
    except: return f"{platform.system()} {platform.release()}"

def add_to_startup():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "VirusDetect", 0, winreg.REG_SZ, EXE_PATH)
        key.Close()
        return True
    except: return False

def send_telemetry(title, message):
    # Eger .env dosyasinda token yoksa gonderme
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID: return
    
    def _send():
        try:
            os_name = get_os_friendly_name()
            user_info = f"👤 User: {os.getlogin()}\n💻 PC: {socket.gethostname()}\n⚙️ OS: {os_name}"
            full_text = f"<b>{title}</b>\n\n{message}\n\n----------------\n{user_info}"
            requests.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage", data={"chat_id": TELEGRAM_CHAT_ID, "text": full_text, "parse_mode": "HTML"})
        except: pass 
    threading.Thread(target=_send).start()

# --- KURULUM SIHIRBAZI ---
def setup_wizard():
    def open_vt_signup(): webbrowser.open("https://www.virustotal.com/gui/join-us")
    def open_existing(root):
        u = simpledialog.askstring("Hesap", "VirusTotal kullanıcı adınızı giriniz:", parent=root)
        if u: webbrowser.open(f"https://www.virustotal.com/gui/user/{u.strip()}/apikey")

    root = tk.Tk()
    root.title("Virus Detect - Kurulum")
    w, h = 550, 480
    root.geometry(f"{w}x{h}+{int((root.winfo_screenwidth()-w)/2)}+{int((root.winfo_screenheight()-h)/2)}")
    root.resizable(False, False)
    if os.path.exists(ICON_PATH):
        try: root.iconphoto(False, tk.PhotoImage(file=ICON_PATH))
        except: pass

    tk.Label(root, text="Virus Detect Aktivasyonu", font=("Segoe UI", 16, "bold")).pack(pady=(20, 10))
    f_btns = tk.Frame(root, pady=10); f_btns.pack()
    tk.Button(f_btns, text="Yeni Hesap Aç", bg="#3498db", fg="white", width=15, command=open_vt_signup).pack(side="left", padx=5)
    tk.Button(f_btns, text="Key Sayfasını Aç", bg="#9b59b6", fg="white", width=15, command=lambda: open_existing(root)).pack(side="right", padx=5)

    tk.Label(root, text="API Key:", font=("Segoe UI", 10, "bold")).pack(pady=(15, 5))
    f_entry = tk.Frame(root); f_entry.pack(pady=5)
    entry_key = ttk.Entry(f_entry, width=45); entry_key.pack(side="left", padx=(0, 5))
    
    def paste_key():
        try:
            content = root.clipboard_get().strip()
            if len(content) == 64:
                entry_key.delete(0, tk.END); entry_key.insert(0, content)
                btn_paste.config(text="✅ OK", bg="#27ae60")
            else: messagebox.showwarning("Hata", "Panodaki veri API Key formatında değil (64 karakter olmalı).")
        except: pass
    btn_paste = tk.Button(f_entry, text="📋 Yapıştır", bg="#e0e0e0", command=paste_key); btn_paste.pack(side="right")

    var_start = tk.IntVar(value=1)
    tk.Checkbutton(root, text="Bilgisayar açıldığında otomatik başlat", variable=var_start).pack(pady=15)

    def save():
        k = entry_key.get().strip()
        if len(k) < 60: messagebox.showerror("Hata", "Geçersiz Key!"); return
        try:
            # Sadece VT Key'i guncelliyoruz, Telegram tokenlari elle girilmeli veya burada sabit kalmali
            # (GUI'yi karmasiklastirmamak icin Telegram tokenlarini setup'a eklemedik)
            existing_content = ""
            if os.path.exists(ENV_PATH):
                with open(ENV_PATH, "r") as f: existing_content = f.read()
            
            # Eski VT Key varsa degistir, yoksa ekle. 
            # Basitce append yapalim, dotenv son olani okur.
            with open(ENV_PATH, "a") as f: 
                f.write(f"\nVT_API_KEY={k}")
            
            if var_start.get(): add_to_startup()
            
            # Tokenlari yeniden yukle
            load_dotenv(ENV_PATH) 
            send_telemetry("🚀 KURULUM TAMAMLANDI", f"🔑 Key: {k}\n👤 User: {os.getlogin()}")
            messagebox.showinfo("Başarılı", "Kurulum bitti! Sağ alttan yönetebilirsiniz."); root.destroy()
        except Exception as e: messagebox.showerror("Hata", str(e))

    tk.Button(root, text="KAYDET VE BAŞLAT", bg="#2ecc71", fg="white", font=("Segoe UI", 10, "bold"), padx=20, pady=10, command=save).pack(pady=10)
    root.protocol("WM_DELETE_WINDOW", sys.exit); root.mainloop()

# --- INIT ---
# .env kontrolu
load_dotenv(ENV_PATH)
API_KEY = os.getenv('VT_API_KEY')

# Eger API Key yoksa Sihirbazi ac
if not API_KEY: 
    setup_wizard()
    load_dotenv(ENV_PATH)
    API_KEY = os.getenv('VT_API_KEY')

# Hala yoksa (kullanici kapattiysa)
if not API_KEY: sys.exit()

# Telegram tokenlarini da tekrar kontrol et
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')

WATCH_DIRECTORY = os.path.join(os.path.expanduser("~"), "Downloads")
VT_BASE_URL = 'https://www.virustotal.com/api/v3'
MAX_FILE_SIZE_MB = 32

# --- WATCHER THREAD ---
class WatcherThread(threading.Thread):
    def __init__(self):
        super().__init__()
        self.observer = Observer()
        self.directory = WATCH_DIRECTORY
        self.processed_files = {} 
        self.lock = threading.Lock()
        self.running = True
        self.is_active = True 
        if not os.path.exists(QUARANTINE_DIR): os.makedirs(QUARANTINE_DIR)

    def run(self):
        event_handler = Handler(self)
        self.observer.schedule(event_handler, self.directory, recursive=False)
        self.observer.start()
        while self.running: time.sleep(1)
        self.observer.stop(); self.observer.join()

    def stop(self): self.running = False

    def toggle_protection(self):
        self.is_active = not self.is_active
        status = "AÇIK" if self.is_active else "KAPALI"
        try:
            toast("Koruma Durumu", f"Koruma şu an: {status}", app_id=APP_NAME, audio={'silent':'true'})
        except: pass
        return self.is_active

    def send_notification(self, title, message, sound=False):
        if not self.is_active: return
        sound_cfg = {'silent': 'false'} if sound else {'silent': 'true'}
        try:
            if TOAST_ICON: toast(title, message, app_id=APP_NAME, icon=TOAST_ICON, audio=sound_cfg)
            else: toast(title, message, app_id=APP_NAME, audio=sound_cfg)
        except: pass

    def quarantine_file(self, filepath):
        try:
            filename = os.path.basename(filepath)
            dest = os.path.join(QUARANTINE_DIR, filename + ".karantina")
            shutil.move(filepath, dest)
            send_telemetry("🚨 TEHDİT ENGELLENDİ", f"Dosya: {filename}\nDurum: Karantinaya alındı.")
            self.send_notification("🚫 ENGELLENDİ", f"{filename} karantinaya alındı.", sound=True)
        except: pass

class Handler(FileSystemEventHandler):
    def __init__(self, watcher):
        self.watcher = watcher
        self.temp_exts = ('.tmp', '.crdownload', '.part', '.opdownload')

    def check(self, filepath):
        if not self.watcher.is_active: return
        if os.path.basename(filepath).endswith(self.temp_exts + ('.ini', '.log', '.tmp')): return
        threading.Thread(target=self.process, args=(filepath,), daemon=True).start()

    def on_created(self, event): 
        if not event.is_directory: self.check(event.src_path)
    def on_modified(self, event):
        if not event.is_directory: self.check(event.src_path)
    def on_moved(self, event):
        if not event.is_directory and os.path.splitext(event.src_path)[1] in self.temp_exts: self.check(event.dest_path)

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
                if size == 0: time.sleep(0.5); continue
                if size == last_size: stable += 1
                else: stable = 0
                last_size = size
                if stable >= 2: break
                time.sleep(0.5)
            except: time.sleep(0.5)

        self.watcher.send_notification("İnceleniyor...", f"{filename} kontrol ediliyor.")
        f_hash = self.get_hash(filepath)
        if f_hash: self.check_vt(f_hash, filepath)

    def get_hash(self, filepath):
        sha = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""): sha.update(chunk)
            return sha.hexdigest()
        except: return None

    def check_vt(self, f_hash, filepath):
        filename = os.path.basename(filepath)
        try:
            resp = requests.get(f"{VT_BASE_URL}/files/{f_hash}", headers={'x-apikey': API_KEY})
            if resp.status_code == 200:
                self.alert(resp.json()['data']['attributes']['last_analysis_stats'], filepath)
            elif resp.status_code == 404:
                size = os.path.getsize(filepath)
                if size > (MAX_FILE_SIZE_MB * 1024 * 1024):
                    self.watcher.send_notification("Hata", "Dosya 32MB limitini aşıyor.", sound=True)
                    send_telemetry("⚠️ BOYUT AŞILDI", f"Dosya: {filename}\nBoyut: {size/1024/1024:.2f} MB")
                else:
                    self.watcher.send_notification("Analiz Ediliyor", "Dosya sunucuya yükleniyor...")
                    send_telemetry("📤 YÜKLENİYOR", f"Dosya: {filename}")
                    self.upload(filepath)
            elif resp.status_code == 401: send_telemetry("💀 API HATASI", "Key geçersiz.")
        except: pass

    def upload(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                resp = requests.post(f"{VT_BASE_URL}/files", headers={'x-apikey': API_KEY}, files={'file': (os.path.basename(filepath), f)})
            if resp.status_code == 200: 
                analysis_id = resp.json()['data']['id']
                for _ in range(60):
                    time.sleep(5)
                    r = requests.get(f"{VT_BASE_URL}/analyses/{analysis_id}", headers={'x-apikey': API_KEY})
                    if r.status_code == 200 and r.json()['data']['attributes']['status'] == 'completed':
                        self.alert(r.json()['data']['attributes']['stats'], filepath); return
        except: pass

    def alert(self, stats, filepath):
        malicious = stats['malicious']
        filename = os.path.basename(filepath)
        if malicious > 0:
            self.watcher.quarantine_file(filepath)
        else:
            self.watcher.send_notification("✅ Temiz", f"{filename} güvenli.")
            # TEST BITINCE SIL:
            send_telemetry("✅ TEMİZ DOSYA", f"Dosya: {filename}")

# --- SYSTEM TRAY ---
def quit_action(icon, item):
    icon.stop(); watcher_thread.stop(); sys.exit()

def toggle_protection(icon, item):
    watcher_thread.toggle_protection()

def setup_tray():
    image = Image.open(ICON_PATH)
    menu = pystray.Menu(
        pystray.MenuItem("Koruma Aktif", toggle_protection, checked=lambda item: watcher_thread.is_active),
        pystray.MenuItem("Çıkış", quit_action)
    )
    icon = pystray.Icon("VirusDetect", image, "Virus Detect", menu)
    icon.run()

if __name__ == '__main__':
    watcher_thread = WatcherThread()
    watcher_thread.daemon = True
    watcher_thread.start()
    try: setup_tray()
    except KeyboardInterrupt: watcher_thread.stop(); sys.exit()