import time
import hashlib
import requests
import os
import logging
import threading
from dotenv import load_dotenv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- BİLDİRİM KÜTÜPHANESİ ---
try:
    from win11toast import toast
    print("[OK] Bildirim sistemi (win11toast) hazır.")
except ImportError:
    print("KRİTİK HATA: 'win11toast' yüklü değil. 'pip install win11toast' yapın.")
    exit()

# --- KONFIGURASYON ---
load_dotenv()
API_KEY = os.getenv('VT_API_KEY')
WATCH_DIRECTORY = r'C:\Users\berka\Downloads'
VT_BASE_URL = 'https://www.virustotal.com/api/v3'
MAX_FILE_SIZE_MB = 32
APP_NAME = "Virus Detect"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ICON_PATH = os.path.join(BASE_DIR, 'logo.png')

# İkon Yapılandırması
if os.path.exists(ICON_PATH):
    print("[BAŞARILI] İkon bulundu.")
    TOAST_ICON = {'src': ICON_PATH, 'placement': 'appLogoOverride'}
else:
    print("[UYARI] İkon dosyası YOK! Varsayılan ikon kullanılacak.")
    TOAST_ICON = None

if not API_KEY:
    print("HATA: .env dosyası eksik!")
    exit()

logging.basicConfig(filename='sentinel_log.txt', level=logging.INFO, 
                    format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

def normalize_path(path):
    return os.path.normpath(os.path.abspath(path)).lower()

class Watcher:
    def __init__(self, directory):
        self.observer = Observer()
        self.directory = normalize_path(directory)
        self.processed_files = set()
        self.lock = threading.Lock()

    def run(self):
        event_handler = Handler(self)
        self.observer.schedule(event_handler, self.directory, recursive=False)
        self.observer.start()
        print(f"\n[+] {APP_NAME} devrede. Klasör: {self.directory}")
        
        self.send_notification("Sistem Aktif", "Arka plan koruması başladı.", sound=False)
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.observer.stop()
        self.observer.join()

    # --- ASENKRON BİLDİRİM FONKSİYONU ---
    def _toast_thread(self, title, message, sound_cfg):
        try:
            # DÜZELTME BURADA: app_id PARAMETRESİ EKLENDİ
            if TOAST_ICON:
                toast(title, message, app_id=APP_NAME, icon=TOAST_ICON, audio=sound_cfg)
            else:
                toast(title, message, app_id=APP_NAME, audio=sound_cfg)
        except:
            pass

    def send_notification(self, title, message, sound=False):
        sound_cfg = {'silent': 'false'} if sound else {'silent': 'true'}
        t = threading.Thread(target=self._toast_thread, args=(title, message, sound_cfg))
        t.daemon = True
        t.start()
        
    def send_alert(self, title, message):
        # Sesli ve acil bildirimler için
        t = threading.Thread(target=self._toast_thread, args=(title, message, {'silent': 'false'}))
        t.daemon = True
        t.start()

class Handler(FileSystemEventHandler):
    def __init__(self, watcher_instance):
        self.watcher = watcher_instance
        self.temp_extensions = ('.tmp', '.crdownload', '.part', '.opdownload')

    def on_moved(self, event):
        if event.is_directory: return
        
        src_path = normalize_path(event.src_path)
        dest_path = normalize_path(event.dest_path)
        src_ext = os.path.splitext(src_path)[1]
        
        if src_ext not in self.temp_extensions:
            print(f"[*] İsim değişikliği algılandı (Atlanıyor): {os.path.basename(dest_path)}")
            return

        self.check_and_process(event.dest_path)

    def on_created(self, event):
        if not event.is_directory:
            self.check_and_process(event.src_path)

    def check_and_process(self, filepath):
        filepath = normalize_path(filepath)
        filename = os.path.basename(filepath)
        
        if filename.endswith(self.temp_extensions + ('.ini', '.log', '.tmp')):
            return

        self.start_thread(filepath)

    def start_thread(self, filepath):
        t = threading.Thread(target=self.process, args=(filepath,))
        t.daemon = True
        t.start()

    def process(self, filepath):
        filepath = normalize_path(filepath)
        filename = os.path.basename(filepath)
        
        with self.watcher.lock:
            if filepath in self.watcher.processed_files:
                return
            self.watcher.processed_files.add(filepath)

        if not self.wait_for_download(filepath):
            with self.watcher.lock:
                self.watcher.processed_files.remove(filepath)
            return

        print(f"[*] Analiz Ediliyor: {filename}")
        self.watcher.send_notification("İnceleniyor...", f"{filename} kontrol ediliyor.", sound=False)
        
        file_hash = self.calculate_sha256(filepath)
        if file_hash:
            self.check_virustotal(file_hash, filepath)

    def wait_for_download(self, filepath, timeout=30):
        start = time.time()
        last_size = -1
        stable = 0
        while time.time() - start < timeout:
            try:
                if not os.path.exists(filepath): return False
                size = os.path.getsize(filepath)
                if size == 0: 
                    time.sleep(0.5)
                    continue
                if size == last_size:
                    stable += 1
                else:
                    stable = 0
                last_size = size
                if stable >= 2: return True
                time.sleep(0.5)
            except:
                time.sleep(0.5)
        return False

    def calculate_sha256(self, filepath):
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return None

    def check_virustotal(self, file_hash, filepath):
        headers = {'x-apikey': API_KEY}
        try:
            response = requests.get(f"{VT_BASE_URL}/files/{file_hash}", headers=headers)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                self.alert_user(stats, filepath)
            elif response.status_code == 404:
                print(f"    -> Bilinmiyor, upload ediliyor: {os.path.basename(filepath)}")
                self.watcher.send_notification("Bilinmeyen Dosya", "Dosya sunucuya yükleniyor...", sound=False)
                self.upload_and_scan(filepath)
        except Exception as e:
            print(f"    -> Hata: {e}")

    def upload_and_scan(self, filepath):
        try:
            size = os.path.getsize(filepath)
            if size > (MAX_FILE_SIZE_MB * 1024 * 1024):
                self.watcher.send_notification("Hata", "Dosya 32MB limitini aşıyor.", sound=True)
                return
            with open(filepath, 'rb') as f:
                files = {'file': (os.path.basename(filepath), f)}
                resp = requests.post(f"{VT_BASE_URL}/files", headers={'x-apikey': API_KEY}, files=files)
            if resp.status_code == 200:
                self.poll_analysis(resp.json()['data']['id'], filepath)
        except: pass

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

    def alert_user(self, stats, filepath):
        malicious = stats['malicious']
        filename = os.path.basename(filepath)
        if malicious > 0:
            msg = f"{malicious} motor zararlı buldu!"
            print(f"    -> ZARARLI: {msg}")
            self.watcher.send_alert("⚠️ TEHDİT ALGILANDI", msg)
        else:
            print(f"    -> Temiz: {filename}")
            self.watcher.send_notification("✅ Dosya Temiz", f"{filename} güvenli.", sound=False)

if __name__ == '__main__':
    w = Watcher(WATCH_DIRECTORY)
    w.run()