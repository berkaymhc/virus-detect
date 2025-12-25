import time
import hashlib
import requests
import os
import logging
import threading
import shutil
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
QUARANTINE_DIR = os.path.join(BASE_DIR, 'Karantina')

if os.path.exists(ICON_PATH):
    print("[BAŞARILI] İkon bulundu.")
    TOAST_ICON = {'src': ICON_PATH, 'placement': 'appLogoOverride'}
else:
    TOAST_ICON = None

if not API_KEY:
    print("HATA: .env dosyası eksik!")
    exit()

# --- LOG AYARLARI ---
logging.basicConfig(
    filename='sentinel_log.txt', 
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s', 
    datefmt='%Y-%m-%d %H:%M:%S',
    encoding='utf-8'
)

def normalize_path(path):
    return os.path.normpath(os.path.abspath(path)).lower()

class Watcher:
    def __init__(self, directory):
        self.observer = Observer()
        self.directory = normalize_path(directory)
        
        # SÖZLÜK YAPISI: { 'dosya_yolu': son_tarama_zamanı }
        self.processed_files = {} 
        self.lock = threading.Lock()
        
        if not os.path.exists(QUARANTINE_DIR):
            os.makedirs(QUARANTINE_DIR)

    def run(self):
        event_handler = Handler(self)
        self.observer.schedule(event_handler, self.directory, recursive=False)
        self.observer.start()
        
        msg = f"{APP_NAME} devrede. Klasör: {self.directory}"
        print(f"\n[+] {msg}")
        logging.info(msg)
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.observer.stop()
        self.observer.join()

    def _toast_thread(self, title, message, sound_cfg):
        try:
            if TOAST_ICON:
                toast(title, message, app_id=APP_NAME, icon=TOAST_ICON, audio=sound_cfg)
            else:
                toast(title, message, app_id=APP_NAME, audio=sound_cfg)
        except Exception as e:
            logging.error(f"Bildirim Hatası: {e}")

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
            
            msg = f"Karantinaya alındı: {filename}"
            print(f"    -> [KARANTİNA] {msg}")
            logging.warning(f"DOSYA KARANTİNAYA ALINDI: {dest_path}")
            
            self.send_alert("🚫 DOSYA ENGELLENDİ", f"{filename} karantinaya taşındı.")
            return True
        except Exception as e:
            logging.critical(f"Karantina Hatası: {e}")
            return False

class Handler(FileSystemEventHandler):
    def __init__(self, watcher_instance):
        self.watcher = watcher_instance
        self.temp_extensions = ('.tmp', '.crdownload', '.part', '.opdownload')
        # COOLDOWN SÜRESİ (Saniye) - Aynı dosyayı tekrar taramak için bekleme süresi
        self.SCAN_COOLDOWN = 5.0 

    def on_deleted(self, event):
        if event.is_directory: return
        path = normalize_path(event.src_path)
        with self.watcher.lock:
            # Dosya silinirse hafızadan temizle ki tekrar indirilirse taranabilsin
            if path in self.watcher.processed_files:
                self.watcher.processed_files.pop(path, None)

    def on_moved(self, event):
        if event.is_directory: return
        src_path = normalize_path(event.src_path)
        src_ext = os.path.splitext(src_path)[1]
        
        if src_ext not in self.temp_extensions:
            return

        self.check_and_process(event.dest_path)

    def on_created(self, event):
        if not event.is_directory:
            self.check_and_process(event.src_path)
            
    def on_modified(self, event):
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
        current_time = time.time()

        with self.watcher.lock:
            # --- COOLDOWN (SOĞUMA) KONTROLÜ ---
            # Eğer dosya daha önce tarandıysa...
            if filepath in self.watcher.processed_files:
                last_scan_time = self.watcher.processed_files[filepath]
                # Ve son taramanın üzerinden 5 saniye geçmediyse...
                if (current_time - last_scan_time) < self.SCAN_COOLDOWN:
                    # HİÇBİR ŞEY YAPMA, ÇIK.
                    return
            
            # Listeyi güncelle (Şu an tarıyoruz)
            self.watcher.processed_files[filepath] = current_time

        if not self.wait_for_download(filepath):
            with self.watcher.lock:
                self.watcher.processed_files.pop(filepath, None)
            return

        print(f"[*] Analiz Ediliyor: {filename}")
        logging.info(f"ANALİZ BAŞLADI: {filename}")
        
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
        except Exception:
            return None

    def check_virustotal(self, file_hash, filepath):
        headers = {'x-apikey': API_KEY}
        filename = os.path.basename(filepath)
        try:
            response = requests.get(f"{VT_BASE_URL}/files/{file_hash}", headers=headers)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                self.alert_user(stats, filepath)
            elif response.status_code == 404:
                print(f"    -> Bilinmiyor, upload ediliyor: {filename}")
                logging.info(f"DOSYA BİLİNMİYOR (Upload Gerekli): {filename}")
                self.watcher.send_notification("Bilinmeyen Dosya", "Dosya sunucuya yükleniyor...", sound=False)
                self.upload_and_scan(filepath)
            else:
                logging.error(f"API Hatası ({response.status_code}): {filename}")
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
            if resp.status_code == 200:
                self.poll_analysis(resp.json()['data']['id'], filepath)
            else:
                logging.error(f"Upload Başarısız ({resp.status_code})")
        except Exception as e:
             logging.error(f"Upload Exception: {e}")

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
        logging.warning(f"Zaman Aşımı (Analiz bitmedi): {os.path.basename(filepath)}")

    def alert_user(self, stats, filepath):
        malicious = stats['malicious']
        filename = os.path.basename(filepath)
        
        if malicious > 0:
            msg = f"{malicious} motor zararlı buldu!"
            print(f"    -> ZARARLI TESPİT EDİLDİ: {msg}")
            logging.warning(f"TEHDİT ALGILANDI: {filename} - Skor: {malicious}")
            self.watcher.quarantine_file(filepath)
        else:
            print(f"    -> Temiz: {filename}")
            logging.info(f"TEMİZ: {filename}")
            self.watcher.send_notification("✅ Dosya Temiz", f"{filename} güvenli.", sound=False)

if __name__ == '__main__':
    w = Watcher(WATCH_DIRECTORY)
    w.run()