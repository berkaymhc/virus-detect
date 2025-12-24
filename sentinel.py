import time
import hashlib
import requests
import os
import logging
import threading
from dotenv import load_dotenv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from plyer import notification

# --- KONFIGURASYON ---
load_dotenv()
API_KEY = os.getenv('VT_API_KEY')
WATCH_DIRECTORY = r'C:\Users\berka\Downloads'
VT_BASE_URL = 'https://www.virustotal.com/api/v3'
MAX_FILE_SIZE_MB = 32

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
        self.directory = directory
        self.processed_files = set() # Set, listeden daha hızlıdır
        self.lock = threading.Lock() # Thread güvenliği için kilit

    def run(self):
        event_handler = Handler(self)
        self.observer.schedule(event_handler, self.directory, recursive=False)
        self.observer.start()
        print(f"[+] Sentinel (Turbo Mod) devrede. Klasör: {self.directory}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.observer.stop()
        self.observer.join()

class Handler(FileSystemEventHandler):
    def __init__(self, watcher_instance):
        self.watcher = watcher_instance

    def on_moved(self, event):
        if not event.is_directory:
            self.start_thread(event.dest_path)

    def on_created(self, event):
        if not event.is_directory:
            self.start_thread(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.start_thread(event.src_path)

    def start_thread(self, filepath):
        # Her dosya için ayrı bir iş parçacığı (Thread) başlat
        # Bu sayede ana program asla donmaz.
        t = threading.Thread(target=self.process, args=(filepath,))
        t.daemon = True # Ana program kapanınca thread'ler de kapansın
        t.start()

    def process(self, filepath):
        filepath = normalize_path(filepath)
        filename = os.path.basename(filepath)
        
        if filename.endswith(('.tmp', '.crdownload', '.part', '.ini', '.opdownload', '.log')):
            return

        # Thread Safe (Güvenli) Kontrol
        with self.watcher.lock:
            if filepath in self.watcher.processed_files:
                return
            self.watcher.processed_files.add(filepath)

        # İndirme bitene kadar bekle (Bloklamadan)
        if not self.wait_for_download(filepath):
            with self.watcher.lock:
                self.watcher.processed_files.remove(filepath)
            return

        # Kullanıcıya "Gördüm" mesajı ver (Anında tepki)
        print(f"[*] Analiz Ediliyor: {filename}")
        
        file_hash = self.calculate_sha256(filepath)
        if not file_hash: return

        # API Sorgusu
        self.check_virustotal(file_hash, filepath)

    def wait_for_download(self, filepath, timeout=30):
        # Bekleme süresini ve kontrol sıklığını hızlandırdım
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
                time.sleep(0.5) # Yarım saniyede bir kontrol
            except:
                time.sleep(0.5)
        return False

    def calculate_sha256(self, filepath):
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""): # Okuma hızını artırdım (64KB Chunk)
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return None

    def check_virustotal(self, file_hash, filepath):
        headers = {'x-apikey': API_KEY}
        try:
            # 1. HIZLI KONTROL: Sadece Hash sor
            response = requests.get(f"{VT_BASE_URL}/files/{file_hash}", headers=headers)
            
            if response.status_code == 200:
                # BULDUM! Anında sonuç.
                self.handle_report(response.json(), filepath)
            elif response.status_code == 404:
                # Dosya yok. Upload gerekiyor.
                print(f"    -> {os.path.basename(filepath)} bilinmiyor. Upload ediliyor...")
                self.notify("Bilinmeyen Dosya", "Dosya VT'ye yükleniyor, sonuç birazdan gelir.")
                self.upload_and_scan(filepath)
            else:
                print(f"    -> API Hatası: {response.status_code}")
                
        except Exception as e:
            print(f"    -> Hata: {e}")

    def upload_and_scan(self, filepath):
        # Bu fonksiyon artık arka planda çalışıyor, kullanıcıyı bekletmez.
        try:
            if os.path.getsize(filepath) > (MAX_FILE_SIZE_MB * 1024 * 1024):
                self.notify("Hata", "Dosya 32MB limitini aşıyor.")
                return

            with open(filepath, 'rb') as f:
                files = {'file': (os.path.basename(filepath), f)}
                resp = requests.post(f"{VT_BASE_URL}/files", headers={'x-apikey': API_KEY}, files=files)
            
            if resp.status_code == 200:
                analysis_id = resp.json()['data']['id']
                self.poll_analysis(analysis_id, filepath)
            else:
                print(f"    -> Upload Başarısız: {resp.status_code}")
        except:
            pass

    def poll_analysis(self, analysis_id, filepath):
        # Arka planda sessizce bekle
        headers = {'x-apikey': API_KEY}
        for _ in range(60): # 5 dakika boyunca dene
            time.sleep(5)
            try:
                resp = requests.get(f"{VT_BASE_URL}/analyses/{analysis_id}", headers=headers)
                if resp.status_code == 200:
                    status = resp.json()['data']['attributes']['status']
                    if status == 'completed':
                        stats = resp.json()['data']['attributes']['stats']
                        self.alert_user(stats, filepath)
                        return
            except:
                pass

    def handle_report(self, json_data, filepath):
        stats = json_data['data']['attributes']['last_analysis_stats']
        self.alert_user(stats, filepath)

    def alert_user(self, stats, filepath):
        malicious = stats['malicious']
        filename = os.path.basename(filepath)
        
        if malicious > 0:
            msg = f"TEHLİKE! {malicious} motor zararlı buldu!"
            print(f"    -> SONUÇ: {msg}")
            self.notify("⚠️ ZARARLI TESPİT EDİLDİ", msg)
        else:
            print(f"    -> Temiz: {filename}")
            self.notify("✅ Temiz", f"{filename} güvenli.")

    def notify(self, title, message):
        try:
            notification.notify(title=title, message=message, app_name='Sentinel', timeout=5)
        except:
            pass

if __name__ == '__main__':
    w = Watcher(WATCH_DIRECTORY)
    w.run()