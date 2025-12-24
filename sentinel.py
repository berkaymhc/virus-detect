import time
import hashlib
import requests
import os
import logging
from dotenv import load_dotenv # YENİ
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from plyer import notification

# --- KONFIGURASYON ---
load_dotenv() # .env dosyasını yükler

API_KEY = os.getenv('VT_API_KEY') # Key'i ortam değişkeninden çeker
WATCH_DIRECTORY = r'C:\Users\berka\Downloads'
VT_BASE_URL = 'https://www.virustotal.com/api/v3'
MAX_FILE_SIZE_MB = 32

# API Key Kontrolü
if not API_KEY:
    print("HATA: .env dosyası bulunamadı veya VT_API_KEY tanımlı değil!")
    exit()

# Loglama ayarı (Önceki adımdan)
logging.basicConfig(filename='sentinel_log.txt', level=logging.INFO, 
                    format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

class Watcher:
    def __init__(self, directory):
        self.observer = Observer()
        self.directory = directory
        self.processed_files = {} # Dedup Cache: {filepath: timestamp}

    def run(self):
        event_handler = Handler(self)
        self.observer.schedule(event_handler, self.directory, recursive=False)
        self.observer.start()
        print(f"[+] Sentinel devrede. İzlenen klasör: {self.directory}")
        print(f"[+] Upload Limiti: {MAX_FILE_SIZE_MB} MB")
        try:
            while True:
                time.sleep(2)
                # Cache temizliği (10 dakikadan eski kayıtları sil)
                current_time = time.time()
                keys_to_delete = [k for k, v in self.processed_files.items() if current_time - v > 600]
                for k in keys_to_delete:
                    del self.processed_files[k]
        except KeyboardInterrupt:
            self.observer.stop()
        self.observer.join()

class Handler(FileSystemEventHandler):
    def __init__(self, watcher_instance):
        self.watcher = watcher_instance

    def on_moved(self, event):
        if not event.is_directory:
            self.process(event.dest_path)

    def on_created(self, event):
        if not event.is_directory:
            self.process(event.src_path)

    def process(self, filepath):
        filename = os.path.basename(filepath)
        
        # Filtreler
        if filename.endswith(('.tmp', '.crdownload', '.part', '.ini', '.opdownload')):
            return

        # Deduplication (Çift taramayı engelle)
        if filepath in self.watcher.processed_files:
            return
        
        print(f"[*] İzleniyor: {filename}")

        if self.wait_for_download_completion(filepath):
            # Dosyayı işlendi olarak işaretle
            self.watcher.processed_files[filepath] = time.time()
            
            print(f"    -> Analiz başlıyor: {filename}")
            file_hash = self.calculate_sha256(filepath)
            
            if file_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
                return # Boş dosya

            if file_hash:
                print(f"    -> HASH: {file_hash}")
                self.check_virustotal(file_hash, filepath)
        else:
            print("    -> ZAMAN AŞIMI: Dosya tamamlanamadı.")

    def wait_for_download_completion(self, filepath, timeout=60):
        start_time = time.time()
        last_size = -1
        stable_count = 0
        
        while time.time() - start_time < timeout:
            try:
                if not os.path.exists(filepath): return False
                current_size = os.path.getsize(filepath)
                if current_size == 0:
                    time.sleep(1)
                    continue
                if current_size == last_size:
                    stable_count += 1
                else:
                    stable_count = 0
                    print(f"    -> İndiriliyor... ({current_size} bytes)")
                
                last_size = current_size
                if stable_count >= 2: return True
                time.sleep(1)
            except OSError:
                time.sleep(1)
        return False

    def calculate_sha256(self, filepath):
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return None

    def check_virustotal(self, file_hash, filepath):
        headers = {'x-apikey': API_KEY}
        try:
            # 1. Önce Hash ile sor
            response = requests.get(f"{VT_BASE_URL}/files/{file_hash}", headers=headers)
            
            if response.status_code == 200:
                self.handle_report(response.json(), filepath)
            elif response.status_code == 404:
                print("    -> Dosya veritabanında yok. Upload işlemine geçiliyor...")
                self.upload_and_scan(filepath)
            else:
                print(f"    -> API Hatası: {response.status_code}")
                
        except Exception as e:
            print(f"    -> BAĞLANTI HATASI: {e}")

    def upload_and_scan(self, filepath):
        # Boyut kontrolü
        file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
        if file_size_mb > MAX_FILE_SIZE_MB:
            print(f"    -> HATA: Dosya çok büyük ({file_size_mb:.2f} MB). Upload limiti {MAX_FILE_SIZE_MB} MB.")
            self.notify("⚠️ Taranamadı", "Dosya boyutu limitin üzerinde.")
            return

        headers = {'x-apikey': API_KEY}
        try:
            with open(filepath, 'rb') as file_obj:
                files = {'file': (os.path.basename(filepath), file_obj)}
                print("    -> Upload ediliyor... (Lütfen bekleyin)")
                response = requests.post(f"{VT_BASE_URL}/files", headers=headers, files=files)
            
            if response.status_code == 200:
                analysis_id = response.json()['data']['id']
                print(f"    -> Upload başarılı. Analiz ID: {analysis_id}")
                self.poll_analysis(analysis_id, filepath)
            else:
                print(f"    -> Upload Hatası: {response.status_code} - {response.text}")

        except Exception as e:
            print(f"    -> UPLOAD HATASI: {e}")

    def poll_analysis(self, analysis_id, filepath):
        print("    -> Analiz sonucu bekleniyor...", end="", flush=True)
        headers = {'x-apikey': API_KEY}
        
        # 60 saniye boyunca sonucu bekle
        for _ in range(12): 
            time.sleep(5)
            print(".", end="", flush=True)
            try:
                response = requests.get(f"{VT_BASE_URL}/analyses/{analysis_id}", headers=headers)
                if response.status_code == 200:
                    status = response.json()['data']['attributes']['status']
                    if status == 'completed':
                        print(" Tamamlandı!")
                        stats = response.json()['data']['attributes']['stats']
                        self.alert_user(stats, filepath)
                        return
            except:
                pass
        
        print("\n    -> Zaman aşımı: Analiz sunucu tarafında hala sürüyor.")
        self.notify("⏳ Analiz Sürüyor", "Sonuçlar gecikti, daha sonra VT üzerinden kontrol edin.")

    def handle_report(self, json_data, filepath):
        stats = json_data['data']['attributes']['last_analysis_stats']
        self.alert_user(stats, filepath)

    def alert_user(self, stats, filepath):
        malicious = stats['malicious']
        filename = os.path.basename(filepath)
        
        if malicious > 0:
            msg = f"TEHLİKE! {malicious} motor zararlı buldu!"
            print(f"\n    -> SONUÇ: {msg}")
            self.notify("⚠️ ZARARLI YAZILIM", msg)
        else:
            msg = "Dosya temiz."
            print(f"\n    -> SONUÇ: {msg}")
            self.notify("✅ Dosya Temiz", f"{filename} güvenli.")

    def notify(self, title, message):
        try:
            notification.notify(title=title, message=message, app_name='Sentinel', timeout=10)
        except:
            pass

if __name__ == '__main__':
    w = Watcher(WATCH_DIRECTORY)
    w.run()