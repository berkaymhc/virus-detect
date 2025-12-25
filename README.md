# 🛡️ Virus Detect Sentinel

**Virus Detect**, indirilen dosyaları anlık olarak izleyen, **VirusTotal** altyapısını kullanarak tarayan ve zararlı yazılımları otomatik olarak karantinaya alan bir güvenlik aracıdır.

![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)
![VirusTotal](https://img.shields.io/badge/API-VirusTotal-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Durum-Aktif-success?style=for-the-badge)

## 🚀 Özellikler

* **Anlık İzleme:** `Downloads` klasörüne inen dosyaları saniyesinde yakalar.
* **Otomatik Tarama:** Dosya hash'ini (SHA256) alır ve VirusTotal veritabanında sorgular.
* **Akıllı Karantina:** Zararlı dosya tespit edilirse anında `Karantina` klasörüne taşır ve kilitler.
* **Bildirim Sistemi:**
    * 🔔 **Windows Bildirimi:** Masaüstünde anlık uyarı verir.
    * 📱 **Telegram Entegrasyonu:** Virüs bulunduğunda veya hata alındığında telefonunuza rapor gönderir.
* **Kolay Kurulum:** İlk açılışta API Key isteyen kullanıcı dostu arayüz (GUI).

## 🛠️ Kurulum

Proje kaynak kodunu indirdikten sonra aşağıdaki adımları izleyin:

1.  **Gereksinimleri Yükleyin:**
    ```bash
    pip install -r requirements.txt
    ```

2.  **Uygulamayı Başlatın:**
    ```bash
    python sentinel.py
    ```

3.  **Aktivasyon:**
    * Açılan pencerede **VirusTotal API Key**'inizi girin.
    * Eğer keyiniz yoksa "Kayıt Sayfasını Aç" butonu ile ücretsiz alabilirsiniz.

## ⚙️ Yapılandırma

Program ilk çalıştığında bir `.env` dosyası oluşturur ve API anahtarınızı burada saklar.
Telegram bildirimlerini aktif etmek için kod içerisindeki şu alanları kendi bilgilerinizle doldurun:

```python
TELEGRAM_BOT_TOKEN = "SIZIN_BOT_TOKENINIZ"
TELEGRAM_CHAT_ID = "SIZIN_CHAT_IDNIZ"