import joblib
import numpy as np
import re
from urllib.parse import urlparse
from difflib import SequenceMatcher
import os

# --- MODELİ YÜKLEME ---
# Bu kod, model dosyasını otomatik olarak bu dosyanın yanında arar.
current_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(current_dir, "phishing_modeli.pkl")

try:
    model = joblib.load(model_path)
    model_yuklendi = True
except FileNotFoundError:
    model_yuklendi = False
    print(f"HATA: Model dosyası bulunamadı: {model_path}")


# --- YARDIMCI FONKSİYON: ÖZELLİK ÇIKARMA ---
def feature_extraction(url):
    features = []
    if not re.match(r"^https?", url):
        url = "http://" + url
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # 1. IP
    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
        features.append(-1)
    else:
        features.append(1)
    # 2. Uzunluk
    if len(url) < 54:
        features.append(1)
    elif 54 <= len(url) <= 75:
        features.append(0)
    else:
        features.append(-1)
    # 3. Kısaltma
    if re.search(r"bit\.ly|goo\.gl|tinyurl|is\.gd|cli\.gs", url):
        features.append(-1)
    else:
        features.append(1)
    # 4. @ İşareti
    if "@" in url:
        features.append(-1)
    else:
        features.append(1)
    # 5. Çift Slash
    if url.rfind("//") > 7:
        features.append(-1)
    else:
        features.append(1)
    # 6. Tire (-)
    if "-" in domain:
        features.append(-1)
    else:
        features.append(1)
    # 7. SSL
    if parsed_url.scheme == "https":
        features.append(1)
    else:
        features.append(-1)
    # 8. Domain Yaşı
    features.append(1)
    # 9. HTTPS Token
    if "https" in domain:
        features.append(-1)
    else:
        features.append(1)

    return np.array(features).reshape(1, -1)


# --- ANA FONKSİYON (Ekibin Çağıracağı Yer) ---
def tahmin_et(url):
    """
    Girdi: URL String
    Çıktı: Sözlük (Dictionary) -> {'score': 0-100, 'label': '...', 'reasons': [...]}
    """
    if not model_yuklendi:
        return {
            "score": 0,
            "label": "error",
            "reasons": ["Sistem Hatası: Model Yüklenemedi"],
            "notes": "offline-analysis"
        }

    reasons = []
    score = 0
    
    # 1. URL Ön İşleme
    if not re.match(r"^https?", url):
        url_check = "http://" + url
    else:
        url_check = url
        
    try:
        parsed = urlparse(url_check)
        domain = parsed.netloc
        
        # 2. HEURISTIC KONTROLLER (Kurallar)
        
        # IP Adresi Kontrolü
        if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
            reasons.append("Alan adı yerine IP adresi kullanımı")
            score += 40

        # Kısaltma Servisi Kontrolü
        if re.search(r"bit\.ly|goo\.gl|tinyurl|is\.gd|cli\.gs|t\.co", url_check):
            reasons.append("URL kısaltma servisi kullanılmış")
            score += 20

        # HTTPS "kelimesi" domain içinde (aldatmaca)
        if "https" in domain and not domain.startswith("https"):
             # domain "https-login.com" gibi ise
            reasons.append("Alan adında güven uyandırmak için 'https' ifadesi geçiyor")
            score += 30
            
        # Çok Uzun URL
        if len(url_check) > 75:
            reasons.append("Olağandışı URL uzunluğu")
            score += 10
            
        # @ işareti (Tarayıcıyı kandırma)
        if "@" in url_check:
            reasons.append("URL içinde '@' karakteri kullanımı (kimlik gizleme şüphesi)")
            score += 50
            
        # Kritik Kelimeler
        supheli_kelimeler = [
            "login", "signin", "verify", "secure", "account", "update", "bank", "wallet", 
            "confirm", "bonus", "free", "gift", "service", "support", "auth", "pay", "win"
        ]
        found_keywords = [k for k in supheli_kelimeler if k in domain or k in parsed.path]
        if found_keywords:
            reasons.append(f"Şüpheli anahtar kelimeler: {', '.join(found_keywords)}")
            score += 25

        # 3. YAPAY ZEKA KONTROLÜ
        # Model 1 (Phishing) veya 0 (Safe) döner, ama biz olasılık bulmak istiyoruz.
        # predict_proba yoksa 0/1 üzerinden puan ekle.
        try:
            features = feature_extraction(url_check)
            prediction = model.predict(features)[0]
            if prediction == -1 or prediction == 0: # Modelin -1 veya 0 döndürme durumuna göre (önceki kodda 1=safe, diğerleri risky idi)
                 # Önceki kod: 1 safe, diğerleri risky (muhtemelen -1)
                 # Kontrol edelim: eski kodda "if prediction == 1: return safe"
                pass 
            else:
                 # Eski kod mantığı: 1 safe ise, 1 olmayan risktir.
                 # Ancak Feature Extraction kısmında -1 ve 1 kullanılıyor.
                 # Biz yine de modele güvenelim.
                 pass
            
            # Model sonucu entegrasyonu
            # Not: Modelin 'predict' çıktısı feature extraction ile uyumlu olmalı.
            # Eski kodda if prediction == 1 -> Safe.
            if prediction != 1:
                reasons.append("Yapay Zeka modeli oltalama belirtileri tespit etti")
                score += 40
            
        except Exception as e:
            print(f"Model hatası: {e}")

        # Skor Normalizasyonu (0-100)
        score = min(score, 100)
        
        # Etiketleme
        label = "safe"
        if score > 70:
            label = "malicious"
        elif score > 30:
            label = "suspicious"
            
        if score == 0 and not reasons:
            reasons.append("Belirgin bir tehdit bulunamadı")
        
        # Maksimum 6 neden kısıtlaması
        reasons = reasons[:6]

        return {
            "score": score,
            "label": label,
            "reasons": reasons,
            "notes": "offline-analysis"
        }

    except Exception as e:
        return {
            "score": 0,
            "label": "error",
            "reasons": [f"Analiz hatası: {str(e)}"],
            "notes": "offline-error"
        }
