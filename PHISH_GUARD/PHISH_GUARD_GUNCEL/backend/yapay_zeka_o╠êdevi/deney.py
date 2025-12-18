'''import joblib

# 1. Modeli yükle
model = joblib.load("turkish_spam_model.pkl")
print("✅ Model başarıyla yüklendi!")

# 2. Etiket sözlüğü (0 = normal, 1 = spam)
labels = {0: "normal", 1: "spam"}

# 3. Test etmek istediğin birkaç örnek
test_messages = [
    "Bu mesaj size özel indirim kazandırdı, hemen tıklayın!",  # spam beklenir
    "Merhaba, yarınki toplantı saatini teyit edebilir miyiz?", # normal beklenir
    "Kazandınız! Hemen tıklayın ve ödülünüzü alın.",           # spam beklenir
    "Hocam ödevin teslim tarihi tam olarak ne zamandı?",        # normal beklenir
    "Merhaba nasılsın?"
]

# 4. Tahmin yap
predictions = model.predict(test_messages)

# 5. Sonuçları yazdır
for msg, pred in zip(test_messages, predictions):
    print("\nMesaj:", msg)
    print("Tahmin:", labels[pred])'''
import joblib
import re

# =====================
# Ayarlar
# =====================
MODEL_PATH = "spam_model_FINAL_calibrated.joblib"
THRESHOLD = 0.35   # spam kaçırmayalım diye düşük

# =====================
# Modeli yükle
# =====================
model = joblib.load(MODEL_PATH)

def clean(text: str) -> str:
    text = str(text).lower()
    text = re.sub(r"http\S+|www\.\S+", "<URL>", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

print("\n✅ FINAL model yüklendi")
print("Çıkmak için 'q' yaz\n")

# =====================
# Canlı test döngüsü
# =====================
while True:
    msg = input("Mesaj gir: ")

    if msg.lower() == "q":
        print("Çıkılıyor...")
        break

    p_spam = model.predict_proba([clean(msg)])[0][1]

    karar = "SPAM / PHISHING" if p_spam >= THRESHOLD else "NORMAL"

    print(f"\n{karar}")
    print(f"spam:   %{p_spam*100:.2f}")
    print(f"normal: %{(1-p_spam)*100:.2f}\n")
