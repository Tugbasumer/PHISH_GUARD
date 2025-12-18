from flask import Flask, request, jsonify
from flask_cors import CORS
import ai_modulu  # Senin hazırladığın zeka modülü

app = Flask(__name__)
CORS(app)  # JavaScript'in bu koda erişmesine izin verir (Çok Önemli!)


@app.route("/kontrol-et", methods=["POST"])
def kontrol_et():
    # 1. JavaScript'ten gelen veriyi al
    veri = request.get_json()
    gelen_url = veri.get("url")

    if not gelen_url:
        return jsonify({"mesaj": "URL boş olamaz!", "renk": "gray", "durum": 0})

    # 2. Senin modülünü (Polis + Yapay Zeka) çalıştır
    sonuc = ai_modulu.tahmin_et(gelen_url)

    # 3. Sonucu JavaScript'e geri gönder
    return jsonify(sonuc)


if __name__ == "__main__":
    print("Python API çalışıyor...")
    app.run(port=5000)
