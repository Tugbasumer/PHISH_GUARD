import re

def analyze_email_offline(text, spam_model=None):
    """
    Offline Email Analysis utilizing Heuristics + Weak ML Model check
    """
    reasons = []
    score = 0
    
    # Text Preprocessing
    text_lower = text.lower()
    
    # --- HEURISTICS ---
    
    # 1. Urgency / Threat Language
    urgency_keywords = [
        "urgent", "immediately", "action required", "account suspended", 
        "unauthorized access", "terminate", "lock your account", "final notice",
        "acil", "hemen", "hesabınız askıya", "uyarı", "son kez"
    ]
    urgency_matches = [w for w in urgency_keywords if w in text_lower]
    if urgency_matches:
        reasons.append(f"Aciliyet veya tehdit içeren dil: {', '.join(urgency_matches[:3])}")
        score += 30
        
    # 2. Sensitive Information Request
    sensitive_keywords = [
        "password", "credit card", "security code", "cvv", "social security", 
        "verify your identity", "otp", "banking details",
        "şifre", "parola", "kredi kartı", "kimlik doğrulama"
    ]
    sensitive_matches = [w for w in sensitive_keywords if w in text_lower]
    if sensitive_matches:
        reasons.append("Hassas bilgi (şifre/kimlik) talebi tespit edildi")
        score += 40
        
    # 3. Reward / Money / Crypto
    reward_keywords = [
        "won", "winner", "lottery", "prize", "claim your reward", 
        "bitcoin", "crypto", "inheritance", "million dollars", "gift card",
        "kazandınız", "ödül", "piyango", "miras", "hediye çeki"
    ]
    reward_matches = [w for w in reward_keywords if w in text_lower]
    if reward_matches:
        reasons.append("Gerçekçi olmayan ödül veya para vaadi")
        score += 25
        
    # 4. Brand Impersonation (Generic)
    # Checks for "Dear Customer" or generic greetings often used in phishing
    first_few_words = text_lower[:50]
    if "dear customer" in first_few_words or "dear user" in first_few_words or "sayın müşteri" in first_few_words:
        reasons.append("Genel hitap kullanımı (Sayın Müşteri vb.)")
        score += 15
        
    # 5. Grammar / Formatting (Basic Caps Lock check)
    # Check if a significant portion of the text is uppercase (shouting)
    if len(text) > 20:
        uppercase_ratio = sum(1 for c in text if c.isupper()) / len(text)
        if uppercase_ratio > 0.4:
            reasons.append("Anormal büyük harf kullanımı (Bağırma tonu)")
            score += 10
            
    # 6. Suspicious Links in text (Regex find HTTP)
    if "http" in text_lower:
         pass # Handled by URL scanner usually, but good to note
         
    # --- MODEL CHECK ---
    if spam_model:
        try:
            # Assuming model.predict returns 1 for Spam
            prediction = spam_model.predict([text])[0]
            if prediction == 1:
                reasons.append("Yapay Zeka spam/phishing modeli pozitif sonuç verdi")
                score += 30
        except Exception:
            pass
            
    # Normalize Score
    score = min(score, 100)
    
    # Labeling
    label = "ham"
    if score > 70:
        label = "phishing"
    elif score > 30:
        label = "spam"
        
    if score == 0 and not reasons:
        reasons.append("Güvenli görünüyor")
        
    return {
        "score": score,
        "label": label,
        "reasons": reasons[:6],
        "notes": "offline-analysis"
    }
