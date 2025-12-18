import requests
import json
import time

BASE_URL = "http://127.0.0.1:8000"

def test_url_analysis():
    print("\n--- Testing URL Analysis ---")
    payload = {"url": "http://secure-login.paypal-update.com@192.168.1.1/login"}
    try:
        response = requests.post(f"{BASE_URL}/analyze-url", json=payload)
        response.raise_for_status()
        data = response.json()
        print(json.dumps(data, indent=2))
        
        assert "score" in data
        assert "reasons" in data
        assert len(data["reasons"]) > 0
        print("✅ URL Analysis Passed Structure Check")
    except Exception as e:
        print(f"❌ URL Analysis Failed: {e}")

def test_email_analysis():
    print("\n--- Testing Email Analysis ---")
    payload = {"text": "URGENT: Dear User, please verify your password immediately to claim your bitcoin prize and gift card!"}
    try:
        response = requests.post(f"{BASE_URL}/analyze", json=payload)
        response.raise_for_status()
        data = response.json()
        print(json.dumps(data, indent=2))
        
        assert "score" in data
        assert "reasons" in data
        assert data["label"] in ["spam", "phishing"]
        print("✅ Email Analysis Passed Structure Check")
    except Exception as e:
        print(f"❌ Email Analysis Failed: {e}")

if __name__ == "__main__":
    # Wait a bit for server to be fully ready if just started
    time.sleep(2) 
    test_url_analysis()
    test_email_analysis()
