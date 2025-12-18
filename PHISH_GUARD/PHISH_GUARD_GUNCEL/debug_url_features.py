import sys
sys.path.append('backend')
from makineogr.ai_modulu import feature_extraction, tahmin_et
import numpy as np

urls_to_test = [
    "http://google.com",
    "http://secure-login-apple.com", # Dash in domain (Feature 6 -> -1)
    "https://www.paypal.com.cgi-bin.webscr.cmd-login-submit.dispatch-5885d80a13c0db1f8e263663d3faee8d4fe8684/login", # Long (Feature 2 -> -1)
    "http://192.168.1.1/login", # IP (Feature 1 -> -1)
    "https://short.ly/xyz", # Shortener (Feature 3 might catch this if regex matches)
]

print("Testing URLs...")
for url in urls_to_test:
    print(f"\n--- URL: {url} ---")
    features = feature_extraction(url)
    print(f"Features: {features}")
    
    result = tahmin_et(url)
    print(f"Result: {result}")
