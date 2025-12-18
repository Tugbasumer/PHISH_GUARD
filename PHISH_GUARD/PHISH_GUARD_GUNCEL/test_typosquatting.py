
import sys
sys.path.append('backend')
from makineogr.ai_modulu import tahmin_et

test_urls = [
    "https://google.com",              # Safe
    "https://www.google.com",          # Safe
    "https://goossgle.com",            # Typosquatting
    "http://www.facebook-login.com",   # Keyword + Typosquatting maybe
    "https://secure-paypaal.com",      # Typosquatting (paypaal vs paypal.com)
    "https://random-site.com",         # Unknown -> AI
]

print("Testing Typosquatting Detection...")
for url in test_urls:
    print(f"\nURL: {url}")
    result = tahmin_et(url)
    print(f"Result: {result}")
