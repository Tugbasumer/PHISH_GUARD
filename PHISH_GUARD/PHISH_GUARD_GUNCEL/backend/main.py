from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from models import UserLogin, UserRegister, AnalysisRequest, AnalysisResponse, URLAnalysisRequest
import random
import json
import os
import datetime
import joblib

# Load Model
import sys
# Ensure we can import from the subfolder if needed, though usually automatic if __init__.py exists or python 3.3+
# However, importing directly from makineogr.ai_modulu should work if running from backend dir

# Import Phishing Model Logic
try:
    from makineogr.ai_modulu import tahmin_et
    print("DEBUG: Phishing model module loaded successfully.")
except ImportError as e:
    print(f"ERROR: Failed to load Phishing model module: {e}")
    tahmin_et = None

try:
    from email_analysis import analyze_email_offline
    print("DEBUG: Email analysis module loaded.")
except ImportError as e:
    print(f"ERROR: Failed to load Email Analysis module: {e}")
    analyze_email_offline = None

MODEL_PATH = "spam_model_FINAL_calibrated.joblib"
try:
    spam_model = joblib.load(MODEL_PATH)
    print(f"DEBUG: Model loaded from {MODEL_PATH}")
except Exception as e:
    print(f"ERROR: Failed to load model from {MODEL_PATH}: {e}")
    spam_model = None

app = FastAPI(title="PhishGuard Backend")

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Persistence Layer ---
USERS_FILE = "users.json"
SCANS_FILE = "scans.json"

def load_data(filename):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            try:
                return json.load(f)
            except:
                return []
    return []

def save_data(filename, data):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

def load_users():
    return load_data(USERS_FILE)

def save_users(users):
    save_data(USERS_FILE, users)

def load_scans():
    return load_data(SCANS_FILE)

def save_scans(scans):
    save_data(SCANS_FILE, scans)

# Initialize in-memory cache (optional, but good for performance if using global vars)
# We will reload on write to be safe with single-file persistence
users_db = load_users()
scans_db = load_scans()

print("--------------------------------------------------")
print(f"DEBUG: Server Persistence Layer Initialized")
print(f"DEBUG: Loaded Users ({len(users_db)}): {[u['username'] for u in users_db]}")
print(f"DEBUG: Loaded Scans ({len(scans_db)})")
print("--------------------------------------------------")

# --- Endpoints ---

@app.get("/")
def read_root():
    return {"message": "Welcome to PhishGuard API"}

@app.get("/get-stats")
def get_stats():
    current_scans = load_scans()
    today_str = datetime.date.today().isoformat()
    
    email_count = sum(1 for s in current_scans if s.get('type') == 'email' and s.get('timestamp', '').startswith(today_str))
    url_count = sum(1 for s in current_scans if s.get('type') == 'url' and s.get('timestamp', '').startswith(today_str))
    
    # Get last 10 scans, reversed (newest first)
    recent_scans = current_scans[-10:][::-1]
    
    return {
        "summary": {
            "email_count": email_count,
            "url_count": url_count
        },
        "recent_scans": recent_scans
    }

@app.post("/auth/register")
def register(user: UserRegister):
    print(f"Register attempt: {user.username}")
    
    current_users = load_users()
    
    for u in current_users:
        if u['username'] == user.username:
            raise HTTPException(status_code=400, detail="Kullanıcı adı zaten kullanımda")
    
    user_dict = user.model_dump()
    current_users.append(user_dict)
    save_users(current_users)
    
    print(f"User registered: {user.username}")
    return {"message": "User registered successfully"}

@app.post("/auth/login")
def login(user: UserLogin):
    print(f"Login attempt: {user.username}")
    
    current_users = load_users()
    
    for u in current_users:
        if u['username'] == user.username and u['password'] == user.password:
            print("Login successful")
            return {"token": "fake-jwt-token", "username": user.username}
            
    print("Login failed: Invalid credentials")
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/analyze", response_model=AnalysisResponse)
def analyze_text(request: AnalysisRequest):
    result = {
        "score": 0,
        "label": "error",
        "reasons": ["Analysis module failed"],
        "notes": "offline-error"
    }
    
    if analyze_email_offline:
        result = analyze_email_offline(request.text, spam_model)
    else:
        # Fallback if module import failed
        score = random.randint(0, 100)
        result = {
            "score": score,
            "label": "unknown",
            "reasons": ["Modules not loaded"],
            "notes": "mock-fallback"
        }

    # Save Scan (Adapted for new schema)
    new_scan = {
        "timestamp": datetime.datetime.now().isoformat(),
        "type": "email",
        "content": request.text[:50] + "..." if len(request.text) > 50 else request.text,
        "score": result.get("score", 0),
        "label": result.get("label", "unknown"),
        "reasons": result.get("reasons", [])
    }
    current_scans = load_scans()
    current_scans.append(new_scan)
    save_scans(current_scans)
        
    return AnalysisResponse(
        input=request.text,
        type="email",
        score=result.get("score", 0),
        label=result.get("label", "unknown"),
        reasons=result.get("reasons", []),
        notes=result.get("notes", "offline-analysis")
    )

@app.post("/analyze-url", response_model=AnalysisResponse)
def analyze_url(request: URLAnalysisRequest):
    print(f"Analyzing URL: {request.url}")
    
    result = {
        "score": 0,
        "label": "unknown",
        "reasons": ["URL analysis unavailable"],
        "notes": "offline-error"
    }

    if tahmin_et:
        result = tahmin_et(request.url)
    else:
        # Fallback
        score = random.randint(0, 100)
        result = {
            "score": score,
            "label": "unknown",
            "reasons": ["Mock analysis"],
            "notes": "mock-fallback"
        }
    
    # Save Scan
    new_scan = {
        "timestamp": datetime.datetime.now().isoformat(),
        "type": "url",
        "content": request.url,
        "score": result.get("score", 0),
        "label": result.get("label", "unknown"),
        "reasons": result.get("reasons", [])
    }
    current_scans = load_scans()
    current_scans.append(new_scan)
    save_scans(current_scans)
        
    return AnalysisResponse(
        input=request.url,
        type="url",
        score=result.get("score", 0),
        label=result.get("label", "unknown"),
        reasons=result.get("reasons", []),
        notes=result.get("notes", "offline-analysis")
    )
