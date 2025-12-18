import re
import joblib
from pathlib import Path
from fastapi import FastAPI
from pydantic import BaseModel

THRESHOLD = 0.35

MODEL_PATH = Path(__file__).resolve().parent / "spam_model_FINAL_calibrated.joblib"
model = joblib.load(MODEL_PATH)

def clean(text: str) -> str:
    text = str(text).lower()
    text = re.sub(r"http\\S+|www\\.\\S+", " <URL> ", text)
    text = re.sub(r"\\s+", " ", text).strip()
    return text

app = FastAPI(title="Phishing Text Detector")

class PredictRequest(BaseModel):
    text: str

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/predict")
def predict(req: PredictRequest):
    x = clean(req.text)
    p_spam = float(model.predict_proba([x])[0][1])
    label = "SPAM/PHISHING" if p_spam >= THRESHOLD else "NORMAL"
    return {
        "label": label,
        "spam_score": round(p_spam * 100, 2),
        "normal_score": round((1 - p_spam) * 100, 2),
        "threshold": THRESHOLD
    }
