# ============================================================
# ThreatDetect AI — FastAPI Backend
# ============================================================

from turtle import pd

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import numpy as np
import pickle
import uvicorn
from datetime import datetime

app = FastAPI(
    title="ThreatDetect AI",
    description="Network Intrusion Detection System using ML",
    version="1.0.0"
)

# CORS — allow frontend to talk to backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# Load all saved models
# ============================================================
import os
BASE = os.path.dirname(os.path.abspath(__file__))
PARENT = os.path.dirname(BASE)  # ThreatDetect-AI folder

with open(os.path.join(PARENT, 'best_model_lgbm.pkl'), 'rb') as f:
    model = pickle.load(f)

with open(os.path.join(PARENT, 'scaler.pkl'), 'rb') as f:
    scaler = pickle.load(f)

with open(os.path.join(PARENT, 'label_encoder.pkl'), 'rb') as f:
    le_target = pickle.load(f)

with open(os.path.join(PARENT, 'cat_encoders.pkl'), 'rb') as f:
    cat_encoders = pickle.load(f)

with open(os.path.join(PARENT, 'iso_forest.pkl'), 'rb') as f:
    iso_forest = pickle.load(f)

print("✅ All models loaded!")

# ============================================================
# Request schema
# ============================================================
class NetworkPacket(BaseModel):
    duration: float = 0
    protocol_type: str = "tcp"
    service: str = "http"
    flag: str = "SF"
    src_bytes: float = 0
    dst_bytes: float = 0
    land: int = 0
    wrong_fragment: int = 0
    urgent: int = 0
    hot: int = 0
    num_failed_logins: int = 0
    logged_in: int = 1
    num_compromised: int = 0
    root_shell: int = 0
    su_attempted: int = 0
    num_root: int = 0
    num_file_creations: int = 0
    num_shells: int = 0
    num_access_files: int = 0
    num_outbound_cmds: int = 0
    is_host_login: int = 0
    is_guest_login: int = 0
    count: float = 1
    srv_count: float = 1
    serror_rate: float = 0
    srv_serror_rate: float = 0
    rerror_rate: float = 0
    srv_rerror_rate: float = 0
    same_srv_rate: float = 1
    diff_srv_rate: float = 0
    srv_diff_host_rate: float = 0
    dst_host_count: float = 1
    dst_host_srv_count: float = 1
    dst_host_same_srv_rate: float = 1
    dst_host_diff_srv_rate: float = 0
    dst_host_same_src_port_rate: float = 0
    dst_host_srv_diff_host_rate: float = 0
    dst_host_serror_rate: float = 0
    dst_host_srv_serror_rate: float = 0
    dst_host_rerror_rate: float = 0
    dst_host_srv_rerror_rate: float = 0

# ============================================================
# Helper — preprocess one packet
# ============================================================
def preprocess(packet: NetworkPacket):
    data = packet.dict()

    # Encode categorical features
    for col in ['protocol_type', 'service', 'flag']:
        le = cat_encoders[col]
        val = data[col]
        if val not in le.classes_:
            val = le.classes_[0]  # fallback for unknown
        data[col] = int(le.transform([val])[0])

    feature_order = [
        'duration','protocol_type','service','flag',
        'src_bytes','dst_bytes','land','wrong_fragment',
        'urgent','hot','num_failed_logins','logged_in',
        'num_compromised','root_shell','su_attempted',
        'num_root','num_file_creations','num_shells',
        'num_access_files','num_outbound_cmds',
        'is_host_login','is_guest_login','count',
        'srv_count','serror_rate','srv_serror_rate',
        'rerror_rate','srv_rerror_rate','same_srv_rate',
        'diff_srv_rate','srv_diff_host_rate',
        'dst_host_count','dst_host_srv_count',
        'dst_host_same_srv_rate','dst_host_diff_srv_rate',
        'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate','dst_host_serror_rate',
        'dst_host_srv_serror_rate','dst_host_rerror_rate',
        'dst_host_srv_rerror_rate'
    ]

    X = pd.DataFrame([[data[f] for f in feature_order]], columns=feature_order)
    XX_scaled = scaler.transform(X)
    return XX_scaled

# ============================================================
# ROUTES
# ============================================================

@app.get("/")
def root():
    return {
        "message": "ThreatDetect AI API is running!",
        "version": "1.0.0",
        "endpoints": ["/predict", "/predict/batch", "/health", "/docs"]
    }

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "models_loaded": True
    }

@app.post("/predict")
def predict(packet: NetworkPacket):
    try:
        X_scaled = preprocess(packet)

        # LightGBM prediction
        prediction   = model.predict(X_scaled)[0]
        probabilities = model.predict_proba(X_scaled)[0]
        confidence   = float(probabilities.max()) * 100

        threat_type = le_target.inverse_transform([prediction])[0]

        # Anomaly detection
        iso_result  = iso_forest.predict(X_scaled)[0]
        is_anomaly  = iso_result == -1

        # Alert level
        if threat_type == "Normal" and not is_anomaly:
            alert_level = "SAFE"
            alert_color = "green"
        elif threat_type == "Normal" and is_anomaly:
            alert_level = "SUSPICIOUS"
            alert_color = "orange"
        elif threat_type in ["U2R", "R2L"]:
            alert_level = "CRITICAL"
            alert_color = "red"
        else:
            alert_level = "WARNING"
            alert_color = "orange"

        # All class probabilities
        class_probs = {
            cls: round(float(prob) * 100, 2)
            for cls, prob in zip(le_target.classes_, probabilities)
        }

        return {
            "threat_type":   threat_type,
            "confidence":    round(confidence, 2),
            "alert_level":   alert_level,
            "alert_color":   alert_color,
            "is_anomaly":    bool(is_anomaly),
            "class_probabilities": class_probs,
            "timestamp":     datetime.now().isoformat()
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predict/batch")
def predict_batch(packets: list[NetworkPacket]):
    results = []
    for packet in packets:
        result = predict(packet)
        results.append(result)
    summary = {
        "total":    len(results),
        "safe":     sum(1 for r in results if r["alert_level"] == "SAFE"),
        "warning":  sum(1 for r in results if r["alert_level"] == "WARNING"),
        "critical": sum(1 for r in results if r["alert_level"] == "CRITICAL"),
        "suspicious": sum(1 for r in results if r["alert_level"] == "SUSPICIOUS"),
    }
    return {"results": results, "summary": summary}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)