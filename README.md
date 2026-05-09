# 🛡️ ThreatDetect AI

> AI-powered Network Intrusion Detection System with 99.63% accuracy

🌐 **Live Dashboard:** [Click Here](https://bytecraft17.github.io/ThreatDetect-AI/Frontend/)

---

## 📊 Model Performance

| Model | Accuracy | F1 Score |
|-------|----------|----------|
| Logistic Regression | 94.35% | 94.12% |
| Random Forest | 99.57% | 99.57% |
| XGBoost | 99.62% | 99.62% |
| **LightGBM ⭐** | **99.63%** | **99.63%** |

---

## 🔍 Attack Types Detected

| Attack | Type | Alert Level |
|--------|------|-------------|
| Neptune, Smurf, Pod | DoS | ⚠️ WARNING |
| Portsweep, Nmap, Satan | Probe | ⚠️ WARNING |
| Guess Password, FTP Write | R2L | 🔴 CRITICAL |
| Buffer Overflow, Rootkit | U2R | 🔴 CRITICAL |
| Normal Traffic | — | ✅ SAFE |

---

## 🧠 Project Modules

### Module 1 — Data Analysis & EDA
- Loaded NSL-KDD dataset (1,48,384 samples)
- Visualized attack distributions
- Correlation heatmap of 41 network features

### Module 2 — Preprocessing
- Label encoding of categorical features
- StandardScaler normalization
- SMOTE for class balancing (U2R, R2L)
- Proper stratified 80/20 train-test split

### Module 3 — Model Training
- Logistic Regression (baseline)
- Random Forest (99.57%)
- XGBoost (99.62%)
- LightGBM ⭐ Best (99.63%)

### Module 4 — Anomaly Detection
- Isolation Forest trained on normal traffic only
- Detects unknown/zero-day attacks
- PCA visualization of anomalies

---

## 🏗️ Project Structure

```
ThreatDetect-AI/
│
├── ThreatDetect_AI.ipynb     ← Complete ML notebook
├── Backend/
│   ├── main.py               ← FastAPI backend
│   └── requirements.txt
├── Frontend/
│   └── index.html            ← Live dashboard
├── scaler.pkl                ← StandardScaler
├── label_encoder.pkl         ← Label encoder
└── cat_encoders.pkl          ← Categorical encoders
```

---

## 🚀 Tech Stack

- **ML Models:** LightGBM, XGBoost, Random Forest, Logistic Regression
- **Anomaly Detection:** Isolation Forest
- **Backend:** FastAPI + Uvicorn
- **Frontend:** HTML, CSS, JavaScript, Chart.js
- **Dataset:** NSL-KDD (148,384 samples, 41 features)

---

## 📁 Dataset & Large Model Files

Dataset and large model files are not included in this repo due to size.

| File | Size | Link |
|------|------|------|
| NSL-KDD Dataset | ~50MB | [Kaggle](https://www.kaggle.com/datasets/hassan06/nslkdd) |
| best_model_lgbm.pkl | 18MB | Google Drive |
| rf_model.pkl | 48MB | Google Drive |

---

## ⚡ How to Run Locally

```bash
# 1. Clone the repo
git clone https://github.com/bytecraft17/ThreatDetect-AI.git

# 2. Install dependencies
cd ThreatDetect-AI/Backend
pip install -r requirements.txt

# 3. Start backend
python main.py

# 4. Open Frontend/index.html in browser
```

---

## 👤 Author

**bytecraft17** — AI/ML Developer