import pandas as pd
import joblib

# Load trained model
model = joblib.load("models/threat_model.pkl")

# Sample data
sample = pd.DataFrame({
    "src_port": [443],
    "dst_port": [80],
    "bytes_sent": [5000],
    "bytes_received": [2000],
    "is_internal_traffic": [0]
})

# Prediction
prediction = model.predict(sample)

if prediction[0] == 1:
    print("🚨 Threat Detected")
else:
    print("✅ Benign Traffic")