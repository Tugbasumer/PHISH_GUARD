import joblib
import numpy as np
import os

model_path = "backend/makineogr/phishing_modeli.pkl"
model = joblib.load(model_path)

print(f"Model expects {model.n_features_in_} features.")

# Test feature vector similar to a standard "Safe" site
# [1, 1, 1, 1, 1, 1, 1, 1, 1] means everything is "Good"
safe_features = np.array([[1, 1, 1, 1, 1, 1, 1, 1, 1]])
print(f"Safe Features Prediction: {model.predict(safe_features)}")

# Test feature vector for "Phishing"
# [-1, -1, -1, -1, -1, -1, -1, -1, -1]
phish_features = np.array([[-1, -1, -1, -1, -1, -1, -1, -1, -1]])
print(f"Phish Features Prediction: {model.predict(phish_features)}")

# Test changing ONLY Domain Age (Index 7)
# [1, 1, 1, 1, 1, 1, 1, -1, 1]
test_age_features = np.array([[1, 1, 1, 1, 1, 1, 1, -1, 1]])
print(f"Safe but Bad Age Prediction: {model.predict(test_age_features)}")
