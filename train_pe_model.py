import pandas as pd
import pickle
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import os

print("🔧 Training PE file detection model...")

# ✅ Load the correct dataset (pipe-separated)
data = pd.read_csv("Dataset/data.csv", sep="|")

print("Columns in dataset:", data.columns.tolist())

# ✅ Drop non-numeric columns if they exist
for col in ["Name", "md5", "Unnamed: 0"]:
    if col in data.columns:
        data = data.drop(columns=[col])

# ✅ Split into features (X) and labels (y)
X = data.drop(columns=["legitimate"])
y = data["legitimate"]

# ✅ Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# ✅ Train Random Forest
model = RandomForestClassifier(
    n_estimators=150,
    random_state=42,
    class_weight="balanced"
)
model.fit(X_train, y_train)

# ✅ Accuracy results
print(f"✅ Training accuracy: {model.score(X_train, y_train):.2f}")
print(f"✅ Testing accuracy : {model.score(X_test, y_test):.2f}")

# ✅ Save model & features
os.makedirs("Classifier", exist_ok=True)

with open("Classifier/classifier.pkl", "wb") as f:
    joblib.dump(model, f)

with open("Classifier/features.pkl", "wb") as f:
    pickle.dump(list(X.columns), f)

print("\n🎯 Model & features saved successfully to Classifier/")
