import pandas as pd
import re
import pickle
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

print("🔧 Training URL model...")

# ✅ Load dataset
data = pd.read_csv("Dataset/data_url.csv")  # <-- replace with your actual file name

# ✅ Normalize labels (handle text or numeric)
data["label"] = data["label"].astype(str).str.lower().map({
    "bad": 1,
    "malicious": 1,
    "phishing": 1,
    "legitimate": 0,
    "benign": 0,
    "safe": 0,
    "good": 0
})
data = data.dropna(subset=["label"])

# ✅ Normalize URLs
def clean_url(u):
    u = u.lower().strip()
    u = re.sub(r"https?://", "", u)
    u = u.replace("www.", "")
    return u

data["url"] = data["url"].astype(str).apply(clean_url)

urls = data["url"].tolist()
labels = data["label"].astype(int).tolist()

# ✅ TF-IDF vectorizer
vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 5))
X = vectorizer.fit_transform(urls)

# ✅ Split + train Logistic Regression
X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.2, random_state=42)

model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

print("✅ Training complete.")
print(f"Accuracy on training data: {model.score(X_train, y_train):.2f}")
print(f"Accuracy on test data: {model.score(X_test, y_test):.2f}")

# ✅ Save model + vectorizer
import os
os.makedirs("Classifier", exist_ok=True)
pickle.dump(model, open("Classifier/pickel_model.pkl", "wb"))
pickle.dump(vectorizer, open("Classifier/pickel_vector.pkl", "wb"))

print("\n✅ Model and vectorizer saved successfully!")
