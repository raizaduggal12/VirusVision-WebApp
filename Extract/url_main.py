import warnings
warnings.filterwarnings("ignore")
import os, pickle, builtins, sys, types

# ✅ Define sanitization function (same as training, but now normalized)
def sanitization(web):
    web = web.strip().lower()
    web = web.replace("https://", "").replace("http://", "").replace("www.", "")
    token = []
    dot_token_slash = []
    raw_slash = str(web).split('/')
    for i in raw_slash:
        raw1 = str(i).split('-')
        slash_token = []
        for j in range(0, len(raw1)):
            raw2 = str(raw1[j]).split('.')
            slash_token = slash_token + raw2
        dot_token_slash = dot_token_slash + raw1 + slash_token
    token = list(set(dot_token_slash))
    if 'com' in token:
        token.remove('com')
    return token

# ✅ Ensure pickle can access sanitization function
builtins.sanitization = sanitization
sys.modules['__main__'].sanitization = sanitization
sys.modules['url_main'] = types.ModuleType('url_main')
sys.modules['url_main'].sanitization = sanitization


def predict_url_from_flask(url):
    import numpy as np

    whitelist = ['google.com', 'gmail.com', 'hackthebox.eu', 'root-me.org', 'microsoft.com', 'yahoo.com']

    base_dir = os.getcwd()
    model_path = os.path.join(base_dir, "Classifier", "pickel_model.pkl")
    vectorizer_path = os.path.join(base_dir, "Classifier", "pickel_vector.pkl")



    # Re-load model and vectorizer
    import joblib

    try:
        lgr = joblib.load(model_path)
        vectorizer = joblib.load(vectorizer_path)
    except Exception as e:
        return f"❌ Error loading model: {e}"


    # Clean the input like during training
    url_clean = url.strip().lower().replace("https://", "").replace("http://", "").replace("www.", "")

    # ✅ Rule 1: Whitelist safe domains
    if url_clean in whitelist:
        return f"✅ '{url}' is LEGITIMATE (Whitelisted)."

    # ✅ Rule 2: If it’s plain http — unsafe
    if url.lower().startswith("http://"):
        return f"⚠️ '{url}' is MALICIOUS (Unsecured HTTP)."

    # Vectorize and predict probability
    x = vectorizer.transform([url_clean])
    y_prob = lgr.predict_proba(x)[0]
    y_pred = lgr.predict(x)[0]

    prob_malicious = y_prob[1]  # probability model thinks it’s malicious

    # ✅ Rule 3: Confidence threshold
    if prob_malicious > 0.7:
        verdict = "⚠️ MALICIOUS"
    elif prob_malicious < 0.3:
        verdict = "✅ SAFE"
    else:
        verdict = "❓ SUSPICIOUS"

    return f"{verdict} → '{url}' (malicious probability: {prob_malicious:.2f})"


