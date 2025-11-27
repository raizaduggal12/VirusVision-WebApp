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
    whitelist = ['hackthebox.eu', 'root-me.org', 'gmail.com']

    base_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.dirname(base_dir)
    model_path = os.path.join(root_dir, "Classifier", "pickel_model.pkl")
    vectorizer_path = os.path.join(root_dir, "Classifier", "pickel_vector.pkl")

    import builtins, sys, types
    builtins.sanitization = sanitization
    sys.modules['__main__'].sanitization = sanitization
    sys.modules['url_main'] = types.ModuleType('url_main')
    sys.modules['url_main'].sanitization = sanitization

    # ✅ Always normalize the input — model expects cleaned version
    url = url.strip().lower()
    url = url.replace("https://", "").replace("http://", "").replace("www.", "")

    # ✅ Whitelist check
    if url in whitelist:
        return f"✅ '{url}' is Legitimate (Whitelisted)."

    # ✅ Always treat “http://” URLs as risky
    if "http://" in url:
        return f"⚠️ '{url}' is MALICIOUS (Unsecured HTTP)."

    try:
        with open(model_path, "rb") as f1:
            lgr = pickle.load(f1)
        with open(vectorizer_path, "rb") as f2:
            vectorizer = pickle.load(f2)
    except Exception as e:
        return f"❌ Error loading model: {e}"

    try:
        # ✅ Apply the same sanitization tokens
        # Let vectorizer handle sanitization exactly as during training
        x = vectorizer.transform([url])

        y_pred = lgr.predict(x)[0]
    except Exception as e:
        return f"❌ Error during prediction: {e}"

    # ✅ Interpret output correctly
    if str(y_pred).lower() in ["bad", "malicious", "1"]:
        return f"⚠️ '{url}' is MALICIOUS."
    else:
        return f"✅ '{url}' is LEGITIMATE."

    
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("⚠️ Please provide a URL to scan.")
        print("Example: python Extract/url_main.py google.com")
    else:
        input_url = sys.argv[1]
        # ✅ Call the function directly (not import again)
        result = predict_url_from_flask(input_url)
        print(result)

