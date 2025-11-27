from flask import Flask, render_template, request
import os
from Extract.PE_main import predict_pe_from_flask
from Extract.url_main import predict_url_from_flask



# ---------------- CONFIG ----------------
app = Flask(__name__, template_folder="templates", static_folder="static")

app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0


@app.after_request
def add_header(response):
    """Prevents browser from caching old templates."""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# ---------------- ROUTES ----------------
@app.route("/")
def home():
    return render_template("index.html", title="Home")

@app.route("/menu")
def menu():
    return render_template("menu.html", title="Menu")

@app.route("/pe")
def pe_page():
    return render_template("pe.html", title="PE Scanner")

@app.route("/url")
def url_page():
    return render_template("url.html", title="URL Scanner")

@app.route("/exit")
def exit_page():
    return render_template("exit.html", title="Exit")


# ---------------- PE SCANNER ROUTE ----------------
@app.route("/scan/pe", methods=["POST"])
def scan_pe():
    file = request.files.get("file")

    if not file:
        return render_template("pe.html", title="PE Scanner", result="⚠️ No file uploaded.")

    # Save uploaded file temporarily
    extract_dir = os.path.join(os.path.dirname(__file__), "Extract")
    os.makedirs(extract_dir, exist_ok=True)
    filepath = os.path.join(extract_dir, file.filename)
    file.save(filepath)

    # Call your ML model directly
    try:
        result = predict_pe_from_flask(filepath)
    except Exception as e:
        result = f"❌ Error during prediction: {str(e)}"

    return render_template("pe.html", title="PE Scanner", result=result)


# ---------------- URL SCANNER ROUTE ----------------
@app.route("/scan/url", methods=["POST"])
def scan_url():
    url = request.form.get("url")

    if not url:
        return render_template("url.html", title="URL Scanner", result="⚠️ No URL entered.")

    try:
        # 🔥 Call the same ML function you verified in terminal
        result = predict_url_from_flask(url)
    except Exception as e:
        result = f"❌ Error during prediction: {e}"

    return render_template("url.html", title="URL Scanner", result=result)




# ---------------- MAIN ----------------
if __name__ == "__main__":
    app.run(debug=True, port=5003)

