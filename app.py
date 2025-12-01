# app.py
import os
import io
import base64
import tempfile
from flask import Flask, request, jsonify, send_file, render_template_string
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from stegano import lsb
from PIL import Image
import secrets

app = Flask(__name__)

# ---------- Helpers ----------
def generate_aes_key_b64():
    key = AESGCM.generate_key(bit_length=256)
    return base64.urlsafe_b64encode(key).decode('utf-8')

def aes_encrypt_b64(key_b64: str, plaintext: str) -> str:
    key = base64.urlsafe_b64decode(key_b64)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)  # 96-bit nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    payload = nonce + ciphertext
    return base64.b64encode(payload).decode('utf-8')

def aes_decrypt_b64(key_b64: str, payload_b64: str) -> str:
    key = base64.urlsafe_b64decode(key_b64)
    aesgcm = AESGCM(key)
    data = base64.b64decode(payload_b64)
    nonce = data[:12]
    ciphertext = data[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode('utf-8')

def image_to_tempfile(file_storage):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
    img = Image.open(file_storage.stream).convert("RGBA")  # ensure consistent format
    img.save(tmp.name, "PNG")
    return tmp.name

def pil_to_base64_png(img):
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b = base64.b64encode(buf.getvalue()).decode('utf-8')
    return "data:image/png;base64," + b

# ---------- Routes ----------
@app.route("/")
def index():
    # Serve static page (we will provide index.html separately; but keep a simple endpoint)
    return send_file("index.html")

@app.route("/encode", methods=["POST"])
def encode():
    """
    Accepts multipart/form-data:
      - image: file (cover image) [required]
      - message: text (required)
    Returns JSON:
      { status: "ok", stego_image_data_url: "...", passphrase: "<base64 key>" }
    """
    try:
        if 'image' not in request.files or request.files['image'].filename == "":
            return jsonify({"status":"error","error":"No image uploaded"}), 400
        message = request.form.get("message", "")
        if not message:
            return jsonify({"status":"error","error":"No message given"}), 400

        # Save uploaded image to temp PNG (convert if needed)
        cover_path = image_to_tempfile(request.files['image'])

        # Generate AES key (base64) and encrypt message -> base64 payload
        key_b64 = generate_aes_key_b64()
        payload_b64 = aes_encrypt_b64(key_b64, message)

        # Embed payload_b64 into cover using LSB
        secret_img = lsb.hide(cover_path, payload_b64)

        # Convert secret_img (PIL) to data URL
        data_url = pil_to_base64_png(secret_img)

        return jsonify({"status":"ok", "stego_image": data_url, "passphrase": key_b64}), 200
    except Exception as e:
        return jsonify({"status":"error", "error": str(e)}), 500

@app.route("/decode", methods=["POST"])
def decode():
    """
    Accepts multipart/form-data:
      - image: file (stego image) [required]
      - passphrase: base64 key (required)
    Returns JSON:
      { status: "ok", message: "..." }
    """
    try:
        if 'image' not in request.files or request.files['image'].filename == "":
            return jsonify({"status":"error","error":"No image uploaded"}), 400
        key_b64 = request.form.get("passphrase", "")
        if not key_b64:
            return jsonify({"status":"error","error":"No passphrase provided"}), 400

        tmp = image_to_tempfile(request.files['image'])
        revealed = lsb.reveal(tmp)
        if revealed is None:
            return jsonify({"status":"error","error":"No hidden message found"}), 404

        # revealed is the base64 payload; decrypt
        message = aes_decrypt_b64(key_b64, revealed)
        return jsonify({"status":"ok","message": message}), 200
    except Exception as e:
        return jsonify({"status":"error","error": str(e)}), 500

if __name__ == "__main__":
    print("Starting Steganogram encode/decode server on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
    app.run(host="0.0.0.0", port=5000, debug=True)
