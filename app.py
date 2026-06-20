import hashlib
import time
import json
import os
import logging
import threading
import queue
import uuid
from functools import wraps
from flask import Flask, request, jsonify, render_template, Response
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# cryptography imports
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

# ── Load environment variables from .env ──────────────────────────────────────
load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ── Config from environment (never hardcoded) ─────────────────────────────────
RESET_TOKEN = os.environ.get("RESET_TOKEN", "")
API_KEY     = os.environ.get("API_KEY", "")
DEMO_MODE   = os.environ.get("DEMO_MODE", "false").lower() == "true"
FLASK_HOST  = os.environ.get("FLASK_HOST", "127.0.0.1")
FLASK_PORT  = int(os.environ.get("FLASK_PORT", "5000"))

if not RESET_TOKEN:
    logger.warning("RESET_TOKEN is not set — /reset endpoint will be disabled.")
if not API_KEY:
    logger.warning("API_KEY is not set — protected endpoints will reject all requests.")

# ── Load public-key user config (no private keys here) ───────────────────────
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "users_config.json")
with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    USERS = json.load(f)

# ── Load private keys from environment variables (CRIT-2 fix) ────────────────
def _load_private_key_from_env(user_id: str):
    """Return the private key PEM for user_id from environment, or None."""
    env_key = f"PRIVATE_KEY_{user_id.replace('-', '_')}"
    pem = os.environ.get(env_key, "")
    if not pem:
        return None
    # .env stores newlines as literal \n — restore them
    return pem.replace("\\n", "\n")

# ── Dynamically generate keypair for NUR-202 if not in config ─────────────────
if "NUR-202" not in USERS:
    _priv = ec.generate_private_key(ec.SECP256R1())
    _pub_pem = _priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    USERS["NUR-202"] = {"role": "Nurse", "public_key": _pub_pem}
    logger.warning(
        "NUR-202 was not in users_config.json. A temporary keypair was generated "
        "for this session only. Run keygen.py and restart to make it permanent."
    )

# ── Helper: load a private key PEM string ────────────────────────────────────
def load_private_key(pem_str: str):
    return serialization.load_pem_private_key(pem_str.encode(), password=None)

# ── Helper: load a public key PEM string ─────────────────────────────────────
def load_public_key(pem_str: str):
    return serialization.load_pem_public_key(pem_str.encode())

# ── Auth decorator (HIGH-2 fix) ───────────────────────────────────────────────
def require_auth(f):
    """Require a valid X-API-Key header on the decorated route."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not API_KEY:
            return jsonify({"error": "Server misconfiguration: API_KEY not set."}), 503
        client_key = request.headers.get("X-API-Key", "")
        if not client_key or client_key != API_KEY:
            return jsonify({"error": "Unauthorized. Provide a valid X-API-Key header."}), 401
        return f(*args, **kwargs)
    return decorated

# ── Input length guard (HIGH-1 fix) ──────────────────────────────────────────
MAX_TEXT_BYTES = 10 * 1024  # 10 KB

def _validate_text(value: str, field: str):
    """Return an error string if value is too long, else None."""
    if len(value.encode("utf-8")) > MAX_TEXT_BYTES:
        return f"Field '{field}' exceeds maximum allowed size of {MAX_TEXT_BYTES} bytes."
    return None

# ── OFF-CHAIN STORAGE ─────────────────────────────────────────────────────────
OFF_CHAIN_DIR = "off_chain_data"
os.makedirs(OFF_CHAIN_DIR, exist_ok=True)

def save_off_chain_data(patient_id, medical_text):
    safe_name = secure_filename(f"{patient_id}_{int(time.time())}.txt")
    joined_path = os.path.join(OFF_CHAIN_DIR, safe_name)
    filepath = os.path.abspath(joined_path)
    if not filepath.startswith(os.path.abspath(OFF_CHAIN_DIR) + os.sep):
        raise ValueError("Path traversal detected in off-chain storage")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(medical_text)
    file_hash = hashlib.sha256(medical_text.encode("utf-8")).hexdigest()
    return file_hash, safe_name


# ── Signature helpers ─────────────────────────────────────────────────────────
def generate_signature(private_key_pem: str, patient_id: str, action: str) -> str:
    private_key_obj = load_private_key(private_key_pem)
    message = f"{patient_id}:{action}".encode()
    signature = private_key_obj.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature.hex()


def verify_signature(user_id: str, patient_id: str, action: str, signature_hex: str) -> bool:
    """CRIT-4 fix: verify using the PUBLIC key only — never loads private key."""
    user = USERS.get(user_id)
    if not user:
        return False
    pub_pem = user.get("public_key", "")
    if not pub_pem:
        logger.error("No public_key found for user %s — cannot verify signature.", user_id)
        return False
    try:
        public_key = load_public_key(pub_pem)
        public_key.verify(bytes.fromhex(signature_hex), f"{patient_id}:{action}".encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, Exception):
        return False


# ── Block ─────────────────────────────────────────────────────────────────────
class Block:
    def __init__(self, index, patient_id, user_id, action, medical_file_hash,
                 file_name, previous_hash, signature="", timestamp=None, hash=None):
        self.index = index
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.patient_id = patient_id
        self.user_id = user_id
        self.action = action
        self.medical_file_hash = medical_file_hash
        self.file_name = file_name
        self.signature = signature
        self.previous_hash = previous_hash
        self.hash = hash if hash is not None else self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "patient_id": self.patient_id,
            "user_id": self.user_id,
            "action": self.action,
            "medical_file_hash": self.medical_file_hash,
            "file_name": self.file_name,
            "signature": self.signature,
            "previous_hash": self.previous_hash
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "patient_id": self.patient_id,
            "user_id": self.user_id,
            "action": self.action,
            "medical_file_hash": self.medical_file_hash,
            "file_name": self.file_name,
            "signature": self.signature,
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }


# ── Blockchain ────────────────────────────────────────────────────────────────
class Blockchain:
    def __init__(self):
        self.chain = []
        self.lock = threading.Lock()
        self.load_chain()

    def load_chain(self):
        ledger_path = os.path.join(os.path.dirname(__file__), "ledger.json")
        if os.path.exists(ledger_path):
            with open(ledger_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for block_dict in data:
                    block = Block(**block_dict)
                    self.chain.append(block)
        if not self.chain:
            self.chain.append(self.create_genesis_block())
        # MED-1 fix: validate integrity immediately on startup
        if not self.is_chain_valid():
            logger.error(
                "INTEGRITY WARNING: Loaded ledger.json failed chain validation. "
                "The ledger may have been tampered with."
            )

    def save_chain(self):
        ledger_path = os.path.join(os.path.dirname(__file__), "ledger.json")
        with open(ledger_path, "w", encoding="utf-8") as f:
            json.dump([b.to_dict() for b in self.chain], f, indent=2)

    def create_genesis_block(self):
        return Block(0, "0", "0", "GENESIS", "0", "NONE", "0")

    def get_latest_block(self):
        return self.chain[-1]

    def request_access(self, patient_id, user_id, action, medical_file_hash, file_name, signature):
        if not verify_signature(user_id, patient_id, action, signature):
            return False, "INVALID SIGNATURE. Access denied."

        # MED-4 fix: safe lookup — user is already verified above but guard anyway
        user = USERS.get(user_id)
        if not user:
            return False, "User not found."

        user_role = user["role"]
        is_authorized = False
        if user_role == "Doctor" and action in ["VIEW", "UPDATE", "PRESCRIPTION"]:
            is_authorized = True
        elif user_role == "Receptionist" and action == "REGISTER":
            is_authorized = True
        elif user_role == "Nurse" and action == "VITALS":
            is_authorized = True

        with self.lock:
            new_index = len(self.chain)
            previous_hash = self.get_latest_block().hash
            if is_authorized:
                new_block = Block(new_index, patient_id, user_id, action,
                                  medical_file_hash, file_name, previous_hash, signature)
                message = f"Authorized access: {user_role} {user_id} performed {action} on {patient_id}."
            else:
                new_block = Block(new_index, patient_id, user_id, "UNAUTHORIZED_ATTEMPT",
                                  "NONE", "NONE", previous_hash, signature)
                message = f"UNAUTHORIZED ROLE: {user_role} {user_id} attempted {action} on {patient_id}."
            self.chain.append(new_block)
            self.save_chain()
        return True, message

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            if current_block.hash != current_block.calculate_hash():
                return False
            if current_block.previous_hash != previous_block.hash:
                return False
        return True

    def is_data_intact(self):
        for block in self.chain:
            if block.file_name != "NONE":
                joined_path = os.path.join(OFF_CHAIN_DIR, block.file_name)
                filepath = os.path.abspath(joined_path)
                if not filepath.startswith(os.path.abspath(OFF_CHAIN_DIR) + os.sep):
                    return False
                if not os.path.exists(filepath):
                    return False
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                actual_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
                if actual_hash != block.medical_file_hash:
                    return False
        return True


hospital_chain = Blockchain()

# ── Outpatient state ──────────────────────────────────────────────────────────
OUTPATIENTS_PATH = os.path.join(os.path.dirname(__file__), "outpatient_data.json")
outpatient_state = {"patients": {}, "queue": []}
outpatient_lock = threading.Lock()  # MED-2 fix: protects outpatient_state mutations

def load_outpatient_state():
    global outpatient_state
    if os.path.exists(OUTPATIENTS_PATH):
        try:
            with open(OUTPATIENTS_PATH, "r", encoding="utf-8") as f:
                outpatient_state = json.load(f)
        except Exception as e:
            # MED-5 fix: log instead of silently swallowing
            logger.error("Failed to load outpatient_data.json: %s. Starting with empty state.", e)

def save_outpatient_state():
    try:
        with open(OUTPATIENTS_PATH, "w", encoding="utf-8") as f:
            json.dump(outpatient_state, f, indent=2)
    except Exception as e:
        logger.error("Failed to save outpatient_data.json: %s", e)

load_outpatient_state()

# ── SSE ───────────────────────────────────────────────────────────────────────
sse_clients = []
sse_clients_lock = threading.Lock()

def announce_sync():
    with sse_clients_lock:
        for client in list(sse_clients):
            try:
                client.put_nowait('data: {"type": "sync"}\n\n')
            except queue.Full:
                pass  # stale client — will be removed on next heartbeat timeout


# ── Flask routes ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/add_record", methods=["POST"])
@require_auth
def add_record():
    data = request.get_json()
    required_fields = ["doctor_id", "patient_id", "medical_text"]
    if not data or not all(k in data for k in required_fields):
        return jsonify({"error": "Missing required fields."}), 400

    doctor_id    = data["doctor_id"]
    patient_id   = data["patient_id"]
    medical_text = data["medical_text"]
    action       = "UPDATE"

    # HIGH-1 fix: validate text length
    err = _validate_text(medical_text, "medical_text")
    if err:
        return jsonify({"error": err}), 400

    if doctor_id not in USERS:
        return jsonify({"error": "User not found."}), 404

    # Load private key from env for signing
    private_key_pem = _load_private_key_from_env(doctor_id)
    if not private_key_pem:
        return jsonify({"error": f"Private key for {doctor_id} not configured on server."}), 500

    medical_file_hash, file_name = save_off_chain_data(patient_id, medical_text)
    signature = generate_signature(private_key_pem, patient_id, action)
    success, message = hospital_chain.request_access(
        patient_id, doctor_id, action, medical_file_hash, file_name, signature
    )
    if not success:
        return jsonify({"error": message}), 403

    return jsonify({
        "message": message,
        "medical_file_hash": medical_file_hash,
        "block_index": hospital_chain.get_latest_block().index
    }), 201


@app.route("/get_chain", methods=["GET"])
@require_auth
def get_chain():
    chain_data = [block.to_dict() for block in hospital_chain.chain]
    return jsonify({"length": len(chain_data), "chain": chain_data}), 200


@app.route("/verify", methods=["GET"])
def verify():
    chain_valid  = hospital_chain.is_chain_valid()
    data_intact  = hospital_chain.is_data_intact()
    return jsonify({
        "is_valid": chain_valid,
        "is_data_intact": data_intact,
        "overall_secure": chain_valid and data_intact
    }), 200


@app.route("/stats", methods=["GET"])
def get_stats():
    total_blocks  = len(hospital_chain.chain)
    last_activity = hospital_chain.get_latest_block().timestamp if total_blocks > 1 else None
    chain_valid   = hospital_chain.is_chain_valid()
    data_intact   = hospital_chain.is_data_intact()

    if not chain_valid:
        health = "COMPROMISED"
    elif not data_intact:
        health = "TAMPERED"
    else:
        health = "SECURE"

    return jsonify({
        "total_blocks": total_blocks,
        "last_activity": last_activity,
        "health": health
    }), 200


@app.route("/users", methods=["GET"])
@require_auth
def get_users():
    # Never expose private keys — return role only
    user_list = [{"user_id": uid, "role": info["role"]} for uid, info in USERS.items()]
    return jsonify(user_list), 200


@app.route("/reset", methods=["POST"])
def reset_ledger():
    # CRIT-1 fix: token from environment, hardcoded 'admin123' is gone
    if not RESET_TOKEN:
        return jsonify({"error": "Reset endpoint is disabled (RESET_TOKEN not configured)."}), 503
    token = request.args.get("token", "")
    if token != RESET_TOKEN:
        return jsonify({"error": "Unauthorized"}), 403

    ledger_path = os.path.join(os.path.dirname(__file__), "ledger.json")
    if os.path.exists(ledger_path):
        os.remove(ledger_path)
    if os.path.isdir(OFF_CHAIN_DIR):
        for fname in os.listdir(OFF_CHAIN_DIR):
            fpath = os.path.join(OFF_CHAIN_DIR, fname)
            if os.path.isfile(fpath):
                os.remove(fpath)
    hospital_chain.chain = [hospital_chain.create_genesis_block()]
    hospital_chain.save_chain()
    return jsonify({"message": "Ledger reset"}), 200


# ── HACK SIMULATOR ENDPOINTS (CRIT-3 fix: gated behind DEMO_MODE) ─────────────
if DEMO_MODE:
    logger.warning("DEMO_MODE is enabled — hack-simulator endpoints are active.")

    @app.route("/get_files", methods=["GET"])
    def get_files():
        files = []
        if os.path.exists(OFF_CHAIN_DIR):
            for filename in os.listdir(OFF_CHAIN_DIR):
                joined_path = os.path.join(OFF_CHAIN_DIR, filename)
                filepath = os.path.abspath(joined_path)
                if not filepath.startswith(os.path.abspath(OFF_CHAIN_DIR) + os.sep):
                    continue
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                files.append({"filename": filename, "content": content})
        return jsonify(files)

    @app.route("/update_file", methods=["POST"])
    def update_file():
        data = request.get_json()
        filename = data.get("filename", "")
        content  = data.get("content", "")

        joined_path = os.path.join(OFF_CHAIN_DIR, filename)
        filepath    = os.path.abspath(joined_path)
        if not filepath.startswith(os.path.abspath(OFF_CHAIN_DIR) + os.sep):
            return jsonify({"error": "Invalid filename"}), 400
        if not os.path.exists(filepath):
            return jsonify({"error": "File not found"}), 404

        # Deliberately does NOT update the blockchain — demo of tamper detection
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return jsonify({"message": "File hacked successfully! (DEMO MODE)"})

else:
    # Stub routes that return 404 when DEMO_MODE is off
    @app.route("/get_files", methods=["GET"])
    @app.route("/update_file", methods=["POST"])
    def demo_disabled():
        return jsonify({"error": "This endpoint is only available in DEMO_MODE."}), 404


# ── HOSPITAL OUTPATIENT MANAGEMENT SYSTEM ────────────────────────────────────

@app.route("/outpatients/stream", methods=["GET"])
def outpatient_stream():
    def event_stream():
        q = queue.Queue(maxsize=50)
        with sse_clients_lock:
            sse_clients.append(q)
        try:
            while True:
                try:
                    # MED-3 fix: 30-second timeout heartbeat to detect dead clients
                    data = q.get(timeout=30)
                    yield data
                except queue.Empty:
                    # Send heartbeat; if client is gone the GeneratorExit will fire
                    yield ": heartbeat\n\n"
        except GeneratorExit:
            with sse_clients_lock:
                if q in sse_clients:
                    sse_clients.remove(q)
    return Response(event_stream(), mimetype="text/event-stream")


@app.route("/outpatients/state", methods=["GET"])
def get_outpatient_state():
    with outpatient_lock:
        state_copy = json.loads(json.dumps(outpatient_state))
    return jsonify(state_copy), 200


@app.route("/outpatients/register", methods=["POST"])
def register_patient():
    data          = request.get_json()
    name          = data.get("name")
    age           = data.get("age")
    gender        = data.get("gender")
    contact       = data.get("contact")
    receptionist_id = data.get("receptionist_id")

    if not name or not age or not gender or not contact or not receptionist_id:
        return jsonify({"error": "Missing required fields."}), 400

    # HIGH-1 fix: validate field lengths
    for field, val in [("name", name), ("contact", str(contact))]:
        err = _validate_text(str(val), field)
        if err:
            return jsonify({"error": err}), 400

    if receptionist_id not in USERS:
        return jsonify({"error": "Unauthorized receptionist ID."}), 403

    # HIGH-4 fix: UUID-based patient ID — no collision risk
    patient_id = f"PAT-{uuid.uuid4().hex[:8].upper()}"

    patient = {
        "id": patient_id,
        "name": name,
        "age": int(age),
        "gender": gender,
        "contact": contact,
        "registered_at": time.time(),
        "vitals": None,
        "consultation": None
    }

    # MED-2 fix: lock outpatient_state mutation
    with outpatient_lock:
        outpatient_state["patients"][patient_id] = patient
        outpatient_state["queue"].append({
            "patient_id": patient_id,
            "status": "NURSE",
            "joined_at": time.time(),
            "updated_at": time.time()
        })
        save_outpatient_state()

    # Blockchain log
    action       = "REGISTER"
    medical_text = f"Patient Registered: {name}, Age {age}, Gender {gender}"
    medical_file_hash, file_name = save_off_chain_data(patient_id, medical_text)

    private_key_pem = _load_private_key_from_env(receptionist_id)
    if not private_key_pem:
        return jsonify({"error": f"Private key for {receptionist_id} not configured on server."}), 500

    signature = generate_signature(private_key_pem, patient_id, action)
    success, message = hospital_chain.request_access(
        patient_id, receptionist_id, action, medical_file_hash, file_name, signature
    )
    if not success:
        return jsonify({"error": message}), 403

    announce_sync()
    return jsonify({
        "message": "Patient registered successfully and block sealed.",
        "patient_id": patient_id
    }), 201


@app.route("/outpatients/vitals", methods=["POST"])
def record_vitals():
    data           = request.get_json()
    patient_id     = data.get("patient_id")
    nurse_id       = data.get("nurse_id")
    height         = data.get("height")
    weight         = data.get("weight")
    blood_pressure = data.get("blood_pressure")
    temperature    = data.get("temperature")
    heart_rate     = data.get("heart_rate")

    if not all([patient_id, nurse_id, height, weight, blood_pressure, temperature, heart_rate]):
        return jsonify({"error": "Missing required fields."}), 400

    if nurse_id not in USERS:
        return jsonify({"error": "Unauthorized nurse ID."}), 403

    with outpatient_lock:
        if patient_id not in outpatient_state["patients"]:
            return jsonify({"error": "Patient not found."}), 404

    h_m  = float(height) / 100.0
    w_kg = float(weight)
    bmi  = round(w_kg / (h_m * h_m), 2)

    vitals = {
        "height":         float(height),
        "weight":         float(weight),
        "bmi":            bmi,
        "blood_pressure": blood_pressure,
        "temperature":    float(temperature),
        "heart_rate":     int(heart_rate),
        "recorded_at":    time.time(),
        "recorded_by":    nurse_id
    }

    # MED-2 fix: lock mutation
    with outpatient_lock:
        outpatient_state["patients"][patient_id]["vitals"] = vitals
        for item in outpatient_state["queue"]:
            if item["patient_id"] == patient_id:
                item["status"]     = "DOCTOR"
                item["updated_at"] = time.time()
                break
        save_outpatient_state()

    # Blockchain log
    action       = "VITALS"
    medical_text = (
        f"Vitals Recorded: Height {height}cm, Weight {weight}kg, BMI {bmi}, "
        f"BP {blood_pressure}, Temp {temperature}C, HR {heart_rate}bpm"
    )
    medical_file_hash, file_name = save_off_chain_data(patient_id, medical_text)

    private_key_pem = _load_private_key_from_env(nurse_id)
    if not private_key_pem:
        return jsonify({"error": f"Private key for {nurse_id} not configured on server."}), 500

    signature = generate_signature(private_key_pem, patient_id, action)
    success, message = hospital_chain.request_access(
        patient_id, nurse_id, action, medical_file_hash, file_name, signature
    )
    if not success:
        return jsonify({"error": message}), 403

    announce_sync()
    return jsonify({
        "message": "Patient vitals recorded successfully and block sealed.",
        "bmi": bmi
    }), 201


@app.route("/outpatients/consultation", methods=["POST"])
def record_consultation():
    data          = request.get_json()
    patient_id    = data.get("patient_id")
    doctor_id     = data.get("doctor_id")
    diagnosis     = data.get("diagnosis")
    medications   = data.get("medications")
    follow_up_date = data.get("follow_up_date")

    if not all([patient_id, doctor_id, diagnosis, medications]):
        return jsonify({"error": "Missing required fields."}), 400

    # HIGH-1 fix: validate diagnosis length
    err = _validate_text(diagnosis, "diagnosis")
    if err:
        return jsonify({"error": err}), 400

    if doctor_id not in USERS:
        return jsonify({"error": "Unauthorized doctor ID."}), 403

    with outpatient_lock:
        if patient_id not in outpatient_state["patients"]:
            return jsonify({"error": "Patient not found."}), 404

    consultation = {
        "diagnosis":      diagnosis,
        "medications":    medications,
        "follow_up_date": follow_up_date,
        "consulted_at":   time.time(),
        "consulted_by":   doctor_id
    }

    # MED-2 fix: lock mutation
    with outpatient_lock:
        outpatient_state["patients"][patient_id]["consultation"] = consultation
        outpatient_state["queue"] = [
            item for item in outpatient_state["queue"]
            if item["patient_id"] != patient_id
        ]
        save_outpatient_state()

    # Blockchain log
    action    = "PRESCRIPTION"
    meds_str  = ", ".join(
        [f"{m['name']} ({m['dosage']} {m['frequency']} x {m['duration']}d)" for m in medications]
    )
    medical_text = f"Diagnosis: {diagnosis}. Prescribed: {meds_str}. Follow-up: {follow_up_date or 'None'}."
    medical_file_hash, file_name = save_off_chain_data(patient_id, medical_text)

    private_key_pem = _load_private_key_from_env(doctor_id)
    if not private_key_pem:
        return jsonify({"error": f"Private key for {doctor_id} not configured on server."}), 500

    signature = generate_signature(private_key_pem, patient_id, action)
    success, message = hospital_chain.request_access(
        patient_id, doctor_id, action, medical_file_hash, file_name, signature
    )
    if not success:
        return jsonify({"error": message}), 403

    announce_sync()
    return jsonify({
        "message": "Consultation prescription sealed successfully.",
        "prescription_hash": medical_file_hash
    }), 201


# ── NEW SECURE /api ENDPOINTS FOR REACT FRONTEND INTEGRATION ──────────────────

@app.route("/api/demo_keys", methods=["GET"])
def get_demo_keys():
    """Expose public info and private keys ONLY in demo mode for UI helper convenience."""
    if not DEMO_MODE:
        return jsonify({"error": "This endpoint is only available in DEMO_MODE."}), 403
    
    # Extract private keys from environment to send to frontend for local signing
    demo_keys = {}
    for uid, info in USERS.items():
        priv_pem = _load_private_key_from_env(uid)
        demo_keys[uid] = {
            "role": info["role"],
            "public_key": info.get("public_key", ""),
            "private_key": priv_pem or ""
        }
    return jsonify(demo_keys), 200


@app.route("/api/queue/nurse", methods=["GET"])
def api_get_nurse_queue():
    with outpatient_lock:
        waiting = []
        printing = []
        for item in outpatient_state["queue"]:
            patient_id = item["patient_id"]
            p = outpatient_state["patients"].get(patient_id)
            if not p:
                continue
            
            if item["status"] == "NURSE":
                waiting.append({
                    "visit_id": p["id"],
                    "name": p["name"],
                    "age": p["age"],
                    "gender": p["gender"],
                    "department": p.get("department", "General Medicine")
                })
            elif item["status"] == "PRINT":
                v = p.get("vitals") or {}
                c = p.get("consultation") or {}
                printing.append({
                    "visit_id": p["id"],
                    "department": p.get("department", "General Medicine"),
                    "doctor_name": c.get("consulted_by", "DOC-505"),
                    "name": p["name"],
                    "age": p["age"],
                    "gender": p["gender"],
                    "phone": p["contact"],
                    "prescription_id": p["id"],
                    "diagnosis": c.get("diagnosis", ""),
                    "follow_up": c.get("follow_up_date", ""),
                    "temperature": v.get("temperature", ""),
                    "heart_rate": v.get("heart_rate", ""),
                    "bp": v.get("blood_pressure", ""),
                    "spo2": v.get("spo2", ""),
                    "weight": v.get("weight", ""),
                    "bmi": v.get("bmi", ""),
                    "medications": c.get("medications", [])
                })
    return jsonify({
        "waiting": waiting,
        "printing": printing
    }), 200


@app.route("/api/queue/doctor", methods=["GET"])
def api_get_doctor_queue():
    with outpatient_lock:
        waiting = []
        for item in outpatient_state["queue"]:
            if item["status"] == "DOCTOR":
                patient_id = item["patient_id"]
                p = outpatient_state["patients"].get(patient_id)
                if not p:
                    continue
                v = p.get("vitals") or {}
                waiting.append({
                    "visit_id": p["id"],
                    "name": p["name"],
                    "age": p["age"],
                    "gender": p["gender"],
                    "temperature": v.get("temperature", ""),
                    "bp": v.get("blood_pressure", ""),
                    "heart_rate": v.get("heart_rate", ""),
                    "bmi": v.get("bmi", ""),
                    "spo2": v.get("spo2", ""),
                    "weight": v.get("weight", "")
                })
    return jsonify(waiting), 200


@app.route("/api/register", methods=["POST"])
def api_register_patient():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON body."}), 400
        
    name = data.get("name")
    age = data.get("age")
    gender = data.get("gender")
    phone = data.get("phone") or data.get("contact")
    receptionist_id = data.get("receptionist_id")
    signature = data.get("signature")
    
    if not all([name, age, gender, phone, receptionist_id, signature]):
        return jsonify({"error": "Missing required fields (name, age, gender, phone, receptionist_id, signature)."}), 400

    if receptionist_id not in USERS:
        return jsonify({"error": "Unauthorized receptionist ID."}), 403

    # Accept patient ID from client, or generate a fallback
    patient_id = data.get("patient_id")
    if not patient_id:
        patient_id = f"PAT-{uuid.uuid4().hex[:8].upper()}"

    action = "REGISTER"
    medical_text = f"Patient Registered: {name}, Age {age}, Gender {gender}"
    medical_file_hash, file_name = save_off_chain_data(patient_id, medical_text)

    # Cryptographic validation of signature received from client
    success, message = hospital_chain.request_access(
        patient_id, receptionist_id, action, medical_file_hash, file_name, signature
    )
    if not success:
        return jsonify({"error": message}), 403

    patient = {
        "id": patient_id,
        "name": name,
        "age": int(age),
        "gender": gender,
        "contact": phone,
        "department": data.get("department", "General Medicine"),
        "registered_at": time.time(),
        "vitals": None,
        "consultation": None
    }

    with outpatient_lock:
        outpatient_state["patients"][patient_id] = patient
        outpatient_state["queue"].append({
            "patient_id": patient_id,
            "status": "NURSE",
            "joined_at": time.time(),
            "updated_at": time.time()
        })
        save_outpatient_state()

    announce_sync()
    return jsonify({
        "message": "Patient registered successfully and block sealed.",
        "patient_id": patient_id,
        "visit_id": patient_id
    }), 201


@app.route("/api/vitals", methods=["POST"])
def api_record_vitals():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON body."}), 400

    patient_id = data.get("visit_id")  # React UI sends visit_id representing patient ID
    nurse_id = data.get("nurse_id")
    height = data.get("height")
    weight = data.get("weight")
    bp = data.get("bp") or data.get("blood_pressure")
    temp = data.get("temp") or data.get("temperature")
    hr = data.get("hr") or data.get("heart_rate")
    spo2 = data.get("spo2") or data.get("spO2")
    signature = data.get("signature")

    if not all([patient_id, nurse_id, height, weight, bp, temp, hr, signature]):
        return jsonify({"error": "Missing required vitals fields or signature."}), 400

    if nurse_id not in USERS:
        return jsonify({"error": "Unauthorized nurse ID."}), 403

    with outpatient_lock:
        if patient_id not in outpatient_state["patients"]:
            return jsonify({"error": "Patient not found."}), 404

    # Calculate BMI
    h_m = float(height) / 100.0
    w_kg = float(weight)
    bmi = round(w_kg / (h_m * h_m), 2)

    vitals = {
        "height": float(height),
        "weight": float(weight),
        "bmi": bmi,
        "blood_pressure": bp,
        "temperature": float(temp),
        "heart_rate": int(hr),
        "spo2": int(spo2) if spo2 else 98,
        "recorded_at": time.time(),
        "recorded_by": nurse_id
    }

    # Cryptographic validation of signature received from client
    action = "VITALS"
    medical_text = (
        f"Vitals Recorded: Height {height}cm, Weight {weight}kg, BMI {bmi}, "
        f"BP {bp}, Temp {temp}C, HR {hr}bpm"
    )
    medical_file_hash, file_name = save_off_chain_data(patient_id, medical_text)

    success, message = hospital_chain.request_access(
        patient_id, nurse_id, action, medical_file_hash, file_name, signature
    )
    if not success:
        return jsonify({"error": message}), 403

    with outpatient_lock:
        outpatient_state["patients"][patient_id]["vitals"] = vitals
        for item in outpatient_state["queue"]:
            if item["patient_id"] == patient_id:
                item["status"] = "DOCTOR"
                item["updated_at"] = time.time()
                break
        save_outpatient_state()

    announce_sync()
    return jsonify({
        "message": "Patient vitals recorded successfully and block sealed.",
        "bmi": bmi
    }), 201


@app.route("/api/prescribe", methods=["POST"])
def api_record_consultation():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON body."}), 400

    patient_id = data.get("visit_id")
    doctor_id = data.get("doctor_id")
    diagnosis = data.get("diagnosis")
    medications = data.get("medications", [])
    follow_up = data.get("follow_up")
    signature = data.get("signature")

    if not all([patient_id, doctor_id, diagnosis, signature]):
        return jsonify({"error": "Missing required prescription fields or signature."}), 400

    if doctor_id not in USERS:
        return jsonify({"error": "Unauthorized doctor ID."}), 403

    with outpatient_lock:
        if patient_id not in outpatient_state["patients"]:
            return jsonify({"error": "Patient not found."}), 404

    consultation = {
        "diagnosis": diagnosis,
        "medications": medications,
        "follow_up_date": follow_up,
        "consulted_at": time.time(),
        "consulted_by": doctor_id
    }

    # Cryptographic validation of signature received from client
    action = "PRESCRIPTION"
    meds_str = ", ".join(
        [f"{m['name']} ({m['dose']} {m['frequency']} x {m['duration']}d)" for m in medications]
    )
    medical_text = f"Diagnosis: {diagnosis}. Prescribed: {meds_str}. Follow-up: {follow_up or 'None'}."
    medical_file_hash, file_name = save_off_chain_data(patient_id, medical_text)

    success, message = hospital_chain.request_access(
        patient_id, doctor_id, action, medical_file_hash, file_name, signature
    )
    if not success:
        return jsonify({"error": message}), 403

    with outpatient_lock:
        outpatient_state["patients"][patient_id]["consultation"] = consultation
        for item in outpatient_state["queue"]:
            if item["patient_id"] == patient_id:
                item["status"] = "PRINT"
                item["updated_at"] = time.time()
                break
        save_outpatient_state()

    announce_sync()
    return jsonify({
        "message": "Consultation prescription sealed successfully.",
        "prescription_hash": medical_file_hash
    }), 201


@app.route("/api/print/complete", methods=["POST"])
def api_complete_print():
    data = request.get_json() or {}
    patient_id = data.get("visit_id")
    if not patient_id:
        return jsonify({"error": "Missing visit_id."}), 400

    with outpatient_lock:
        outpatient_state["queue"] = [
            item for item in outpatient_state["queue"]
            if item["patient_id"] != patient_id
        ]
        save_outpatient_state()

    announce_sync()
    return jsonify({"message": "Session finalized successfully"}), 200


if __name__ == "__main__":
    # LOW-2 fix: host from env — defaults to 127.0.0.1 (localhost only)
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=False, use_reloader=False)
