import hashlib
import time
import json

# --- MOCK DATABASE ---
# Simulates a user directory with Roles and Private Keys
USERS = {
    "DOC-505": {"role": "Doctor", "private_key": "secret_doc_key_505"},
    "DOC-911": {"role": "Doctor", "private_key": "secret_doc_key_911"},
    "REC-101": {"role": "Receptionist", "private_key": "secret_rec_key_101"}
}

def generate_signature(private_key, patient_id, action):
    """
    SIMULATION ONLY — NOT CRYPTOGRAPHICALLY SECURE.

    This function produces a plain SHA-256 hash of the private key string
    concatenated with the message.  It is NOT a digital signature:
      - It provides no asymmetric properties.
      - Anyone who knows the private key string can generate the same output.
      - You cannot verify it without the private key (breaking key separation).
      - It is vulnerable to length-extension and pre-image attacks.

    This file exists solely as an educational prototype (Stage 2 demo).
    For real ECDSA signing and verification, see app.py:
        generate_signature()  →  uses cryptography.hazmat ECDSA + SECP256R1
        verify_signature()    →  verifies with the PUBLIC key only

    DO NOT copy this implementation into production code.
    """
    message = f"{patient_id}:{action}"
    signature = hashlib.sha256(f"{private_key}:{message}".encode()).hexdigest()
    return signature

def verify_signature(user_id, patient_id, action, signature):
    """
    SIMULATION ONLY — NOT CRYPTOGRAPHICALLY SECURE.

    Verification here requires the private key, which defeats the purpose of
    asymmetric cryptography.  A real system verifies using the PUBLIC key only
    so the verifier never needs (or holds) the private key.

    See app.py → verify_signature() for the correct ECDSA implementation.
    """
    user = USERS.get(user_id)
    if not user:
        return False
    expected_signature = generate_signature(user["private_key"], patient_id, action)
    return signature == expected_signature

class Block:
    def __init__(self, index, patient_id, user_id, action, medical_file_hash, previous_hash, signature=""):
        self.index = index
        self.timestamp = time.time()
        self.patient_id = patient_id
        self.user_id = user_id # Renamed from doctor_id since other roles might trigger it
        self.action = action
        self.medical_file_hash = medical_file_hash
        self.signature = signature
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "patient_id": self.patient_id,
            "user_id": self.user_id,
            "action": self.action,
            "medical_file_hash": self.medical_file_hash,
            "signature": self.signature,
            "previous_hash": self.previous_hash
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, "0", "0", "GENESIS", "0", "0")

    def get_latest_block(self):
        return self.chain[-1]

    def request_access(self, patient_id, user_id, action, medical_file_hash, signature):
        """
        Handles an access request to the blockchain, applying RBAC and Signature verification.
        """
        # 1. Verify Digital Signature (Non-repudiation)
        if not verify_signature(user_id, patient_id, action, signature):
            print(f"[!] INVALID SIGNATURE from {user_id}. Access denied.")
            return

        # 2. Role-Based Access Control (RBAC)
        user_role = USERS[user_id]["role"]
        
        # Check if the user is a 'Doctor' before allowing them to modify/access
        is_authorized = False
        if user_role == "Doctor" and action in ["VIEW", "UPDATE"]:
            is_authorized = True

        new_index = len(self.chain)
        previous_hash = self.get_latest_block().hash

        if is_authorized:
            print(f"[+] Authorized access: {user_role} {user_id} performing {action} on {patient_id}.")
            new_block = Block(new_index, patient_id, user_id, action, medical_file_hash, previous_hash, signature)
        else:
            print(f"[!] UNAUTHORIZED ROLE: {user_role} {user_id} attempted {action} on {patient_id}.")
            new_block = Block(new_index, patient_id, user_id, "UNAUTHORIZED_ATTEMPT", "NONE", previous_hash, signature)
        
        self.add_block(new_block)

    def add_block(self, new_block):
        # We assume the new_block already got the correct previous_hash via request_access
        self.chain.append(new_block)

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            if current_block.hash != current_block.calculate_hash():
                return False

            if current_block.previous_hash != previous_block.hash:
                return False

        return True

if __name__ == "__main__":
    hospital_chain = Blockchain()

    print("--- Stage 2: Digital Signatures & RBAC Demo ---")

    # Scenario 1: A legitimate Doctor updating a record
    print("\nScenario 1: Doctor tries to update a record.")
    doc_id = "DOC-505"
    patient = "PAT-1001"
    action = "UPDATE"
    doc_signature = generate_signature(USERS[doc_id]["private_key"], patient, action)
    hospital_chain.request_access(patient, doc_id, action, "file_hash_123", doc_signature)

    # Scenario 2: A Receptionist trying to update a record (Unauthorized)
    print("\nScenario 2: Receptionist tries to update a record.")
    rec_id = "REC-101"
    patient2 = "PAT-1002"
    action2 = "UPDATE"
    rec_signature = generate_signature(USERS[rec_id]["private_key"], patient2, action2)
    hospital_chain.request_access(patient2, rec_id, action2, "file_hash_456", rec_signature)

    # Scenario 3: Someone forging a request pretending to be DOC-911
    print("\nScenario 3: Forged signature attempt.")
    fake_signature = "this_is_a_made_up_signature"
    hospital_chain.request_access("PAT-1003", "DOC-911", "VIEW", "file_hash_789", fake_signature)

    # Output final chain
    print("\n--- Final Blockchain Ledger ---")
    for block in hospital_chain.chain:
        if block.index == 0:
            continue # Skip genesis
        print(f"Block {block.index} | User: {block.user_id} | Action: {block.action} | File Hash: {block.medical_file_hash}")
