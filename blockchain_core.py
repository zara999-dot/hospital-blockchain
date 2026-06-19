"""
================================================================================
  STAGE 1 — THE CRYPTOGRAPHIC CORE (The Blockchain Engine)
  Healthcare Audit Blockchain · Private Ledger
================================================================================

  This module implements the raw mathematical engine behind a private
  blockchain designed for hospital audit trails.

  Every medical access event (VIEW, UPDATE, DELETE …) is sealed inside a
  Block whose SHA-256 hash depends on the block's own data *and* the hash
  of the block that came before it.  Changing even a single character in
  any historical block breaks the chain — making tampering immediately
  detectable.

  Classes
  -------
  Block       – One immutable record in the ledger.
  Blockchain  – The ordered chain of Blocks + validation logic.
================================================================================
"""

import hashlib
import json
import sys
from datetime import datetime, timezone

# Ensure the console can handle our output on Windows
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


# ──────────────────────────────────────────────────────────────────────────────
#  Block
# ──────────────────────────────────────────────────────────────────────────────

class Block:
    """A single block in the healthcare audit blockchain.

    Attributes
    ----------
    index : int
        Position of the block in the chain (0 = genesis).
    timestamp : str
        ISO-8601 UTC timestamp of when the block was created.
    patient_id : str
        Identifier of the patient whose record was accessed.
    doctor_id : str
        Identifier of the medical professional who performed the action.
    action : str
        The type of access event — e.g. VIEW, UPDATE, CREATE, DELETE.
    medical_file_hash : str
        SHA-256 fingerprint of the actual medical document stored off-chain.
        The blockchain never stores raw patient data — only this hash.
    previous_hash : str
        Hash of the preceding block, forming the cryptographic chain.
    hash : str
        SHA-256 hash of *this* block's contents (computed on creation).
    """

    def __init__(
        self,
        index: int,
        patient_id: str,
        doctor_id: str,
        action: str,
        medical_file_hash: str,
        previous_hash: str,
        timestamp: str = None,   # LOW-3 fix: accept stored timestamp for reload
    ):
        self.index = index
        # If reloading from persisted data, preserve the original timestamp;
        # otherwise stamp the block with the current UTC time.
        self.timestamp = timestamp if timestamp is not None else datetime.now(timezone.utc).isoformat()
        self.patient_id = patient_id
        self.doctor_id = doctor_id
        self.action = action
        self.medical_file_hash = medical_file_hash
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()


    # ── hashing ──────────────────────────────────────────────────────────

    def calculate_hash(self) -> str:
        """Produce a deterministic SHA-256 digest of every field in the block.

        The digest covers *all* mutable-looking fields so that any
        after-the-fact change — timestamp, patient ID, action, or even
        the previous-hash pointer — will cause a mismatch.
        """
        block_contents = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "patient_id": self.patient_id,
                "doctor_id": self.doctor_id,
                "action": self.action,
                "medical_file_hash": self.medical_file_hash,
                "previous_hash": self.previous_hash,
            },
            sort_keys=True,
        )
        return hashlib.sha256(block_contents.encode("utf-8")).hexdigest()

    # ── display ──────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return (
            f"Block(index={self.index}, action={self.action!r}, "
            f"patient={self.patient_id!r}, doctor={self.doctor_id!r})"
        )

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dictionary of the block."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "patient_id": self.patient_id,
            "doctor_id": self.doctor_id,
            "action": self.action,
            "medical_file_hash": self.medical_file_hash,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
        }


# ──────────────────────────────────────────────────────────────────────────────
#  Blockchain
# ──────────────────────────────────────────────────────────────────────────────

class Blockchain:
    """A private blockchain ledger for healthcare audit events.

    The chain begins with a hard-coded *genesis block* (index 0) whose
    ``previous_hash`` is ``"0"`` by convention.  Every subsequent block
    cryptographically references the one before it.
    """

    def __init__(self):
        self.chain: list[Block] = []
        self._create_genesis_block()

    # ── genesis ──────────────────────────────────────────────────────────

    def _create_genesis_block(self) -> None:
        """Initialise the chain with a special genesis block."""
        genesis = Block(
            index=0,
            patient_id="SYSTEM",
            doctor_id="SYSTEM",
            action="GENESIS",
            medical_file_hash="0" * 64,      # 64 hex zeros
            previous_hash="0",
        )
        self.chain.append(genesis)

    # ── adding blocks ────────────────────────────────────────────────────

    def add_block(
        self,
        patient_id: str,
        doctor_id: str,
        action: str,
        medical_file_hash: str,
    ) -> Block:
        """Create a new block chained to the current tail and append it.

        Parameters
        ----------
        patient_id : str
            The patient whose record is being accessed.
        doctor_id : str
            The doctor performing the action.
        action : str
            ACCESS event type (VIEW, UPDATE, CREATE, DELETE …).
        medical_file_hash : str
            SHA-256 hash of the off-chain medical document.

        Returns
        -------
        Block
            The newly created and appended block.
        """
        previous_block = self.chain[-1]
        new_block = Block(
            index=len(self.chain),
            patient_id=patient_id,
            doctor_id=doctor_id,
            action=action,
            medical_file_hash=medical_file_hash,
            previous_hash=previous_block.hash,
        )
        self.chain.append(new_block)
        return new_block

    # ── validation ───────────────────────────────────────────────────────

    def is_chain_valid(self) -> tuple[bool, str]:
        """Walk the entire chain and verify cryptographic integrity.

        Two checks are performed on every block (after the genesis):

        1. **Self-consistency** — recalculating the block's hash from its
           stored fields must reproduce ``block.hash``.
        2. **Link integrity** — ``block.previous_hash`` must equal the
           hash of the preceding block.

        Returns
        -------
        tuple[bool, str]
            ``(True, "Chain is valid …")`` on success, or
            ``(False, "<description of first violation>")`` on failure.
        """
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            # Check 1 — has the block's own data been altered?
            recalculated = current.calculate_hash()
            if current.hash != recalculated:
                return (
                    False,
                    f"Block {current.index}: stored hash does not match "
                    f"recalculated hash.  Data has been tampered with!\n"
                    f"  stored:       {current.hash}\n"
                    f"  recalculated: {recalculated}",
                )

            # Check 2 — does this block correctly point to its predecessor?
            if current.previous_hash != previous.hash:
                return (
                    False,
                    f"Block {current.index}: previous_hash does not match "
                    f"the hash of Block {previous.index}.  "
                    f"Chain link is broken!\n"
                    f"  block.previous_hash: {current.previous_hash}\n"
                    f"  previous.hash:       {previous.hash}",
                )

        return (True, f"Chain is valid. {len(self.chain)} blocks verified.")

    # -- display ----------------------------------------------------------

    def print_chain(self) -> None:
        """Pretty-print every block in the ledger."""
        print("\n" + "=" * 72)
        print("  HEALTHCARE AUDIT BLOCKCHAIN -- FULL LEDGER")
        print("=" * 72)
        for block in self.chain:
            print(f"\n  +--- Block {block.index} {'-' * (55 - len(str(block.index)))}")
            print(f"  |  Timestamp        : {block.timestamp}")
            print(f"  |  Patient ID       : {block.patient_id}")
            print(f"  |  Doctor ID        : {block.doctor_id}")
            print(f"  |  Action           : {block.action}")
            print(f"  |  Medical File Hash: {block.medical_file_hash[:32]}...")
            print(f"  |  Previous Hash    : {block.previous_hash[:32]}...")
            print(f"  |  Block Hash       : {block.hash[:32]}...")
            print(f"  +{'-' * 67}")
        print()


# ------------------------------------------------------------------------------
#  Helper -- simulate hashing a medical file
# ------------------------------------------------------------------------------

def hash_medical_text(text: str) -> str:
    """Return the SHA-256 hex digest of raw medical text.

    In a real system this would hash the bytes of an actual file stored
    in off-chain storage.  Here we use it to simulate that fingerprint.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
#  DEMO — run this file directly to see the blockchain in action
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":

    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

    print(f"\n{BOLD}{CYAN}{'═' * 72}")
    print("  STAGE 1 · THE CRYPTOGRAPHIC CORE")
    print("  Healthcare Audit Blockchain — Demo")
    print(f"{'═' * 72}{RESET}\n")

    # 1. Create the ledger ────────────────────────────────────────────────
    ledger = Blockchain()
    print(f"{YELLOW}▸ Genesis block created.{RESET}")

    # 2. Simulate two medical access events ───────────────────────────────

    # Event A — Dr. Patel views Patient #1042's blood-work report
    file_hash_a = hash_medical_text(
        "Patient 1042 — CBC results: WBC 7.2, RBC 4.8, Hgb 14.1 g/dL"
    )
    block_a = ledger.add_block(
        patient_id="PAT-1042",
        doctor_id="DR-PATEL",
        action="VIEW",
        medical_file_hash=file_hash_a,
    )
    print(f"{YELLOW}▸ Block {block_a.index} added — "
          f"Dr. Patel VIEWED Patient 1042's blood-work report.{RESET}")

    # Event B — Dr. Nguyen updates Patient #2087's prescription
    file_hash_b = hash_medical_text(
        "Patient 2087 — Rx: Amoxicillin 500 mg TID × 10 days. "
        "Previous Rx: Ibuprofen 400 mg PRN discontinued."
    )
    block_b = ledger.add_block(
        patient_id="PAT-2087",
        doctor_id="DR-NGUYEN",
        action="UPDATE",
        medical_file_hash=file_hash_b,
    )
    print(f"{YELLOW}▸ Block {block_b.index} added — "
          f"Dr. Nguyen UPDATED Patient 2087's prescription.{RESET}")

    # 3. Print the full ledger ────────────────────────────────────────────
    ledger.print_chain()

    # 4. Validate the untouched chain ─────────────────────────────────────
    print(f"{BOLD}── Validation Check #1: Original chain ──{RESET}")
    valid, message = ledger.is_chain_valid()
    if valid:
        print(f"   {GREEN}✔ {message}{RESET}\n")
    else:
        print(f"   {RED}✘ {message}{RESET}\n")

    # 5. Tamper with a block and re-validate ──────────────────────────────
    print(f"{BOLD}── Tampering Simulation ──{RESET}")
    print(f"   {RED}⚠  Changing Block 1's action from 'VIEW' to 'DELETE'…{RESET}")
    ledger.chain[1].action = "DELETE"          # Malicious edit!

    print(f"\n{BOLD}── Validation Check #2: After tampering ──{RESET}")
    valid, message = ledger.is_chain_valid()
    if valid:
        print(f"   {GREEN}✔ {message}{RESET}\n")
    else:
        print(f"   {RED}✘ INTEGRITY VIOLATION DETECTED{RESET}")
        print(f"   {RED}{message}{RESET}\n")

    print(f"{CYAN}{'═' * 72}")
    print("  Demo complete. The chain caught the tampered block.")
    print(f"{'═' * 72}{RESET}\n")
