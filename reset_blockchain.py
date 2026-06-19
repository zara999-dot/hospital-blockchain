import os
import json
import urllib.request
import urllib.error

# Paths
BASE_DIR = r"c:\Users\Rishika\OneDrive\Desktop\code\antigravity\delulu squard"
LEDGER_PATH = os.path.join(BASE_DIR, "ledger.json")
OUTPATIENTS_PATH = os.path.join(BASE_DIR, "outpatient_data.json")
OFF_CHAIN_DIR = os.path.join(BASE_DIR, "off_chain_data")
ENV_PATH = os.path.join(BASE_DIR, ".env")

print("1. Reading .env for configuration...")
reset_token = ""
port = 5000
host = "127.0.0.1"

if os.path.exists(ENV_PATH):
    with open(ENV_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("RESET_TOKEN="):
                reset_token = line.split("=", 1)[1].strip()
            elif line.startswith("FLASK_PORT="):
                try:
                    port = int(line.split("=", 1)[1].strip())
                except ValueError:
                    pass
            elif line.startswith("FLASK_HOST="):
                host = line.split("=", 1)[1].strip()

print(f"   Found RESET_TOKEN: {reset_token[:6]}... if present")
print(f"   Server host/port: {host}:{port}")

# Reset on-disk outpatient state
print("\n2. Resetting outpatient_data.json on disk...")
empty_outpatients = {"patients": {}, "queue": []}
try:
    with open(OUTPATIENTS_PATH, "w", encoding="utf-8") as f:
        json.dump(empty_outpatients, f, indent=2)
    print("   outpatient_data.json reset successfully.")
except Exception as e:
    print(f"   Failed to reset outpatient_data.json: {e}")

# Call Flask reset endpoint if server is running
server_url = f"http://{host}:{port}/reset"
if reset_token:
    url_with_token = f"{server_url}?token={reset_token}"
    print(f"\n3. Attempting to call running server reset endpoint at {server_url}...")
    try:
        req = urllib.request.Request(url_with_token, method="POST")
        with urllib.request.urlopen(req, timeout=5) as response:
            res_body = response.read().decode("utf-8")
            print(f"   Server responded: {res_body}")
            print("   In-memory ledger and off-chain data cleared by server successfully.")
            # Since server is running and cleared files, we are done with ledger & off-chain files.
            # But let's verify if they are indeed cleared/reset.
            exit(0)
    except urllib.error.URLError as e:
        print(f"   Could not connect to running server (expected if server is stopped): {e}")
    except Exception as e:
        print(f"   Error calling reset API: {e}")

# Fallback: manually reset files on disk if server not running or reset token missing
print("\n4. Falling back to manual file cleanup on disk...")

# 4a. Reset/Delete ledger.json
if os.path.exists(LEDGER_PATH):
    try:
        os.remove(LEDGER_PATH)
        print("   ledger.json deleted successfully.")
    except Exception as e:
        print(f"   Error deleting ledger.json: {e}")
else:
    print("   ledger.json already does not exist.")

# 4b. Clear off_chain_data files
if os.path.isdir(OFF_CHAIN_DIR):
    print(f"   Clearing files in {OFF_CHAIN_DIR}...")
    for fname in os.listdir(OFF_CHAIN_DIR):
        fpath = os.path.join(OFF_CHAIN_DIR, fname)
        if os.path.isfile(fpath):
            try:
                os.remove(fpath)
                print(f"   Deleted off-chain file: {fname}")
            except Exception as e:
                print(f"   Error deleting {fname}: {e}")
else:
    print("   off_chain_data directory does not exist.")

print("\nBlockchain reset process completed.")
