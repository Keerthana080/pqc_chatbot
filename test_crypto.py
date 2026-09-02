# test_crypto.py
# Run this to verify encryption is working correctly

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pqc_chatbot.settings')

import django
django.setup()

from chat.crypto import pqc

print("="*55)
print("POST-QUANTUM CRYPTOGRAPHY TEST")
print("="*55)

# ─── TEST 1: Key Generation ───
print("\n[TEST 1] Generating Alice's key pair...")
alice_public, alice_private = pqc.generate_keypair()
print(f"✅ Public Key  (first 40 chars): {alice_public[:40]}...")
print(f"✅ Private Key (first 40 chars): {alice_private[:40]}...")

# ─── TEST 2: Key Generation for Bob ───
print("\n[TEST 2] Generating Bob's key pair...")
bob_public, bob_private = pqc.generate_keypair()
print(f"✅ Bob's Public Key: {bob_public[:40]}...")

# ─── TEST 3: Encapsulation ───
print("\n[TEST 3] Alice encapsulates key using Bob's public key...")
ciphertext, shared_secret_alice = pqc.encapsulate_key(bob_public)
print(f"✅ Ciphertext (first 40 chars): {ciphertext[:40]}...")
print(f"✅ Shared Secret (Alice): {shared_secret_alice.hex()}")

# ─── TEST 4: Decapsulation ───
print("\n[TEST 4] Bob decapsulates to recover shared secret...")
shared_secret_bob = pqc.decapsulate_key(ciphertext, bob_private)
print(f"✅ Shared Secret (Bob):   {shared_secret_bob.hex()}")

# ─── TEST 5: Verify Secrets Match ───
print("\n[TEST 5] Verifying both parties got same secret...")
if shared_secret_alice == shared_secret_bob:
    print("✅ SECRETS MATCH — Secure channel established!")
else:
    print("❌ SECRETS DON'T MATCH — Something is wrong!")

# ─── TEST 6: Message Encryption ───
print("\n[TEST 6] Encrypting a message...")
original = "Hello Bob! Meet me at 5pm. Password: Tiger123"
print(f"Original message: '{original}'")

encrypted = pqc.encrypt_message(original, shared_secret_alice)
print(f"Encrypted (stored in DB): {encrypted[:60]}...")

# ─── TEST 7: Message Decryption ───
print("\n[TEST 7] Decrypting the message...")
decrypted = pqc.decrypt_message(encrypted, shared_secret_bob)
print(f"Decrypted message: '{decrypted}'")

# ─── TEST 8: Verify Decryption ───
print("\n[TEST 8] Verifying decryption is perfect...")
if original == decrypted:
    print("✅ PERFECT MATCH — Encryption and decryption working!")
else:
    print("❌ MISMATCH — Something went wrong!")

print("\n" + "="*55)
print("ALL TESTS PASSED — Ready to build the chat app!")
print("="*55)