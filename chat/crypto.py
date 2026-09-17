# chat/crypto.py

"""
POST-QUANTUM CRYPTOGRAPHY ENGINE
==================================
This file is the heart of our security system.

It handles:
1. Generating Kyber-512 key pairs for users
2. Kyber key encapsulation (sharing a secret safely)
3. Kyber key decapsulation (recovering the shared secret)
4. Dilithium signing keypair generation
5. Dilithium signing / verification
6. AES-GCM message encryption
7. AES-GCM message decryption

IMPORTANT CONCEPT:
We use THREE algorithms together:

KYBER-512   -> Solves the key exchange problem (quantum-safe)
               "How do Alice and Bob agree on a secret key
                without anyone intercepting it?"

DILITHIUM2  -> Solves the authenticity problem (quantum-safe)
               "How do we prove WHO sent a message, and that
                it wasn't altered since it was signed?"

AES-256-GCM -> Solves the message encryption problem (fast)
               "How do we actually lock the message?"
"""

import os
import base64
import json
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kyber_py.ml_kem import ML_KEM_512
from dilithium_py.ml_dsa import ML_DSA_44


class KyberSimulation:
    """
    Real Kyber-512 key encapsulation, via the kyber-py library's
    ML_KEM_512 implementation (NIST FIPS 203).

    NOTE FOR YOUR VIVA:
    This class is still named "KyberSimulation" for historical reasons
    (it started as a hash-based stand-in). It now wraps a REAL,
    standards-compliant ML-KEM-512 implementation, not a simulation.
    The lattice/LWE math, noise sampling, and NTT polynomial
    arithmetic all happen inside kyber_py itself.

    This class exists as a thin adapter layer so the rest of the app
    (utils.py, views.py) never has to import kyber_py directly, and
    so keys/ciphertexts move around the app as base64 strings (easy
    to store in Django's CharField/TextField columns) instead of
    raw bytes.
    """

    def __init__(self):
        self.algorithm_name = "Kyber-512 (ML-KEM, FIPS 203)"
        self._kem = ML_KEM_512

        # Real Kyber-512 sizes, in bytes -- these are now ACTUAL
        # measured sizes of what generate_keypair()/encapsulate_key()
        # produce, not just numbers quoted for a report.
        self.PUBLIC_KEY_SIZE    = 800
        self.PRIVATE_KEY_SIZE   = 1632
        self.CIPHERTEXT_SIZE    = 768
        self.SHARED_SECRET_SIZE = 32

    def generate_keypair(self):
        """
        STEP 1: Key Generation
        ------------------------
        Runs real ML-KEM-512 keygen: samples a secret key from a
        centered binomial distribution, builds a public key as
        A*s + e over a polynomial ring (the actual Learning-With-
        Errors construction), where A is a public random matrix.

        Returns:
            public_key_b64  (str): Share freely with anyone
            private_key_b64 (str): NEVER share -- keep secret
        """
        ek, dk = self._kem.keygen()  # ek = encapsulation (public) key
                                      # dk = decapsulation (private) key
        public_key_b64  = base64.b64encode(ek).decode('utf-8')
        private_key_b64 = base64.b64encode(dk).decode('utf-8')
        return public_key_b64, private_key_b64

    def encapsulate_key(self, recipient_public_key_b64):
        """
        STEP 2: Key Encapsulation (the SENDER runs this)
        ---------------------------------------------------
        Real ML-KEM encapsulation: samples fresh randomness, encrypts
        it against the recipient's public key using the underlying
        K-PKE scheme, and derives the shared secret via a hash of
        that randomness + a hash of the ciphertext (the FO transform,
        which is what makes ML-KEM secure against chosen-ciphertext
        attacks, not just chosen-plaintext).

        Args:
            recipient_public_key_b64 (str): recipient's public key

        Returns:
            ciphertext_b64 (str): send this to the recipient
            shared_secret  (bytes): 32-byte AES key, keep locally
        """
        recipient_public_key = base64.b64decode(recipient_public_key_b64)
        shared_secret, ciphertext = self._kem.encaps(recipient_public_key)
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')
        return ciphertext_b64, shared_secret

    def decapsulate_key(self, ciphertext_b64, private_key_b64):
        """
        STEP 3: Key Decapsulation (the RECEIVER runs this)
        ------------------------------------------------------
        Real ML-KEM decapsulation: uses the private key to invert
        the K-PKE encryption and recover the sender's randomness,
        re-derives what the ciphertext *should* look like, and only
        returns the real shared secret if it matches (otherwise
        returns an indistinguishable pseudorandom value -- this is
        the implicit-rejection defense against ciphertext-tampering
        attacks, built into the FIPS 203 standard itself).

        Args:
            ciphertext_b64  (str): received from sender
            private_key_b64 (str): your own private key

        Returns:
            shared_secret (bytes): same 32-byte secret the sender had
        """
        ciphertext  = base64.b64decode(ciphertext_b64)
        private_key = base64.b64decode(private_key_b64)
        shared_secret = self._kem.decaps(private_key, ciphertext)
        return shared_secret


class DilithiumSignature:
    """
    Real Dilithium digital signatures, via the dilithium-py library's
    ML_DSA_44 implementation (NIST FIPS 204).

    This solves a DIFFERENT problem from Kyber:
        Kyber      -> "How do two parties agree on a secret key?"
        Dilithium  -> "How do we prove WHO sent this message,
                       and that it wasn't altered since signing?"

    A signature is NOT encryption -- signing a message doesn't hide
    its contents, and anyone with the signer's public key can verify
    it. What a valid signature proves is: "the holder of this specific
    private key produced this exact signature over this exact data."
    That's authenticity (proof of sender) and integrity (proof of
    no alteration since signing) -- the two properties your abstract
    lists alongside confidentiality.
    """

    def __init__(self):
        self.algorithm_name = "Dilithium2 (ML-DSA-44, FIPS 204)"
        self._dsa = ML_DSA_44

        # Real ML-DSA-44 sizes, in bytes.
        self.PUBLIC_KEY_SIZE  = 1312
        self.PRIVATE_KEY_SIZE = 2560
        self.SIGNATURE_SIZE   = 2420

    def generate_signing_keypair(self):
        """
        Generates a Dilithium keypair. Every user needs their OWN
        signing keypair, separate from their Kyber encryption keypair
        -- these are two unrelated cryptographic tools.

        Returns:
            public_key_b64  (str): share with anyone who needs to
                                    verify this user's signatures
            private_key_b64 (str): NEVER share -- only the real user
                                    should be able to sign as themself
        """
        pk, sk = self._dsa.keygen()
        public_key_b64  = base64.b64encode(pk).decode('utf-8')
        private_key_b64 = base64.b64encode(sk).decode('utf-8')
        return public_key_b64, private_key_b64

    def sign(self, message_bytes, private_key_b64):
        """
        Signs arbitrary bytes with the signer's private key.

        Args:
            message_bytes    (bytes): what to sign -- in this app,
                                       the encrypted_content string,
                                       encoded to bytes
            private_key_b64  (str):   signer's own private key

        Returns:
            signature_b64 (str): attach this alongside the message
        """
        private_key = base64.b64decode(private_key_b64)
        signature = self._dsa.sign(private_key, message_bytes)
        return base64.b64encode(signature).decode('utf-8')

    def verify(self, message_bytes, signature_b64, public_key_b64):
        """
        Verifies a signature against the CLAIMED signer's public key.

        Returns True only if:
          1. The signature was produced by the private key matching
             this exact public key, AND
          2. message_bytes is exactly what was originally signed
             (any alteration, even one bit, fails verification).

        Returns False on any mismatch or malformed input -- never
        raises, so callers can safely check this in a display loop
        without wrapping every call in try/except.
        """
        try:
            signature   = base64.b64decode(signature_b64)
            public_key  = base64.b64decode(public_key_b64)
            return self._dsa.verify(public_key, message_bytes, signature)
        except Exception:
            return False


class MessageEncryption:
    """
    AES-256-GCM Message Encryption
    ================================
    Once we have a shared secret from Kyber,
    we use it to encrypt actual messages.
    
    WHY AES-GCM specifically?
    
    AES     -> Advanced Encryption Standard
              The global standard for symmetric encryption
              Used by banks, governments, military worldwide
              
    GCM     -> Galois/Counter Mode
              This is the MODE of operation for AES
              
    GCM gives us TWO things at once:
    1. CONFIDENTIALITY -> No one can read the message
    2. INTEGRITY       -> If someone tampers with the message,
                          decryption FAILS (you know it was tampered)
    
    The second property is crucial:
    Without integrity checking, a clever attacker could modify
    your encrypted message in a way that changes the decrypted
    result without you knowing.
    """
    
    def encrypt(self, plaintext, shared_secret):
        """
        Encrypt a message using AES-256-GCM.
        
        Args:
            plaintext     (str):   Original message "Hello Bob!"
            shared_secret (bytes): 32-byte key from Kyber
            
        Returns:
            encrypted_package (str): JSON string containing:
                - nonce: random value (needed for decryption)
                - ciphertext: the encrypted message
                
        WHAT IS A NONCE?
        -----------------
        Nonce = "Number used ONCE"
        It's a random 12-byte value generated fresh for EACH message.
        
        Why needed?
        If you encrypt "Hello" twice with the same key:
        Without nonce: both produce SAME ciphertext
                       -> attacker knows you sent same message twice
        With nonce:    both produce DIFFERENT ciphertexts
                       -> attacker learns nothing
        
        The nonce is NOT secret -- it's sent with the ciphertext.
        Its only job is to ensure each encryption is unique.
        """
        
        # Use first 32 bytes of shared secret as AES key
        aes_key = shared_secret[:32]
        
        # Generate fresh random nonce (12 bytes = 96 bits for GCM)
        nonce = os.urandom(12)
        
        # Create AES-GCM cipher object
        aesgcm = AESGCM(aes_key)
        
        # Encrypt
        # The 'None' is for "additional authenticated data" 
        # (optional extra data to authenticate but not encrypt)
        message_bytes   = plaintext.encode('utf-8')
        encrypted_bytes = aesgcm.encrypt(nonce, message_bytes, None)
        
        # Package nonce + ciphertext together (both needed for decryption)
        package = {
            'nonce'      : base64.b64encode(nonce).decode('utf-8'),
            'ciphertext' : base64.b64encode(encrypted_bytes).decode('utf-8'),
            'algorithm'  : 'AES-256-GCM'
        }
        
        return json.dumps(package)
    
    def decrypt(self, encrypted_package_str, shared_secret):
        """
        Decrypt a message using AES-256-GCM.
        
        Args:
            encrypted_package_str (str):   The JSON string from encrypt()
            shared_secret         (bytes): Same 32-byte key from Kyber
            
        Returns:
            plaintext (str): Original message "Hello Bob!"
            
        WHAT IF SOMEONE TAMPERED WITH THE MESSAGE?
        --------------------------------------------
        AES-GCM will raise an InvalidTag exception.
        The decryption simply FAILS -- safely.
        You know the message was tampered with.
        This is the INTEGRITY property of GCM.
        """
        
        aes_key = shared_secret[:32]
        
        # Unpack the JSON
        package    = json.loads(encrypted_package_str)
        nonce      = base64.b64decode(package['nonce'])
        ciphertext = base64.b64decode(package['ciphertext'])
        
        aesgcm = AESGCM(aes_key)
        
        # Decrypt -- raises exception if tampered
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        
        return decrypted_bytes.decode('utf-8')


class PostQuantumCrypto:
    """
    Main interface combining Kyber + Dilithium + AES.
    
    This is the class all other files import and use.
    It ties together:
    - KyberSimulation (key exchange)
    - DilithiumSignature (authenticity / signing)
    - MessageEncryption (actual message locking)
    
    Usage example:
        pqc = PostQuantumCrypto()
        
        # Generate keys for a user
        pub, priv = pqc.generate_keypair()
        sign_pub, sign_priv = pqc.generate_signing_keypair()
        
        # Sender: create shared secret, encrypt, sign
        ciphertext, secret = pqc.encapsulate_key(pub)
        encrypted_msg = pqc.encrypt_message("Hello!", secret)
        signature = pqc.sign_message(encrypted_msg, sign_priv)
        
        # Receiver: recover same shared secret, decrypt, verify
        same_secret = pqc.decapsulate_key(ciphertext, priv)
        original_msg = pqc.decrypt_message(encrypted_msg, same_secret)
        is_valid = pqc.verify_signature(encrypted_msg, signature, sign_pub)
        
        print(original_msg, is_valid)  # "Hello!" True
    """
    
    def __init__(self):
        self.kyber = KyberSimulation()
        self.dilithium = DilithiumSignature()
        self.aes   = MessageEncryption()
    
    def generate_keypair(self):
        return self.kyber.generate_keypair()
    
    def encapsulate_key(self, recipient_public_key_b64):
        return self.kyber.encapsulate_key(recipient_public_key_b64)
    
    def decapsulate_key(self, ciphertext_b64, private_key_b64):
        return self.kyber.decapsulate_key(ciphertext_b64, private_key_b64)

    def generate_signing_keypair(self):
        return self.dilithium.generate_signing_keypair()

    def sign_message(self, encrypted_content_str, private_signing_key_b64):
        """Signs the ciphertext string (as UTF-8 bytes) that gets stored."""
        return self.dilithium.sign(
            encrypted_content_str.encode('utf-8'), private_signing_key_b64
        )

    def verify_signature(self, encrypted_content_str, signature_b64, public_signing_key_b64):
        """Verifies a stored message's signature against the claimed sender's public key."""
        return self.dilithium.verify(
            encrypted_content_str.encode('utf-8'), signature_b64, public_signing_key_b64
        )
    
    def encrypt_message(self, message_text, shared_secret):
        return self.aes.encrypt(message_text, shared_secret)
    
    def decrypt_message(self, encrypted_data, shared_secret):
        return self.aes.decrypt(encrypted_data, shared_secret)
    
    def get_algorithm_info(self):
        """Returns algorithm details for display in UI"""
        return {
            'kem_algorithm'    : 'Kyber-512 (ML-KEM)',
            'signature_algo'   : 'Dilithium2 (ML-DSA-44)',
            'symmetric_algo'   : 'AES-256-GCM',
            'security_level'   : '128-bit quantum security',
            'nist_standard'    : 'FIPS 203 (ML-KEM) + FIPS 204 (ML-DSA)',
            'quantum_safe'     : True,
            'public_key_size'  : '800 bytes',
            'private_key_size' : '1632 bytes',
            'ciphertext_size'  : '768 bytes',
            'signature_size'   : '2420 bytes'
        }


# Single instance -- import this everywhere
pqc = PostQuantumCrypto()