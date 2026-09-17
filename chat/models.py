# chat/models.py

from django.db import models
from django.contrib.auth.models import User

# ==================================================
# MODEL 1: UserKeys
# Stores each user's Post-Quantum key pair
# ==================================================
from django.utils import timezone
class UserKeys(models.Model):
    """
    Every user in our system gets a Kyber key pair (encryption) AND
    a Dilithium key pair (signing).
    
    Think of it as: each user has a locker AND a personal signature.
    Public key  = the locker NUMBER (anyone can see it)
    Private key = the locker COMBINATION (secret)
    Signing public key  = a stamp anyone can use to check your signature
    Signing private key = the pen only you can sign with
    """
    
    # OneToOneField means: one user -> exactly one set of keys
    # Like: one person -> one passport
    user = models.OneToOneField(
        User,                        # links to Django's built-in User
        on_delete=models.CASCADE     # if user is deleted, delete keys too
    )
    
    # TextField = stores long text (keys are very long strings)
    public_key = models.TextField(
        help_text="Kyber-512 public key (base64 encoded)"
    )
    
    private_key = models.TextField(
        help_text="Kyber-512 private key (base64 encoded)"
    )

    # -- Dilithium signing keypair (separate from the Kyber pair above) --
    # Kyber's keypair is for ENCRYPTION (who can read a message).
    # This keypair is for SIGNING (who actually sent a message).
    # They're mathematically unrelated -- a KEM and a signature scheme
    # solve different problems, so PQC systems use one keypair for each.
    signing_public_key = models.TextField(
        null=True, blank=True,
        help_text="Dilithium (ML-DSA-44) public key (base64 encoded)"
    )

    signing_private_key = models.TextField(
        null=True, blank=True,
        help_text="Dilithium (ML-DSA-44) private key (base64 encoded)"
    )
    
    # auto_now_add = automatically records when this was created
    created_at = models.DateTimeField(auto_now_add=True)
        # Updated every time rotate_user_keys() runs (see utils.py).
    # Starts equal to created_at for a brand new user; gets bumped
    # forward on every rotation after that. Used to decide which
    # users are "due" for automatic rotation.
    #
    # NOTE: uses default=timezone.now (a plain callable default),
    # not auto_now_add=True -- auto_now_add locks a field to only
    # ever be set once, at creation, which would make it impossible
    # to update on rotation. A plain default just sets the INITIAL
    # value; utils.rotate_user_keys() updates it manually afterward.
    rotated_at = models.DateTimeField(default=timezone.now)
    def __str__(self):
        # This controls what shows in Django Admin panel
        return f"PQ Keys for user: {self.user.username}"
    
    class Meta:
        verbose_name = "User Key Pair"
        verbose_name_plural = "User Key Pairs"


# ==================================================
# MODEL 2: ChatRoom
# Represents a conversation between exactly 2 users
# ==================================================

class ChatRoom(models.Model):
    """
    A secure channel between two users.
    
    The kyber_ciphertext stored here is what allows
    BOTH users to independently derive the SAME 
    shared secret (AES key) for message encryption.
    
    Think of it as: a sealed envelope containing
    instructions that only Bob can open, telling him
    the combination to use for decrypting Alice's messages.
    """
    
    # Two users in this room
    user1 = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='rooms_as_user1'
        # related_name lets us query: user.rooms_as_user1.all()
    )
    
    user2 = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='rooms_as_user2'
    )
    
    # This is the Kyber "locked box" -- stores the 
    # encapsulated key that lets both parties 
    # arrive at the same shared secret
    kyber_ciphertext = models.TextField(
        null=True,   # can be empty in database
        blank=True,  # can be empty in forms
        help_text="Kyber ciphertext for key encapsulation"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Chat: {self.user1.username} <-> {self.user2.username}"
    
    def get_other_user(self, current_user):
        """
        Simple helper: given one user, return the other.
        
        Example:
        Room has Alice and Bob.
        current_user = Alice
        Returns: Bob
        """
        if self.user1 == current_user:
            return self.user2
        return self.user1
    
    class Meta:
        verbose_name = "Chat Room"


# ==================================================
# MODEL 3: Message
# A single message in a chat room
# ==================================================

class Message(models.Model):
    """
    One message in a conversation.
    
    CRITICAL SECURITY POINT:
    The original text "Hello Bob!" is NEVER stored here.
    Only the encrypted version "X7#mK9@!..." is stored.
    
    Even if someone steals the entire database,
    they only see gibberish. This is the core value
    of our project.
    """
    
    # Which room this message belongs to
    room = models.ForeignKey(
        ChatRoom,
        on_delete=models.CASCADE,
        related_name='messages'   # lets us do room.messages.all()
    )
    
    # Who sent this message
    sender = models.ForeignKey(
        User,
        on_delete=models.CASCADE
    )
    
    # THE KEY FIELD:
    # This stores the AES-GCM encrypted version of the message.
    # The original text NEVER touches the database.
    encrypted_content = models.TextField(
        help_text="AES-GCM encrypted message (JSON with nonce + ciphertext)"
    )
    
    # Flag to identify AI-generated responses
    is_ai_response = models.BooleanField(
        default=False,
        help_text="True if this message was generated by Gemini AI"
    )

    # -- Dilithium signature --
    # The sender signs encrypted_content with their private signing key
    # at send time. Anyone holding the sender's PUBLIC signing key can
    # later verify this signature -- proving the message really came
    # from that sender and wasn't altered after signing.
    #
    # This is a DIFFERENT security property from AES-GCM's built-in
    # authentication tag: GCM's tag only proves "this ciphertext wasn't
    # tampered with since encryption" to whoever holds the AES key.
    # A Dilithium signature proves "this specific user's private key
    # produced this exact content" -- verifiable by anyone with the
    # sender's public key, without needing the AES key at all.
    signature = models.TextField(
        null=True, blank=True,
        help_text="Dilithium signature over encrypted_content (base64 encoded)"
    )
    
    # Auto-set when message is created
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Message by {self.sender.username} at {self.timestamp}"
    
    class Meta:
        # Show messages in time order (oldest first)
        ordering = ['timestamp']
        verbose_name = "Encrypted Message"