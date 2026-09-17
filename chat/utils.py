# chat/utils.py
"""
Helper functions that glue UserKeys / ChatRoom / Message together.

These are small, boring functions on purpose -- the interesting crypto
logic lives in crypto.py.
"""

from django.contrib.auth.models import User
from .models import UserKeys, ChatRoom
from .crypto import pqc

AI_BOT_USERNAME = "ai_assistant"


def get_or_create_ai_bot():
    """
    The AI is modeled as a normal Django User so it can slot into
    the existing ChatRoom(user1, user2) / Message(sender) schema
    without any special-casing.

    Returns the bot's User object. Creates the user + its Kyber
    keypair AND Dilithium signing keypair the very first time this
    is called (e.g. first chat request after a fresh migrate).
    """
    bot_user, created = User.objects.get_or_create(
        username=AI_BOT_USERNAME,
        defaults={"first_name": "AI Assistant", "is_active": True},
    )

    if created:
        public_key, private_key = pqc.generate_keypair()
        signing_public_key, signing_private_key = pqc.generate_signing_keypair()
        UserKeys.objects.create(
            user=bot_user,
            public_key=public_key,
            private_key=private_key,
            signing_public_key=signing_public_key,
            signing_private_key=signing_private_key,
        )

    return bot_user


def get_or_create_chat_room(user_a, user_b):
    """
    Returns the ChatRoom between any two users, creating it (and
    running the Kyber key exchange exactly once) if it doesn't
    exist yet.

    Whichever user is passed as `user_b` becomes the room's "keyholder"
    -- the Kyber ciphertext is encapsulated against THEIR public key,
    and the server later decapsulates using THEIR private key to
    recover the shared secret. This works regardless of who user_b
    is, because the server holds every user's private key in this
    design (a deliberate simplification -- see the note in
    get_room_shared_secret below).
    """
    room = ChatRoom.objects.filter(
        user1=user_a, user2=user_b
    ).first() or ChatRoom.objects.filter(
        user1=user_b, user2=user_a
    ).first()

    if room is not None:
        return room

    b_keys = UserKeys.objects.get(user=user_b)
    ciphertext, _shared_secret = pqc.encapsulate_key(b_keys.public_key)

    room = ChatRoom.objects.create(
        user1=user_a,
        user2=user_b,
        kyber_ciphertext=ciphertext,
    )
    return room


def get_or_create_ai_room(human_user):
    """Convenience wrapper: the AI-chat room is just a chat room
    where user_b happens to be the bot."""
    bot_user = get_or_create_ai_bot()
    return get_or_create_chat_room(human_user, bot_user)


def get_room_shared_secret(room):
    """
    Recomputes the AES key for this room from the stored Kyber
    ciphertext + user2's (the "keyholder's") private key.

    NOTE ON THE SIMPLIFICATION HERE:
    In a true end-to-end system, only the two chat participants would
    ever hold private keys, and the server would never see plaintext
    or perform decryption itself. Here, because there's no client-side
    JS cryptography layer, the server holds every user's private key
    and performs encryption/decryption on their behalf. This still
    proves the Kyber + AES + Dilithium pipeline works correctly
    end-to-end, but it is NOT a claim of true E2E encryption in the
    "server never sees plaintext" sense. Worth stating explicitly in
    your report.
    """
    keyholder_keys = UserKeys.objects.get(user=room.user2)
    return pqc.decapsulate_key(room.kyber_ciphertext, keyholder_keys.private_key)
def rotate_user_keys(user):
    """
    Generates a BRAND NEW Kyber keypair and Dilithium signing keypair
    for `user`, replacing their old ones, and updates rotated_at.

    WHY THIS MATTERS (forward secrecy):
    If a user's private key is ever stolen, an attacker with an old
    copy of the database could decrypt every message that user ever
    received. Rotating keys limits that blast radius: once rotated,
    the OLD private key is gone -- even the legitimate user can't
    recover it -- so messages encrypted under the old key become
    permanently unreadable by anyone, attacker included.

    THE TRADE-OFF (and why this is a real, not fake, security property):
    For every ChatRoom where this user is the "keyholder" (user2 --
    see get_room_shared_secret), we re-run the Kyber key exchange
    against their NEW public key. This changes that room's shared
    secret going forward. Any messages sent BEFORE rotation, in a
    room where this user was the keyholder, will no longer decrypt
    correctly -- not because of a bug, but because the AES key that
    unlocked them literally no longer exists anywhere. This is the
    honest cost of forward secrecy, and it's worth stating plainly in
    a report rather than presenting it as if old messages should
    still work.

    Returns the number of chat rooms whose shared secret changed as
    a result of this rotation.
    """
    from django.utils import timezone

    keys = UserKeys.objects.get(user=user)

    new_public_key, new_private_key = pqc.generate_keypair()
    new_signing_public_key, new_signing_private_key = pqc.generate_signing_keypair()

    keys.public_key = new_public_key
    keys.private_key = new_private_key
    keys.signing_public_key = new_signing_public_key
    keys.signing_private_key = new_signing_private_key
    keys.rotated_at = timezone.now()
    keys.save()

    rooms_affected = ChatRoom.objects.filter(user2=user)
    for room in rooms_affected:
        new_ciphertext, _ = pqc.encapsulate_key(new_public_key)
        room.kyber_ciphertext = new_ciphertext
        room.save()

    return rooms_affected.count()