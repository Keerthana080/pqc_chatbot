# chat/utils.py
"""
Helper functions that glue UserKeys / ChatRoom / Message together.

These are small, boring functions on purpose — the interesting crypto
logic lives in crypto.py. This file just answers two questions:

1. "Where do I get the AI's keys from?"          -> get_or_create_ai_bot()
2. "What's the shared secret for this room?"     -> get_room_shared_secret()
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
    keypair the very first time this is called (e.g. first chat
    request after a fresh migrate).
    """
    bot_user, created = User.objects.get_or_create(
        username=AI_BOT_USERNAME,
        defaults={"first_name": "AI Assistant", "is_active": True},
    )

    if created:
        # Brand new bot account -> give it a Kyber keypair, same
        # generate_keypair() every human user gets.
        public_key, private_key = pqc.generate_keypair()
        UserKeys.objects.create(
            user=bot_user,
            public_key=public_key,
            private_key=private_key,
        )

    return bot_user


def get_or_create_ai_room(human_user):
    """
    Returns the ChatRoom between `human_user` and the AI bot,
    creating it (and running the Kyber key exchange exactly once)
    if it doesn't exist yet.
    """
    bot_user = get_or_create_ai_bot()

    # A room already exists either way round (user1/user2), so check both.
    room = ChatRoom.objects.filter(
        user1=human_user, user2=bot_user
    ).first() or ChatRoom.objects.filter(
        user1=bot_user, user2=human_user
    ).first()

    if room is not None:
        return room

    # No room yet -> this is a brand new conversation.
    # Run the Kyber key exchange ONCE: encapsulate against the bot's
    # public key. We keep the ciphertext (goes in the DB); we throw
    # away the shared_secret returned here because we never store
    # secrets — see get_room_shared_secret() below for how it's
    # recovered on demand.
    bot_keys = UserKeys.objects.get(user=bot_user)
    ciphertext, _shared_secret = pqc.encapsulate_key(bot_keys.public_key)

    room = ChatRoom.objects.create(
        user1=human_user,
        user2=bot_user,
        kyber_ciphertext=ciphertext,
    )
    return room


def get_room_shared_secret(room):
    """
    Recomputes the AES key for this room from the stored Kyber
    ciphertext + the AI bot's private key.

    Why recompute instead of caching? Because the private key never
    leaves the server anyway in this design (the "AI" side of every
    room lives on the server), so there's no real cost to recomputing
    it, and it means we're never persisting a raw AES key anywhere —
    only the pieces needed to regenerate it.
    """
    bot_user = get_or_create_ai_bot()
    bot_keys = UserKeys.objects.get(user=bot_user)
    return pqc.decapsulate_key(room.kyber_ciphertext, bot_keys.private_key)
