# chat/admin.py
from django.contrib import admin
from .models import UserKeys, ChatRoom, Message


@admin.register(UserKeys)
class UserKeysAdmin(admin.ModelAdmin):
    # Never list public_key/private_key in list_display in a real
    # deployment -- fine for a student demo, but worth mentioning
    # in your report as a "production hardening" note.
    list_display = ("user", "created_at")
    readonly_fields = ("public_key", "private_key", "created_at")


@admin.register(ChatRoom)
class ChatRoomAdmin(admin.ModelAdmin):
    list_display = ("id", "user1", "user2", "created_at")


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    # Deliberately does NOT show encrypted_content in list_display --
    # this is the visual proof, in your own admin panel, that plaintext
    # never sits in the DB. Open a row and you'll see ciphertext (JSON
    # with nonce + ciphertext), never the original words.
    list_display = ("id", "room", "sender", "is_ai_response", "timestamp")
    list_filter = ("is_ai_response",)
