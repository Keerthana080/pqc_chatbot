# chat/views.py

import json

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_http_methods

from .crypto import pqc
from .utils import get_or_create_ai_room, get_room_shared_secret
from .ai_service import get_ai_reply


@login_required
def chat_view(request):
    """
    GET-only page: creates the user's AI chat room if it doesn't
    exist yet, decrypts the full message history for display, and
    renders the chat template.

    Decryption only happens here, at the last possible moment before
    showing text to the browser -- everything in the DB stays encrypted
    right up until this point.
    """
    room = get_or_create_ai_room(request.user)
    shared_secret = get_room_shared_secret(room)

    history = []
    for msg in room.messages.all():  # ordered by timestamp, see Message.Meta
        try:
            plaintext = pqc.decrypt_message(msg.encrypted_content, shared_secret)
        except Exception:
            # If a message fails to decrypt (corrupted / tampered row),
            # don't crash the whole page -- show that clearly instead.
            plaintext = "[Could not decrypt this message]"

        history.append({
            "text": plaintext,
            "is_ai_response": msg.is_ai_response,
            "timestamp": msg.timestamp,
        })

    return render(request, "chat/chat.html", {"history": history})


@login_required
@require_http_methods(["POST"])
def send_message(request):
    """
    POST endpoint: user sends one plaintext message ->
      1. encrypt + save it
      2. ask Gemini for a reply, using decrypted history as context
      3. encrypt + save the reply
      4. return both in plaintext JSON for the frontend to render

    Note: the plaintext exists in memory only for the duration of this
    request (to send to the browser / Gemini). It's never written to
    disk unencrypted -- only msg.encrypted_content is ever saved.
    """
    user_text = request.POST.get("message", "").strip()
    if not user_text:
        return JsonResponse({"error": "Message cannot be empty."}, status=400)

    room = get_or_create_ai_room(request.user)
    shared_secret = get_room_shared_secret(room)

    # 1. Encrypt and store the human's message
    encrypted_user_msg = pqc.encrypt_message(user_text, shared_secret)
    room.messages.create(
        sender=request.user,
        encrypted_content=encrypted_user_msg,
        is_ai_response=False,
    )

    # 2. Build decrypted conversation history for Gemini's context.
    #    Gemini's chat API wants roles "user" and "model".
    conversation_history = []
    for msg in room.messages.all():
        try:
            text = pqc.decrypt_message(msg.encrypted_content, shared_secret)
        except Exception:
            continue  # skip any message we can't decrypt
        role = "model" if msg.is_ai_response else "user"
        conversation_history.append({"role": role, "text": text})

    # The message we just saved is already the last item in that list,
    # so hand it to get_ai_reply as history[:-1] + new_message.
    history_for_context = conversation_history[:-1]

    try:
        ai_text = get_ai_reply(history_for_context, user_text)
    except Exception as e:
        # Gemini failed (bad key, rate limit, network, etc). We still
        # keep the user's message saved -- just surface the error.
        return JsonResponse({
            "user_message": user_text,
            "ai_message": None,
            "error": f"AI reply failed: {e}",
        }, status=502)

    # 3. Encrypt and store the AI's reply
    bot_user = room.get_other_user(request.user)
    encrypted_ai_msg = pqc.encrypt_message(ai_text, shared_secret)
    room.messages.create(
        sender=bot_user,
        encrypted_content=encrypted_ai_msg,
        is_ai_response=True,
    )

    # 4. Return plaintext to the browser (this is the one place
    #    plaintext is meant to leave the server -- over HTTPS, to the
    #    logged-in user who owns this room).
    return JsonResponse({
        "user_message": user_text,
        "ai_message": ai_text,
    })
