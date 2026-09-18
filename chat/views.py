# chat/views.py

from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_http_methods

from .crypto import pqc
from .forms import SignUpForm
from .models import UserKeys
from .utils import (
    AI_BOT_USERNAME,
    get_or_create_ai_bot,
    get_or_create_chat_room,
    get_room_shared_secret,
)
from .ai_service import get_ai_reply
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_http_methods

from .crypto import pqc
from .forms import SignUpForm
from .models import UserKeys
from .utils import (
    AI_BOT_USERNAME,
    get_or_create_ai_bot,
    get_or_create_chat_room,
    get_room_shared_secret,
    rotate_user_keys,
)
from .ai_service import get_ai_reply

def signup_view(request):
    """
    Handles new-user registration AND automatically generates their
    Kyber keypair AND Dilithium signing keypair.
    """
    if request.user.is_authenticated:
        return redirect("chat:inbox")

    if request.method == "POST":
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()

            public_key, private_key = pqc.generate_keypair()
            signing_public_key, signing_private_key = pqc.generate_signing_keypair()
            UserKeys.objects.create(
                user=user,
                public_key=public_key,
                private_key=private_key,
                signing_public_key=signing_public_key,
                signing_private_key=signing_private_key,
            )

            login(request, user)
            return redirect("chat:inbox")
    else:
        form = SignUpForm()

    return render(request, "chat/signup.html", {"form": form})


@login_required
@login_required
def inbox_view(request):
    """
    Landing page after login: pick who to chat with -- any other
    signed-up user, or the AI assistant.
    """
    get_or_create_ai_bot()

    other_users = (
        User.objects.exclude(pk=request.user.pk)
        .exclude(username=AI_BOT_USERNAME)
        .filter(userkeys__isnull=False)
        .order_by("username")
    )
    my_keys = UserKeys.objects.get(user=request.user)
    return render(request, "chat/inbox.html", {
        "other_users": other_users,
        "keys_rotated_at": my_keys.rotated_at,
    })


@login_required
@require_http_methods(["POST"])
def rotate_keys_view(request):
    """
    Manual "rotate my keys now" button. See utils.rotate_user_keys
    for what this actually does and its trade-offs (forward secrecy
    vs. old messages in rooms you're the keyholder for becoming
    undecryptable).
    """
    rooms_affected = rotate_user_keys(request.user)
    if rooms_affected:
        messages.success(
            request,
            f"Keys rotated. {rooms_affected} chat room(s) re-keyed -- "
            f"messages sent to you before this point in those rooms can "
            f"no longer be decrypted (forward secrecy)."
        )
    else:
        messages.success(request, "Keys rotated successfully.")
    return redirect("chat:inbox")


@login_required
def room_chat_view(request, username):
    """
    GET-only page: shows the decrypted, signature-verified history of
    a conversation with `username` (a real user, or the AI bot).
    """
    if username == AI_BOT_USERNAME:
        other_user = get_or_create_ai_bot()
    else:
        other_user = get_object_or_404(User, username=username)

    room = get_or_create_chat_room(request.user, other_user)
    shared_secret = get_room_shared_secret(room)

    history = []
    for msg in room.messages.all():
        try:
            plaintext = pqc.decrypt_message(msg.encrypted_content, shared_secret)
        except Exception:
            plaintext = "[Could not decrypt this message]"

        signature_valid = False
        if msg.signature:
            try:
                sender_keys = UserKeys.objects.get(user=msg.sender)
                signature_valid = pqc.verify_signature(
                    msg.encrypted_content, msg.signature, sender_keys.signing_public_key
                )
            except UserKeys.DoesNotExist:
                signature_valid = False

        history.append({
            "text": plaintext,
            "is_own_message": msg.sender_id == request.user.id,
            "timestamp": msg.timestamp,
            "signature_valid": signature_valid,
            # NEW: raw data exactly as stored in the database, for the
            # "View encrypted" toggle -- this is literally what an
            # attacker with DB access would see instead of the message.
            "encrypted_content": msg.encrypted_content,
            "signature": msg.signature or "",
        })

    return render(request, "chat/chat.html", {
        "history": history,
        "other_username": other_user.username,
        "is_ai": username == AI_BOT_USERNAME,
    })


@login_required
@require_http_methods(["POST"])
def send_to_room(request, username):
    """
    POST endpoint: send one plaintext message to `username` (a real
    user, or the AI bot).

    For a human recipient: encrypt + sign + save. The recipient sees
    it next time THEY load this room (refresh-based, not real-time --
    there's no websocket layer here).

    For the AI bot: same, PLUS immediately generate + encrypt + sign
    + save a reply, and return it right away.
    """
    user_text = request.POST.get("message", "").strip()
    if not user_text:
        return JsonResponse({"error": "Message cannot be empty."}, status=400)

    if username == AI_BOT_USERNAME:
        other_user = get_or_create_ai_bot()
    else:
        other_user = get_object_or_404(User, username=username)

    room = get_or_create_chat_room(request.user, other_user)
    shared_secret = get_room_shared_secret(room)

    encrypted_user_msg = pqc.encrypt_message(user_text, shared_secret)
    sender_keys = UserKeys.objects.get(user=request.user)
    user_signature = pqc.sign_message(encrypted_user_msg, sender_keys.signing_private_key)
    room.messages.create(
        sender=request.user,
        encrypted_content=encrypted_user_msg,
        is_ai_response=False,
        signature=user_signature,
    )

    if username != AI_BOT_USERNAME:
        # Return the encrypted form too, so the frontend can show the
        # "View encrypted" toggle on the message we just optimistically rendered.
        return JsonResponse({
            "user_message": user_text,
            "user_message_encrypted": encrypted_user_msg,
            "user_message_signature": user_signature,
        })

    conversation_history = []
    for msg in room.messages.all():
        try:
            text = pqc.decrypt_message(msg.encrypted_content, shared_secret)
        except Exception:
            continue
        role = "model" if msg.is_ai_response else "user"
        conversation_history.append({"role": role, "text": text})
    history_for_context = conversation_history[:-1]

    try:
        ai_text = get_ai_reply(history_for_context, user_text)
    except Exception as e:
        return JsonResponse({
            "user_message": user_text,
            "ai_message": None,
            "error": f"AI reply failed: {e}",
        }, status=502)

    encrypted_ai_msg = pqc.encrypt_message(ai_text, shared_secret)
    bot_keys = UserKeys.objects.get(user=other_user)
    ai_signature = pqc.sign_message(encrypted_ai_msg, bot_keys.signing_private_key)
    room.messages.create(
        sender=other_user,
        encrypted_content=encrypted_ai_msg,
        is_ai_response=True,
        signature=ai_signature,
    )

    return JsonResponse({
        "user_message": user_text,
        "user_message_encrypted": encrypted_user_msg,
        "user_message_signature": user_signature,
        "ai_message": ai_text,
        "ai_message_encrypted": encrypted_ai_msg,
        "ai_message_signature": ai_signature,
    })