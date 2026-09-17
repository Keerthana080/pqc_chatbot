# chat/ai_service.py
"""
Thin wrapper around the Gemini API.

Kept deliberately separate from views.py and crypto.py so each file
has one job:
  crypto.py      -> encryption/decryption
  ai_service.py  -> talking to the LLM
  views.py       -> wiring HTTP requests to the above two

Uses the current `google-genai` SDK (the older `google-generativeai`
package is deprecated by Google as of 2025 and no longer receives
updates -- worth a one-line footnote in your report if you looked at
older Gemini tutorials while researching this).
"""

import os
from google import genai
from google.genai import types
from django.conf import settings

_client = None


def _get_client():
    """Lazily create the Gemini client on first real use."""
    global _client
    if _client is not None:
        return _client

    api_key = getattr(settings, "GEMINI_API_KEY", None) or os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is not set. Add it to your environment or "
            "settings.py before using the chatbot. See README for setup."
        )

    _client = genai.Client(api_key=api_key)
    return _client


def get_ai_reply(conversation_history, new_message):
    """
    conversation_history: list of {"role": "user"|"model", "text": str}
                           in chronological order (already decrypted by
                           the caller -- this function never touches
                           crypto.py directly).
    new_message: the latest plaintext message from the human user.

    Returns the AI's plaintext reply as a string.

    Any Gemini-side failure (bad key, rate limit, network) raises --
    the caller (views.py) decides how to surface that to the user, so
    this function stays a pure "ask the model" utility.
    """
    client = _get_client()

    contents = [
        types.Content(role=turn["role"], parts=[types.Part(text=turn["text"])])
        for turn in conversation_history
    ]
    contents.append(types.Content(role="user", parts=[types.Part(text=new_message)]))

    response = client.models.generate_content(
        model="gemini-3.6-flash",
        contents=contents,
    )
    return response.text
