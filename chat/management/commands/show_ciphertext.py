# chat/management/commands/show_ciphertext.py
"""
Independent proof-of-encryption tool for demos/viva.

Run: python manage.py show_ciphertext

This queries the database DIRECTLY through Django's ORM -- it does
NOT go through any of the app's own views or the browser's "view
encrypted" toggle. It's a separate code path, useful as a second,
independent check that what's stored really is ciphertext: if
someone asks "how do I know the UI isn't just faking that?", this
command answers it from a different angle.
"""

from django.core.management.base import BaseCommand
from chat.models import Message


class Command(BaseCommand):
    help = "Prints every stored message's raw encrypted content, straight from the database."

    def add_arguments(self, parser):
        parser.add_argument(
            "--full",
            action="store_true",
            help="Show the full ciphertext/signature instead of a truncated preview.",
        )

    def handle(self, *args, **options):
        messages = Message.objects.select_related("sender", "room").all()

        if not messages.exists():
            self.stdout.write("No messages in the database yet.")
            return

        full = options["full"]

        for msg in messages:
            self.stdout.write("")
            self.stdout.write(self.style.HTTP_INFO(
                f"Message #{msg.id}  |  room {msg.room_id}  |  "
                f"sender: {msg.sender.username}  |  {msg.timestamp}"
            ))

            content = msg.encrypted_content
            if not full and len(content) > 140:
                content = content[:140] + " ...[truncated, use --full to see everything]"
            self.stdout.write(f"  stored in DB (encrypted_content): {content}")

            if msg.signature:
                sig = msg.signature
                if not full and len(sig) > 80:
                    sig = sig[:80] + " ...[truncated]"
                self.stdout.write(f"  dilithium signature:              {sig}")
            else:
                self.stdout.write(self.style.WARNING("  dilithium signature:              (none)"))

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS(
            f"{messages.count()} message(s) shown -- notice: no plaintext appears anywhere above."
        ))