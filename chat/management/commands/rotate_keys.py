# chat/management/commands/rotate_keys.py
"""
Automatic key rotation, runnable as:

    python manage.py rotate_keys
    python manage.py rotate_keys --max-age-days 30
    python manage.py rotate_keys --max-age-days 30 --dry-run

In a real deployment, this command would be scheduled to run
periodically -- e.g. via Windows Task Scheduler (on the machine
you're developing on) or a cron job (on a Linux server), typically
once a day. That's what "automatic key rotation" means in practice:
not a background thread inside the web app itself, but a small,
separate, auditable script that a scheduler triggers regularly.
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta

from chat.models import UserKeys
from chat.utils import rotate_user_keys


class Command(BaseCommand):
    help = "Rotates Kyber + Dilithium keypairs for any user whose keys are older than --max-age-days."

    def add_arguments(self, parser):
        parser.add_argument(
            "--max-age-days",
            type=int,
            default=30,
            help="Rotate keys last rotated more than this many days ago (default: 30).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show who WOULD be rotated, without actually rotating anything.",
        )

    def handle(self, *args, **options):
        cutoff = timezone.now() - timedelta(days=options["max_age_days"])
        due_for_rotation = UserKeys.objects.filter(rotated_at__lt=cutoff)

        if not due_for_rotation.exists():
            self.stdout.write(self.style.SUCCESS("No users are due for key rotation."))
            return

        for keys in due_for_rotation:
            age_days = (timezone.now() - keys.rotated_at).days
            if options["dry_run"]:
                self.stdout.write(
                    f"[DRY RUN] Would rotate keys for '{keys.user.username}' "
                    f"(last rotated {age_days} days ago)"
                )
            else:
                rooms_affected = rotate_user_keys(keys.user)
                self.stdout.write(self.style.SUCCESS(
                    f"Rotated keys for '{keys.user.username}' "
                    f"(was {age_days} days old, {rooms_affected} chat room(s) re-keyed)"
                ))