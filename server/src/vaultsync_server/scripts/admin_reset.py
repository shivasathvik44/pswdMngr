"""Administrative account password reset and legacy migration CLI.

Usage:
    python -m vaultsync_server.scripts.admin_reset --username alice --password "NewSecurePassword123!"

Security Guarantee:
    Updates only the server account password hash.
    Never modifies or decrypts vault envelopes or client-encrypted records.
"""

import argparse
import sys

from vaultsync_server.db.base import SessionLocal
from vaultsync_server.services.recovery import AccountNotFoundError, reset_account_password_admin


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Administratively reset account password without modifying vault data.",
    )
    parser.add_argument("--username", required=True, help="Username of the account to reset/migrate")
    parser.add_argument("--password", required=True, help="New server account password (min 8 chars)")

    args = parser.parse_args()

    if len(args.password) < 8:
        print("Error: Password must be at least 8 characters.", file=sys.stderr)
        sys.exit(1)

    with SessionLocal() as db:
        try:
            account = reset_account_password_admin(db, args.username, args.password)
            print(f"Successfully updated account password for '{account.username}'.")
            print("All active sessions revoked. Encrypted vault contents preserved intact.")
        except AccountNotFoundError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
