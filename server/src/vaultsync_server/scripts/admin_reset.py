"""Administrative account password reset and legacy migration CLI.

Usage:
    # Interactive mode (recommended, hides password from process table and shell history):
    python -m vaultsync_server.scripts.admin_reset --username alice

    # Non-interactive / piped stdin mode (for automation / CI):
    echo -n "NewSecurePassword123!" | python -m vaultsync_server.scripts.admin_reset --username alice --password-stdin

Security Guarantee:
    - Never accepts passwords as command-line arguments (prevents leakage into /proc and history).
    - Updates only the server account password hash.
    - Never modifies or decrypts vault envelopes or client-encrypted records.
"""

import argparse
import getpass
import sys

from vaultsync_server.db.base import SessionLocal
from vaultsync_server.services.recovery import AccountNotFoundError, reset_account_password_admin

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 256


def get_password_from_input(password_stdin: bool = False) -> str:
    """Acquire password either via stdin or interactive getpass prompt."""
    if password_stdin:
        pwd = sys.stdin.readline().rstrip("\r\n")
        if not pwd:
            print("Error: Empty password provided via standard input.", file=sys.stderr)
            sys.exit(1)
        return pwd

    pwd1 = getpass.getpass("Enter new account password: ")
    pwd2 = getpass.getpass("Confirm new account password: ")

    if pwd1 != pwd2:
        print("Error: Passwords do not match.", file=sys.stderr)
        sys.exit(1)

    return pwd1


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Administratively reset account password without modifying vault data.",
    )
    parser.add_argument("--username", required=True, help="Username of the account to reset/migrate")
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read password from standard input rather than interactive prompt (for automation).",
    )

    args = parser.parse_args(argv)

    new_password = get_password_from_input(password_stdin=args.password_stdin)

    if len(new_password) < MIN_PASSWORD_LENGTH:
        print(f"Error: Password must be at least {MIN_PASSWORD_LENGTH} characters.", file=sys.stderr)
        sys.exit(1)
    if len(new_password) > MAX_PASSWORD_LENGTH:
        print(f"Error: Password cannot exceed {MAX_PASSWORD_LENGTH} characters.", file=sys.stderr)
        sys.exit(1)

    with SessionLocal() as db:
        try:
            account = reset_account_password_admin(db, args.username, new_password)
            print(f"Successfully updated account password for '{account.username}'.")
            print("All active sessions revoked. Encrypted vault contents preserved intact.")
        except AccountNotFoundError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
