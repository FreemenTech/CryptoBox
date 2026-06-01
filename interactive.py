"""
CryptoBox v2.0 — Interactive menu mode.

Preserves the original menu-driven interface with security improvements:
    - Passwords hidden with getpass
    - Password confirmation on encryption
    - Minimum password length enforced
    - Clear mode-mismatch detection
"""

import os
import sys
from getpass import getpass
from rich import print
from rich.panel import Panel

from constants import __version__, MIN_PASSWORD_LENGTH
from crypto_engine import (
    encrypt_file_password,
    decrypt_file_password,
    encrypt_file_aes,
    decrypt_file_aes,
    generate_aes_key,
    decrypt_key_file,
)


# ══════════════════════════════════════════════════════════════
#                          HELPERS
# ══════════════════════════════════════════════════════════════

def _file_exists(path: str) -> bool:
    return os.path.isfile(path)


def _valid_filename(name: str) -> bool:
    forbidden = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
    return bool(name) and not any(c in name for c in forbidden)


def _ask_existing_file(prompt: str) -> str:
    path = input(prompt).strip()
    if not path:
        raise ValueError("No file path provided")
    if not _file_exists(path):
        raise FileNotFoundError(f"File not found: {path}")
    return path


def _ask_new_file(prompt: str) -> str:
    name = input(prompt).strip()
    if not name:
        raise ValueError("No file name provided")
    if not _valid_filename(name):
        raise ValueError("Invalid file name (contains forbidden characters)")
    if os.path.exists(name):
        raise FileExistsError(f"File already exists: {name}")
    return name


def _ask_password_encrypt() -> str:
    """Ask for password with confirmation. Hidden input."""
    password = getpass("Password: ")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"Password too short (minimum {MIN_PASSWORD_LENGTH} characters)"
        )
    confirm = getpass("Confirm password: ")
    if password != confirm:
        raise ValueError("Passwords do not match")
    return password


def _ask_password_decrypt() -> str:
    """Ask for password without confirmation. Hidden input."""
    password = getpass("Password: ")
    if not password:
        raise ValueError("Password required")
    return password


# ══════════════════════════════════════════════════════════════
#                        MAIN MENU
# ══════════════════════════════════════════════════════════════

def run_interactive() -> None:
    """Launch the interactive menu."""

    print(Panel(
        f"[bold cyan]CRYPTOBOX v{__version__}[/bold cyan]\n"
        "Secure file encryption tool",
        expand=False,
    ))

    while True:
        print(Panel(
            "[bold]Main Menu[/bold]\n"
            "1 — Encrypt file\n"
            "2 — Decrypt file\n"
            "3 — Exit",
            expand=False,
        ))

        choice = input("> ").strip()

        # ─── ENCRYPT ──────────────────────────────────────────
        if choice == "1":
            _encrypt_menu()

        # ─── DECRYPT ──────────────────────────────────────────
        elif choice == "2":
            _decrypt_menu()

        # ─── EXIT ─────────────────────────────────────────────
        elif choice == "3":
            print("[cyan]Good Bye 👋[/cyan]")
            break

        else:
            print("[red]Choose a correct number[/red]")


# ══════════════════════════════════════════════════════════════
#                      ENCRYPT SUBMENU
# ══════════════════════════════════════════════════════════════

def _encrypt_menu() -> None:
    while True:
        print(Panel(
            "[bold]Encryption Menu[/bold]\n"
            "1 — Password-based encryption\n"
            "2 — AES key + password-protected key file\n"
            "0 — Return",
            expand=False,
        ))

        choice = input("> ").strip()

        # ─── Password mode ────────────────────────────────────
        if choice == "1":
            try:
                input_file = _ask_existing_file("Input file path: ")
                output_file = _ask_new_file("Output encrypted file name: ")
                password = _ask_password_encrypt()

                encrypt_file_password(input_file, output_file, password)
                print("[green]✔ Encryption completed successfully[/green]")
                break

            except Exception as e:
                print(f"[red]✖ Error:[/red] {e}")

        # ─── AES key mode ─────────────────────────────────────
        elif choice == "2":
            try:
                input_file = _ask_existing_file("Input file path: ")
                output_file = _ask_new_file("Output encrypted file name: ")
                key_name = input(
                    "AES key file name (without extension): "
                ).strip()
                if not _valid_filename(key_name):
                    raise ValueError("Invalid key file name")

                password = _ask_password_encrypt()

                aes_key = generate_aes_key(key_name, password)
                encrypt_file_aes(input_file, output_file, aes_key)

                print("[green]✔ Encryption completed successfully[/green]")
                print(
                    f"[yellow]Key saved to: {key_name}.enc "
                    "(keep this file safe)[/yellow]"
                )
                break

            except Exception as e:
                print(f"[red]✖ Error:[/red] {e}")

        elif choice == "0":
            break

        else:
            print("[red]Wrong choice[/red]")


# ══════════════════════════════════════════════════════════════
#                      DECRYPT SUBMENU
# ══════════════════════════════════════════════════════════════

def _decrypt_menu() -> None:
    while True:
        print(Panel(
            "[bold]Decryption Menu[/bold]\n"
            "1 — Password-based decryption\n"
            "2 — AES key + password-protected key file\n"
            "0 — Return",
            expand=False,
        ))

        choice = input("> ").strip()

        # ─── Password mode ────────────────────────────────────
        if choice == "1":
            try:
                input_file = _ask_existing_file("Input file path: ")
                output_file = _ask_new_file("Output file name: ")
                password = _ask_password_decrypt()

                decrypt_file_password(input_file, output_file, password)
                print("[green]✔ Decryption completed successfully[/green]")
                break

            except Exception as e:
                print(f"[red]✖ Error:[/red] {e}")

        # ─── AES key mode ─────────────────────────────────────
        elif choice == "2":
            try:
                input_file = _ask_existing_file("Input file path: ")
                output_file = _ask_new_file("Output file name: ")
                key_name = input(
                    "AES key file name (without .enc): "
                ).strip()
                if not _valid_filename(key_name):
                    raise ValueError("Invalid key file name")

                key_file = f"{key_name}.enc"
                if not _file_exists(key_file):
                    raise FileNotFoundError(f"Key file not found: {key_file}")

                password = _ask_password_decrypt()

                aes_key = decrypt_key_file(key_file, password)
                decrypt_file_aes(input_file, output_file, aes_key)

                print("[green]✔ Decryption completed successfully[/green]")
                break

            except Exception as e:
                print(f"[red]✖ Error:[/red] {e}")

        elif choice == "0":
            break

        else:
            print("[red]Wrong choice[/red]")
